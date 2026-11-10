/**
 * Satset Sync - Sync Service
 *
 * Handles communication with the Satset sync-notes Edge Function via API Key,
 * writing/updating Markdown files in Obsidian, and AES-GCM decryption.
 *
 * Smart Sync: Uses satset_id in frontmatter to prevent duplicates,
 * handles renames, and supports incremental sync.
 *
 * Retry: HTTP requests use exponential backoff (3 retries) for transient errors.
 *
 * Soft Delete: Notes deleted on the web are moved to the local Obsidian trash.
 */
import { Notice, Vault, TFile, TFolder, normalizePath, requestUrl, RequestUrlParam } from "obsidian";
import type SatsetSyncPlugin from "./main";
import {
    PermanentError,
    checkSupabaseUrl,
    extractFrontmatterValue,
    holdCursor,
    isLaterTime,
    isPermanentError,
    renameFrontmatterKey,
    sanitizeFilename,
    yamlQuote,
} from "./util";

// ── Supabase Gateway Auth ──
// The anon key is required by Supabase API gateway to route requests to Edge Functions.
// This is a PUBLIC key (same as in the web app client) — it only grants anon-level access.
// Actual auth is handled by our custom x-api-key mechanism inside the Edge Function.
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Iml4dmJzZXh1anhkYmJ2enZteWJqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDk5Mzg4MDAsImV4cCI6MjA2NTUxNDgwMH0.CYpokPpeceFYzh9gMh-ymGYte9iCWcNamCCIc56Fh1I";

// ── Encryption Constants (must match Satset web app) ──
const ENCRYPTION_VERSION_V1 = "v1";
const ENCRYPTION_VERSION_V2 = "v2";
const PBKDF2_ITERATIONS_V1 = 100000;
const PBKDF2_ITERATIONS_V2 = 600000;
const KEY_LENGTH = 256;

// ── Retry Constants ──
const MAX_RETRIES = 3;
const BASE_DELAY_MS = 1000; // 1s → 2s → 4s

// ── Paging Constants ──
// The Edge Function returns at most this many notes per page; a shorter page is the last one.
const PAGE_SIZE = 50;
const MAX_PAGES = 1000;

// ── Interfaces ──
interface SatsetNote {
    id: string;
    title: string;
    content: string | null;
    labels: string[] | null;
    pinned: boolean | null;
    archived: boolean | null;
    encrypted: boolean | null;
    created_at: string;
    updated_at: string;
    timestamp: number;
}

interface ConfigResponse {
    userId: string;
    email: string;
    encryptionSalt: string | null;
}

interface DeletedNote {
    note_id: string;
    deleted_at: string;
}

type Keyring = Record<string, CryptoKey>;

// ── Crypto Helpers ──
function base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

async function deriveEncryptionKey(passphrase: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(passphrase),
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"]
    );
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt as BufferSource, iterations, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: KEY_LENGTH },
        false,
        ["decrypt"]
    );
}

async function decryptText(encrypted: string, keyring: Keyring): Promise<string> {
    if (!encrypted) return encrypted;
    if (!encrypted.includes("|")) return encrypted;

    const parts = encrypted.split("|");
    if (parts.length !== 4) throw new Error("Invalid encrypted format");

    const [version, , ivB64, ciphertextB64] = parts;
    const key = keyring[version];

    if (!key) throw new Error(`No decryption key available for version: ${version}`);

    const iv = new Uint8Array(base64ToArrayBuffer(ivB64));
    const ciphertext = new Uint8Array(base64ToArrayBuffer(ciphertextB64));

    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return new TextDecoder().decode(decrypted);
}

// ── Main Service ──
export class SyncService {
    private plugin: SatsetSyncPlugin;
    private keyring: Keyring | null = null; // Stores { v1: Key, v2: Key }

    // In-memory index: satset_id -> file path (built on each sync)
    private idToFileMap: Map<string, string> = new Map();

    /** True while a sync run is in progress; a second run would race on the same files. */
    private syncing = false;

    /** Number of consecutive sync failures. Reset to 0 on successful sync. */
    public consecutiveFailures = 0;

    constructor(plugin: SatsetSyncPlugin) {
        this.plugin = plugin;
    }

    // ── Utility ──

    /** Promise-based sleep for retry delays. */
    private sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * HTTP request to the sync-notes Edge Function with retry + exponential backoff.
     *
     * Headers:
     * - `apikey` + `Authorization`: Supabase API gateway auth (anon key, public).
     * - `x-api-key`: Our custom auth, validated inside the Edge Function.
     *
     * Retry policy:
     * - Retries up to MAX_RETRIES times for transient errors (5xx, network failures).
     * - Uses exponential backoff: 1s, 2s, 4s + random jitter (0–500ms).
     * - Does NOT retry client errors (4xx) as they indicate permanent failures.
     * - Permanent failures are thrown as PermanentError; retry is decided by that flag, never by message text.
     */
    private async request(path: string, options: Partial<RequestUrlParam> = {}): Promise<unknown> {
        const { supabaseUrl, apiKey } = this.plugin.settings;
        if (!supabaseUrl) throw new PermanentError("Supabase URL not configured.");
        if (!apiKey) throw new PermanentError("API key not configured.");
        // Checked before any request so the API key never leaves over plain http.
        const urlError = checkSupabaseUrl(supabaseUrl);
        if (urlError) throw new PermanentError(urlError);

        const url = `${supabaseUrl}/functions/v1/sync-notes${path}`;
        let lastError: Error = new Error("Request failed");

        for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
            // Exponential backoff before retry (skip on first attempt)
            if (attempt > 0) {
                const jitter = Math.random() * 500;
                const delay = BASE_DELAY_MS * Math.pow(2, attempt - 1) + jitter;
                console.debug(
                    `[Satset Sync] Retry ${attempt}/${MAX_RETRIES} in ${Math.round(delay)}ms...`
                );
                await this.sleep(delay);
            }

            try {
                const response = await requestUrl({
                    url,
                    throw: false,
                    ...options,
                    headers: {
                        "Content-Type": "application/json",
                        "apikey": SUPABASE_ANON_KEY,
                        "Authorization": `Bearer ${SUPABASE_ANON_KEY}`,
                        "x-api-key": apiKey,
                        ...options.headers,
                    },
                });

                // ── Success ──
                if (response.status >= 200 && response.status < 300) {
                    try {
                        return response.json;
                    } catch {
                        // response.json parses lazily and throws on a non-JSON body.
                        throw new PermanentError(
                            `Unexpected non-JSON response (HTTP ${response.status}).`
                        );
                    }
                }

                // ── Client errors (4xx): permanent, do NOT retry ──
                if (response.status === 401) {
                    throw new PermanentError(
                        "Invalid or expired API key. Please generate a new one from the website."
                    );
                }
                if (response.status === 403) {
                    throw new PermanentError(
                        "API key has been revoked. Generate a new one from the website."
                    );
                }
                if (response.status >= 400 && response.status < 500) {
                    let body = "";
                    try {
                        body = (response.text || "").slice(0, 200);
                    } catch {
                        // Body unreadable; the status alone is reported.
                    }
                    throw new PermanentError(`HTTP ${response.status}: ${body}`);
                }

                // ── Server errors (5xx) — transient, retry ──
                lastError = new Error(
                    `Server error (HTTP ${response.status}). ` +
                    (attempt < MAX_RETRIES ? "Retrying..." : "All retries exhausted.")
                );
            } catch (error: unknown) {
                const err = error instanceof Error ? error : new Error(String(error));

                // A permanent error thrown above propagates immediately
                if (isPermanentError(err)) {
                    throw err;
                }

                // Network error or unexpected failure: retry
                lastError = err;
            }
        }

        // All retries exhausted
        throw new Error(
            `Request failed after ${MAX_RETRIES} retries: ${lastError.message}`
        );
    }

    /**
     * Fetch the account behind the API key, store its identity and derive the
     * decryption keys. Shared by connect() and syncNotes() so that an API key
     * alone is enough for encrypted notes. Leaves the keyring null when the
     * account has no encryption salt.
     */
    private async ensureKeyring(): Promise<ConfigResponse> {
        const config = await this.request("/config", { method: "GET" }) as ConfigResponse;

        // Read before it is overwritten below, or an account change is never seen.
        const previousUserId = this.plugin.settings.userId;
        if (previousUserId && previousUserId !== config.userId) {
            // Sync history belongs to the previous account; the new one starts from scratch.
            this.plugin.settings.lastSyncTime = "";
            this.plugin.settings.syncedFiles = {};
        }

        this.plugin.settings.userId = config.userId;
        this.plugin.settings.email = config.email;
        await this.plugin.saveSettings();

        if (config.encryptionSalt) {
            const salt = new Uint8Array(base64ToArrayBuffer(config.encryptionSalt));
            const passphrase = `${config.userId}:${config.email}`;

            // Derive both V1 and V2 keys for backward compatibility
            const [keyV1, keyV2] = await Promise.all([
                deriveEncryptionKey(passphrase, salt, PBKDF2_ITERATIONS_V1),
                deriveEncryptionKey(passphrase, salt, PBKDF2_ITERATIONS_V2)
            ]);

            this.keyring = {
                [ENCRYPTION_VERSION_V1]: keyV1,
                [ENCRYPTION_VERSION_V2]: keyV2
            };
        } else {
            this.keyring = null;
        }

        return config;
    }

    /** Connect using API Key: fetch config and derive encryption keys. */
    async connect(): Promise<boolean> {
        try {
            const config = await this.ensureKeyring();

            if (!this.keyring) {
                console.log("[Satset Sync] No encryption salt found. Encrypted notes will be skipped.");
                new Notice("No encryption salt. Encrypted notes will be skipped.");
            }

            this.consecutiveFailures = 0;
            new Notice(`Connected as ${config.email}`);
            return true;
        } catch (error: unknown) {
            this.consecutiveFailures++;
            const message = error instanceof Error ? error.message : String(error);
            new Notice(`Connection failed: ${message}`);
            console.log("[Satset Sync] Connection error:", error);
            return false;
        }
    }

    /** Disconnect: clear API Key, user data and the sync history tied to the account. */
    async disconnect(): Promise<void> {
        this.plugin.settings.apiKey = "";
        this.plugin.settings.userId = "";
        this.plugin.settings.email = "";
        // Without this reset the next account would start from the old cursor and miss its older notes.
        this.plugin.settings.lastSyncTime = "";
        this.plugin.settings.syncedFiles = {};
        this.idToFileMap.clear();
        this.keyring = null;
        this.consecutiveFailures = 0;
        await this.plugin.saveSettings();
        new Notice("Disconnected.");
    }

    /** Build an index of satset_id -> filePath by scanning the sync folder. */
    private async buildIdIndex(syncFolder: string): Promise<void> {
        this.idToFileMap.clear();
        const vault: Vault = this.plugin.app.vault;
        const normalizedFolder = normalizePath(syncFolder);
        const folder = vault.getAbstractFileByPath(normalizedFolder);

        if (!folder || !(folder instanceof TFolder)) {
            return; // Folder doesn't exist yet, no files to index
        }

        const files = vault.getMarkdownFiles().filter(f => f.path.startsWith(normalizedFolder + "/"));

        for (const file of files) {
            try {
                const content = await vault.cachedRead(file);
                const satsetId = this.extractFrontmatterValue(content, "satset_id");
                if (satsetId) {
                    this.idToFileMap.set(satsetId, file.path);
                }
            } catch {
                // Skip unreadable files
            }
        }
    }

    /**
     * Main sync function. Only one run at a time: a second call returns at once.
     * `silent` hides the "already running" Notice, for the auto-sync timer.
     */
    async syncNotes(options: { silent?: boolean } = {}): Promise<void> {
        if (!this.plugin.settings.apiKey) {
            new Notice("Please connect with an API key first.");
            return;
        }

        if (this.syncing) {
            if (!options.silent) new Notice("Sync already running");
            return;
        }

        this.syncing = true;
        try {
            await this.runSync();
        } finally {
            this.syncing = false;
        }
    }

    private async runSync(): Promise<void> {
        // Ensure keyring is ready. An API key alone is enough; the user id is filled from /config.
        if (!this.keyring) {
            try {
                await this.ensureKeyring();
            } catch (err: unknown) {
                // Non-fatal; encrypted notes are held back and fetched again next sync
                console.log("[Satset Sync] Could not prepare decryption keys:", err);
            }
        }

        // Read after ensureKeyring: an account change resets the cursor there.
        const { syncFolder, lastSyncTime } = this.plugin.settings;

        try {
            // Build the ID -> file path index
            await this.buildIdIndex(syncFolder);

            new Notice("Syncing notes...");
            await this.ensureFolder(syncFolder);

            let created = 0;
            let updated = 0;
            let skipped = 0;
            let renamed = 0;
            let decryptFailed = 0;
            let failed = 0;
            let held = 0;

            // Page cursor: largest updated_at seen, held notes included. It only drives paging.
            // The saved cursor (lastSyncTime) is computed at the end and stays behind every held note.
            let pageCursor = lastSyncTime;
            const hold = { earliest: null as string | null, unparsable: false };
            const holdNote = (note: SatsetNote): void => {
                if (Number.isNaN(Date.parse(note.updated_at))) {
                    hold.unparsable = true;
                } else if (hold.earliest === null || isLaterTime(hold.earliest, note.updated_at)) {
                    hold.earliest = note.updated_at;
                }
            };

            for (let page = 1; ; page++) {
                if (page > MAX_PAGES) {
                    new Notice(`Sync paused after ${MAX_PAGES} pages. Run sync again to continue.`);
                    break;
                }

                const since = pageCursor;
                let query = "";
                if (since) {
                    query += `?since=${encodeURIComponent(since)}`;
                }

                const result = await this.request(`/${query}`, { method: "GET" }) as { notes?: SatsetNote[] };
                const notes: SatsetNote[] = result.notes || [];

                if (notes.length === 0) {
                    break;
                }

                for (const note of notes) {
                    // Compared as times: the cursor and the server value may differ in format.
                    if (isLaterTime(note.updated_at, pageCursor)) {
                        pageCursor = note.updated_at;
                    }

                    // One bad note must not stop the others: it is counted, held and retried next sync.
                    try {
                        if (note.encrypted) {
                            if (!this.keyring) {
                                held++;
                                holdNote(note);
                                continue;
                            }
                            try {
                                note.title = await decryptText(note.title, this.keyring);
                                note.content = note.content ? await decryptText(note.content, this.keyring) : "";
                            } catch (err: unknown) {
                                // Nothing is written, so an existing local copy stays as it is.
                                console.log(`[Satset Sync] Decrypt failed for ${note.id}:`, err);
                                decryptFailed++;
                                holdNote(note);
                                continue;
                            }
                        }

                        const syncResult = await this.writeNoteSmartSync(note, syncFolder);
                        if (syncResult === "created") created++;
                        else if (syncResult === "updated") updated++;
                        else if (syncResult === "renamed") renamed++;
                        else if (syncResult === "skipped") skipped++;
                    } catch (err: unknown) {
                        console.log(`[Satset Sync] Could not write note ${note.id}:`, err);
                        failed++;
                        holdNote(note);
                        continue;
                    }

                    // Batch save settings (every 10 items) to persist hashes
                    if ((created + updated + renamed + skipped) % 10 === 0) {
                        await this.plugin.saveSettings();
                    }
                }

                if (notes.length < PAGE_SIZE) {
                    // A short page is the last one
                    break;
                }

                if (pageCursor === since) {
                    // A full page that does not move the cursor would be fetched again forever.
                    new Notice("Sync paused: the server returned the same page again. Run sync again later.");
                    break;
                }

                new Notice(`Syncing... (processed ${created + updated + skipped + renamed} notes)`);
            }

            if (held > 0) {
                new Notice(
                    `${held} encrypted note${held > 1 ? "s" : ""} not synced: no decryption key. Will retry on the next sync.`
                );
            }

            // ── Soft Delete Sync ──
            const deletions = await this.syncDeletions(syncFolder, lastSyncTime);

            if (deletions === null) {
                // Keep the old cursor so the next run asks /deleted for the same window again.
                // Notes fetched again are skipped by their updated_at.
                new Notice("Deletion check failed, will retry");
            } else if (!hold.unparsable) {
                this.plugin.settings.lastSyncTime = holdCursor(pageCursor, hold.earliest);
            }
            await this.plugin.saveSettings();

            // Sync run finished: reset failure counter
            this.consecutiveFailures = 0;

            const deletedCount = deletions ? deletions.deleted : 0;
            const keptCount = deletions ? deletions.kept : 0;

            const parts: string[] = [];
            if (created > 0) parts.push(`${created} created`);
            if (updated > 0) parts.push(`${updated} updated`);
            if (renamed > 0) parts.push(`${renamed} renamed`);
            if (skipped > 0) parts.push(`${skipped} skipped`);
            if (deletedCount > 0) parts.push(`${deletedCount} deleted`);
            if (keptCount > 0) parts.push(`${keptCount} kept as conflict`);
            if (decryptFailed > 0) parts.push(`${decryptFailed} errors`);
            if (failed > 0) parts.push(`${failed} failed`);
            if (held > 0) parts.push(`${held} held`);

            if (parts.length === 0 && deletions !== null) {
                new Notice("Already up to date.");
            } else {
                new Notice(`Sync complete: ${parts.join(", ") || "no changes"}`);
            }
        } catch (error: unknown) {
            this.consecutiveFailures++;
            const message = error instanceof Error ? error.message : String(error);
            console.log(`[Satset Sync] Sync error (failure #${this.consecutiveFailures}):`, error);
            new Notice(`Sync error: ${message}`);
        }
    }

    /**
     * Sync deletions: query the /deleted endpoint and delete local files.
     * A file edited since its last sync is kept as a conflict copy instead.
     * Returns null when the check itself failed, so the caller keeps its cursor.
     */
    private async syncDeletions(
        syncFolder: string, lastSyncTime: string
    ): Promise<{ deleted: number; kept: number } | null> {
        try {
            let query = "/deleted";
            if (lastSyncTime) {
                query += `?since=${encodeURIComponent(lastSyncTime)}`;
            }

            const result = await this.request(query, { method: "GET" }) as {
                deleted?: DeletedNote[];
            };
            const deletedNotes = result.deleted || [];

            if (deletedNotes.length === 0) return { deleted: 0, kept: 0 };

            const vault: Vault = this.plugin.app.vault;
            let deletedCount = 0;
            let keptCount = 0;

            for (const del of deletedNotes) {
                const existingPath = this.idToFileMap.get(del.note_id);
                if (!existingPath) continue;

                const file = vault.getAbstractFileByPath(existingPath);
                if (!(file instanceof TFile)) continue;

                try {
                    // A missing hash means the last synced state is unknown, so the file is kept too.
                    const localHash = await this.computeBodyHash(await vault.read(file));
                    if (localHash !== this.plugin.settings.syncedFiles[del.note_id]) {
                        const basename = file.basename;
                        const conflictFilename = await this.backupAsConflict(file);
                        new Notice(`"${basename}" was deleted on the web but edited here. \nKept as "${conflictFilename}".`);

                        this.idToFileMap.delete(del.note_id);
                        delete this.plugin.settings.syncedFiles[del.note_id];
                        keptCount++;
                        continue;
                    }

                    await this.plugin.app.fileManager.trashFile(file);

                    this.idToFileMap.delete(del.note_id);
                    delete this.plugin.settings.syncedFiles[del.note_id];

                    deletedCount++;
                    console.debug(
                        `[Satset Sync] Deleted note: ${existingPath}`
                    );
                } catch (err: unknown) {
                    console.log(
                        `[Satset Sync] Failed to delete ${existingPath}:`,
                        err
                    );
                }
            }

            if (deletedCount > 0) {
                new Notice(
                    `${deletedCount} deleted note${deletedCount > 1 ? "s" : ""} moved to trash.`
                );
            }
            if (deletedCount > 0 || keptCount > 0) {
                await this.plugin.saveSettings();
            }

            return { deleted: deletedCount, kept: keptCount };
        } catch (error: unknown) {
            console.log("[Satset Sync] Deletion check failed:", error);
            return null;
        }
    }

    /**
     * Move a locally edited file aside as "<name> (Conflict <time>).md" and detach it
     * from its note id, so the id index never maps the backup. Returns the new file name.
     */
    private async backupAsConflict(file: TFile): Promise<string> {
        const vault: Vault = this.plugin.app.vault;
        const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
        const conflictFilename = `${file.basename} (Conflict ${timestamp}).md`;
        const conflictPath = normalizePath(`${file.parent?.path}/${conflictFilename}`);

        await vault.rename(file, conflictPath);

        const conflictFile = vault.getAbstractFileByPath(conflictPath);
        if (conflictFile instanceof TFile) {
            const conflictContent = await vault.read(conflictFile);
            // Frontmatter only: a "satset_id:" line in the body is the user's text.
            await vault.modify(
                conflictFile,
                renameFrontmatterKey(conflictContent, "satset_id", "satset_conflict_of")
            );
        }
        return conflictFilename;
    }

    /**
     * Smart Sync write logic with ONE-WAY SYNC PROTECTION.
     */
    private async writeNoteSmartSync(
        note: SatsetNote, folderPath: string
    ): Promise<"created" | "updated" | "renamed" | "skipped"> {
        const vault: Vault = this.plugin.app.vault;
        const title = this.sanitizeFilename(note.title || "Untitled");
        const content = this.noteToMarkdown(note);
        const serverHash = await this.computeBodyHash(content);

        const existingPath = this.idToFileMap.get(note.id);

        if (existingPath) {
            const existingFile = vault.getAbstractFileByPath(existingPath);
            if (existingFile instanceof TFile) {
                const existingContent = await vault.read(existingFile);

                const existingUpdatedAt = this.extractFrontmatterValue(existingContent, "updated_at");
                if (existingUpdatedAt && existingUpdatedAt >= note.updated_at) {
                    if (!this.plugin.settings.syncedFiles[note.id]) {
                        const localHash = await this.computeBodyHash(existingContent);
                        this.plugin.settings.syncedFiles[note.id] = localHash;
                    }
                    return "skipped";
                }

                const localHash = await this.computeBodyHash(existingContent);
                const lastSyncedHash = this.plugin.settings.syncedFiles[note.id];

                const isDirty = lastSyncedHash
                    ? localHash !== lastSyncedHash
                    : localHash !== serverHash;

                if (isDirty) {
                    const basename = existingFile.basename;
                    const conflictFilename = await this.backupAsConflict(existingFile);
                    new Notice(`Conflict detected: ${basename}. \nLocal changes backed up to "${conflictFilename}".`);

                    let targetPath = normalizePath(`${folderPath}/${title}.md`);
                    targetPath = await this.getUniquePath(targetPath, note.id);

                    await vault.create(targetPath, content);
                    this.idToFileMap.set(note.id, targetPath);
                    this.plugin.settings.syncedFiles[note.id] = serverHash;
                    return "updated";
                }

                let targetPath = normalizePath(`${folderPath}/${title}.md`);

                if (existingFile.path !== targetPath) {
                    targetPath = await this.getUniquePath(targetPath, note.id);
                    try {
                        await vault.rename(existingFile, targetPath);
                        const renamedFile = vault.getAbstractFileByPath(targetPath);
                        if (renamedFile instanceof TFile) {
                            await vault.modify(renamedFile, content);
                        }
                        this.idToFileMap.set(note.id, targetPath);
                        this.plugin.settings.syncedFiles[note.id] = serverHash;
                        return "renamed";
                    } catch (err: unknown) {
                        console.log(`[Satset Sync] Rename failed for ${note.id}, updating in place:`, err);
                        await vault.modify(existingFile, content);
                        this.plugin.settings.syncedFiles[note.id] = serverHash;
                        return "updated";
                    }
                }

                await vault.modify(existingFile, content);
                this.plugin.settings.syncedFiles[note.id] = serverHash;
                return "updated";
            }
        }

        let targetPath = normalizePath(`${folderPath}/${title}.md`);
        targetPath = await this.getUniquePath(targetPath, note.id);

        await vault.create(targetPath, content);
        this.idToFileMap.set(note.id, targetPath);
        this.plugin.settings.syncedFiles[note.id] = serverHash;
        return "created";
    }

    private async getUniquePath(basePath: string, noteId: string): Promise<string> {
        const vault: Vault = this.plugin.app.vault;
        let candidatePath = basePath;
        let counter = 1;

        while (true) {
            const file = vault.getAbstractFileByPath(candidatePath);
            if (!file) {
                return candidatePath;
            }

            if (file instanceof TFile) {
                try {
                    const content = await vault.cachedRead(file);
                    const existingId = this.extractFrontmatterValue(content, "satset_id");
                    if (existingId === noteId) {
                        return candidatePath;
                    }
                } catch {
                    // Can't read? Treat as taken.
                }
            }

            const extIndex = basePath.lastIndexOf(".");
            const base = extIndex > -1 ? basePath.substring(0, extIndex) : basePath;
            const ext = extIndex > -1 ? basePath.substring(extIndex) : "";
            candidatePath = `${base} (${counter})${ext}`;
            counter++;
        }
    }

    private noteToMarkdown(note: SatsetNote): string {
        const fm: string[] = ["---"];
        fm.push(`satset_id: ${yamlQuote(note.id)}`);
        fm.push(`created_at: ${yamlQuote(note.created_at)}`);
        fm.push(`updated_at: ${yamlQuote(note.updated_at)}`);

        if (note.labels && note.labels.length > 0) {
            fm.push("tags:");
            for (const label of note.labels) fm.push(`  - ${yamlQuote(label)}`);
        }
        if (note.pinned) fm.push("pinned: true");
        if (note.archived) fm.push("archived: true");

        fm.push("---");
        fm.push("");

        const content = note.content || "";
        return fm.join("\n") + `${content}\n`;
    }

    private sanitizeFilename(title: string): string {
        return sanitizeFilename(title);
    }

    private extractFrontmatterValue(content: string, key: string): string | null {
        return extractFrontmatterValue(content, key);
    }

    private async ensureFolder(path: string): Promise<void> {
        const vault: Vault = this.plugin.app.vault;
        const normalizedPath = normalizePath(path);
        if (!vault.getAbstractFileByPath(normalizedPath)) {
            await vault.createFolder(normalizedPath);
        }
    }

    private extractBody(content: string): string {
        const match = content.match(/^---\n[\s\S]*?\n---\n([\s\S]*)$/);
        return match ? match[1] : content;
    }

    private async computeBodyHash(content: string): Promise<string> {
        const body = this.extractBody(content);
        const normalized = body.replace(/\r\n/g, "\n");
        const encoder = new TextEncoder();
        const data = encoder.encode(normalized);
        const hashBuffer = await crypto.subtle.digest("SHA-256", data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
    }
}
