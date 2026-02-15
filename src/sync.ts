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
 * Soft Delete: Notes deleted on the web are moved to _archived/ subfolder locally.
 */
import { Notice, Vault, TFile, TFolder, normalizePath, requestUrl, RequestUrlParam } from "obsidian";
import type SatsetSyncPlugin from "./main";

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
     */
    private async request(path: string, options: Partial<RequestUrlParam> = {}): Promise<unknown> {
        const { supabaseUrl, apiKey } = this.plugin.settings;
        if (!supabaseUrl) throw new Error("Supabase URL not configured.");
        if (!apiKey) throw new Error("API key not configured.");

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
                    return response.json;
                }

                // ── Client errors (4xx) — permanent, do NOT retry ──
                if (response.status === 401) {
                    throw new Error(
                        "Invalid or expired API key. Please generate a new one from the website."
                    );
                }
                if (response.status === 403) {
                    throw new Error(
                        "API key has been revoked. Generate a new one from the website."
                    );
                }
                if (response.status >= 400 && response.status < 500) {
                    throw new Error(`HTTP ${response.status}: ${JSON.stringify(response.json)}`);
                }

                // ── Server errors (5xx) — transient, retry ──
                lastError = new Error(
                    `Server error (HTTP ${response.status}). ` +
                    (attempt < MAX_RETRIES ? "Retrying..." : "All retries exhausted.")
                );
            } catch (error: unknown) {
                const err = error instanceof Error ? error : new Error(String(error));

                // If it's a non-retryable error we threw above, propagate immediately
                if (
                    err.message.includes("API key") ||
                    err.message.includes("not configured") ||
                    err.message.startsWith("HTTP 4")
                ) {
                    throw err;
                }

                // Network error or unexpected failure — retry
                lastError = err;
            }
        }

        // All retries exhausted
        throw new Error(
            `Request failed after ${MAX_RETRIES} retries: ${lastError.message}`
        );
    }

    /** Connect using API Key: fetch config and derive encryption keys. */
    async connect(): Promise<boolean> {
        try {
            const config = await this.request("/config", { method: "GET" }) as ConfigResponse;

            this.plugin.settings.userId = config.userId;
            this.plugin.settings.email = config.email;
            await this.plugin.saveSettings();

            // Derive encryption keys if salt is available
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
                console.warn("[Satset Sync] No encryption salt found. Encrypted notes will be skipped.");
                new Notice("⚠️ No encryption salt. Encrypted notes will be skipped.");
                this.keyring = null;
            }

            this.consecutiveFailures = 0;
            new Notice(`✅ Connected as ${config.email}`);
            return true;
        } catch (error: unknown) {
            this.consecutiveFailures++;
            const message = error instanceof Error ? error.message : String(error);
            new Notice(`❌ Connection failed: ${message}`);
            console.error("[Satset Sync] Connection error:", error);
            return false;
        }
    }

    /** Disconnect: clear API Key and user data. */
    async disconnect(): Promise<void> {
        this.plugin.settings.apiKey = "";
        this.plugin.settings.userId = "";
        this.plugin.settings.email = "";
        this.keyring = null;
        this.consecutiveFailures = 0;
        await this.plugin.saveSettings();
        new Notice("👋 Disconnected.");
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

    /** Main sync function. */
    async syncNotes(): Promise<void> {
        const { apiKey, syncFolder, lastSyncTime } = this.plugin.settings;

        if (!apiKey) {
            new Notice("⚠️ Please connect with an API key first.");
            return;
        }

        // Ensure keyring is ready
        if (!this.keyring && this.plugin.settings.userId) {
            try {
                const config = await this.request("/config", { method: "GET" }) as ConfigResponse;
                if (config.encryptionSalt) {
                    const salt = new Uint8Array(base64ToArrayBuffer(config.encryptionSalt));
                    const passphrase = `${config.userId}:${config.email}`;

                    const [keyV1, keyV2] = await Promise.all([
                        deriveEncryptionKey(passphrase, salt, PBKDF2_ITERATIONS_V1),
                        deriveEncryptionKey(passphrase, salt, PBKDF2_ITERATIONS_V2)
                    ]);

                    this.keyring = {
                        [ENCRYPTION_VERSION_V1]: keyV1,
                        [ENCRYPTION_VERSION_V2]: keyV2
                    };
                }
            } catch {
                // Non-fatal; encrypted notes will be skipped
            }
        }

        try {
            // Build the ID -> file path index
            await this.buildIdIndex(syncFolder);

            let query = "";
            if (lastSyncTime) {
                query += `?since=${encodeURIComponent(lastSyncTime)}`;
            }

            new Notice("🔄 Syncing notes...");

            const result = await this.request(`/${query}`, { method: "GET" }) as { notes?: SatsetNote[] };
            const notes: SatsetNote[] = result.notes || [];

            await this.ensureFolder(syncFolder);

            let created = 0;
            let updated = 0;
            let skipped = 0;
            let renamed = 0;
            let decryptFailed = 0;
            let maxUpdatedAt = lastSyncTime;

            for (const note of notes) {
                // Decrypt if needed
                if (note.encrypted && this.keyring) {
                    try {
                        note.title = await decryptText(note.title, this.keyring);
                        note.content = note.content ? await decryptText(note.content, this.keyring) : "";
                    } catch (err: unknown) {
                        console.warn(`[Satset Sync] Decrypt failed for ${note.id}:`, err);
                        note.title = `Decryption failed ${note.id.substring(0, 8)}`;
                        note.content = `> [!ERROR] Decryption failed\n> Could not decrypt this note. It might use a different key or be corrupted.\n\nRaw content length: ${note.content?.length ?? 0}`;
                        decryptFailed++;
                    }
                } else if (note.encrypted && !this.keyring) {
                    // Skip if we can't decrypt at all (no key derived)
                    skipped++;
                    continue;
                }

                const syncResult = await this.writeNoteSmartSync(note, syncFolder);
                if (syncResult === "created") created++;
                else if (syncResult === "updated") updated++;
                else if (syncResult === "renamed") renamed++;
                else if (syncResult === "skipped") skipped++;

                if (note.updated_at > maxUpdatedAt) {
                    maxUpdatedAt = note.updated_at;
                }

                // Batch save settings (every 10 items) to persist hashes
                if ((created + updated + renamed + skipped) % 10 === 0) {
                    await this.plugin.saveSettings();
                }
            }

            // ── Soft Delete Sync ──
            const archived = await this.syncDeletions(syncFolder, lastSyncTime);

            this.plugin.settings.lastSyncTime = maxUpdatedAt;
            await this.plugin.saveSettings();

            // ✅ Sync succeeded — reset failure counter
            this.consecutiveFailures = 0;

            const parts: string[] = [];
            if (created > 0) parts.push(`${created} created`);
            if (updated > 0) parts.push(`${updated} updated`);
            if (renamed > 0) parts.push(`${renamed} renamed`);
            if (skipped > 0) parts.push(`${skipped} skipped`);
            if (archived > 0) parts.push(`${archived} archived`);
            if (decryptFailed > 0) parts.push(`${decryptFailed} errors`);

            if (notes.length === 0 && archived === 0) {
                new Notice("✅ Already up to date.");
            } else {
                new Notice(`✅ Sync complete: ${parts.join(", ") || "no changes"}`);
            }
        } catch (error: unknown) {
            this.consecutiveFailures++;
            const message = error instanceof Error ? error.message : String(error);
            console.error(`[Satset Sync] Sync error (failure #${this.consecutiveFailures}):`, error);
            new Notice(`❌ Sync error: ${message}`);
        }
    }

    /**
     * Sync deletions: query the /deleted endpoint and archive local files.
     */
    private async syncDeletions(syncFolder: string, lastSyncTime: string): Promise<number> {
        try {
            let query = "/deleted";
            if (lastSyncTime) {
                query += `?since=${encodeURIComponent(lastSyncTime)}`;
            }

            const result = await this.request(query, { method: "GET" }) as {
                deleted?: DeletedNote[];
            };
            const deletedNotes = result.deleted || [];

            if (deletedNotes.length === 0) return 0;

            const archiveFolder = normalizePath(`${syncFolder}/_archived`);
            await this.ensureFolder(archiveFolder);

            const vault: Vault = this.plugin.app.vault;
            let archived = 0;

            for (const del of deletedNotes) {
                const existingPath = this.idToFileMap.get(del.note_id);
                if (!existingPath) continue;

                const file = vault.getAbstractFileByPath(existingPath);
                if (!(file instanceof TFile)) continue;

                try {
                    let archivePath = normalizePath(`${archiveFolder}/${file.name}`);
                    archivePath = await this.getUniqueArchivePath(archivePath);

                    await vault.rename(file, archivePath);

                    const archivedFile = vault.getAbstractFileByPath(archivePath);
                    if (archivedFile instanceof TFile) {
                        let content = await vault.read(archivedFile);
                        content = content.replace(/^satset_id:/m, "satset_deleted_from:");
                        content = content.replace(
                            /^---\n/m,
                            `---\ndeleted_at: "${del.deleted_at}"\n`
                        );
                        await vault.modify(archivedFile, content);
                    }

                    this.idToFileMap.delete(del.note_id);
                    delete this.plugin.settings.syncedFiles[del.note_id];

                    archived++;
                    console.debug(
                        `[Satset Sync] Archived deleted note: ${existingPath} → ${archivePath}`
                    );
                } catch (err: unknown) {
                    console.warn(
                        `[Satset Sync] Failed to archive ${existingPath}:`,
                        err
                    );
                }
            }

            if (archived > 0) {
                new Notice(
                    `📦 ${archived} deleted note${archived > 1 ? "s" : ""} archived to _archived/ folder.`
                );
                await this.plugin.saveSettings();
            }

            return archived;
        } catch (error: unknown) {
            console.warn("[Satset Sync] Deletion sync skipped:", error);
            return 0;
        }
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
                    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
                    const conflictFilename = `${existingFile.basename} (Conflict ${timestamp}).md`;
                    const conflictPath = normalizePath(`${existingFile.parent?.path}/${conflictFilename}`);

                    await vault.rename(existingFile, conflictPath);
                    new Notice(`⚠️ Conflict detected: ${existingFile.basename}. \nLocal changes backed up to "${conflictFilename}".`);

                    const conflictFile = vault.getAbstractFileByPath(conflictPath);
                    if (conflictFile instanceof TFile) {
                        let conflictContent = await vault.read(conflictFile);
                        conflictContent = conflictContent.replace(/^satset_id:/m, "satset_conflict_of:");
                        await vault.modify(conflictFile, conflictContent);
                    }

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
                        console.warn(`[Satset Sync] Rename failed for ${note.id}, updating in place:`, err);
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

    private async getUniqueArchivePath(basePath: string): Promise<string> {
        const vault: Vault = this.plugin.app.vault;
        let candidatePath = basePath;
        let counter = 1;

        while (vault.getAbstractFileByPath(candidatePath)) {
            const extIndex = basePath.lastIndexOf(".");
            const base = extIndex > -1 ? basePath.substring(0, extIndex) : basePath;
            const ext = extIndex > -1 ? basePath.substring(extIndex) : "";
            candidatePath = `${base} (${counter})${ext}`;
            counter++;
        }

        return candidatePath;
    }

    private noteToMarkdown(note: SatsetNote): string {
        const fm: string[] = ["---"];
        fm.push(`satset_id: "${note.id}"`);
        fm.push(`created_at: "${note.created_at}"`);
        fm.push(`updated_at: "${note.updated_at}"`);

        if (note.labels && note.labels.length > 0) {
            fm.push("tags:");
            for (const label of note.labels) fm.push(`  - "${label}"`);
        }
        if (note.pinned) fm.push("pinned: true");
        if (note.archived) fm.push("archived: true");

        fm.push("---");
        fm.push("");

        const content = note.content || "";
        return fm.join("\n") + `${content}\n`;
    }

    private sanitizeFilename(title: string): string {
        return title
            .replace(/[\\/:*?"<>|]/g, "-")
            .replace(/\s+/g, " ")
            .trim()
            .slice(0, 100) || "Untitled";
    }

    private extractFrontmatterValue(content: string, key: string): string | null {
        const match = content.match(new RegExp(`^${key}:\\s*"?([^"\\n]+)"?`, "m"));
        return match ? match[1].trim() : null;
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
