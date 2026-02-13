/**
 * Satset Sync - Sync Service
 *
 * Handles communication with the Satset sync-notes Edge Function via API Key,
 * writing/updating Markdown files in Obsidian, and AES-GCM decryption.
 * 
 * Smart Sync: Uses satset_id in frontmatter to prevent duplicates,
 * handles renames, and supports incremental sync.
 */
import { Notice, Vault, TFile, TFolder, normalizePath, requestUrl } from "obsidian";
import type SatsetSyncPlugin from "./main";

// ── Encryption Constants (must match Satset web app) ──
const ENCRYPTION_VERSION = "v1";
const PBKDF2_ITERATIONS = 100000;
const KEY_LENGTH = 256;

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

// ── Crypto Helpers ──
function base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

async function deriveEncryptionKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(passphrase),
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"]
    );
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt as BufferSource, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: KEY_LENGTH },
        false,
        ["decrypt"]
    );
}

async function decryptText(encrypted: string, key: CryptoKey): Promise<string> {
    if (!encrypted) return encrypted;
    if (!encrypted.includes("|")) return encrypted;

    const parts = encrypted.split("|");
    if (parts.length !== 4) throw new Error("Invalid encrypted format");

    const [version, _salt, ivB64, ciphertextB64] = parts;
    if (version !== ENCRYPTION_VERSION) throw new Error(`Unsupported encryption version: ${version}`);

    const iv = new Uint8Array(base64ToArrayBuffer(ivB64));
    const ciphertext = new Uint8Array(base64ToArrayBuffer(ciphertextB64));

    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return new TextDecoder().decode(decrypted);
}

// ── Main Service ──
export class SyncService {
    private plugin: SatsetSyncPlugin;
    private encryptionKey: CryptoKey | null = null;

    // In-memory index: satset_id -> file path (built on each sync)
    private idToFileMap: Map<string, string> = new Map();

    constructor(plugin: SatsetSyncPlugin) {
        this.plugin = plugin;
    }

    /** HTTP request to the sync-notes Edge Function. */
    private async request(path: string, options: any = {}): Promise<any> {
        const { supabaseUrl, apiKey } = this.plugin.settings;
        if (!supabaseUrl) throw new Error("Supabase URL not configured.");
        if (!apiKey) throw new Error("API Key not configured.");

        const url = `${supabaseUrl}/functions/v1/sync-notes${path}`;
        const response = await requestUrl({
            url,
            ...options,
            headers: {
                "Content-Type": "application/json",
                "x-api-key": apiKey,
                ...options.headers,
            },
        });

        if (response.status >= 200 && response.status < 300) {
            return response.json;
        }

        // Handle specific error codes
        if (response.status === 401) {
            throw new Error("Invalid or expired API Key. Please reconnect.");
        }
        if (response.status === 403) {
            throw new Error("API Key has been revoked. Generate a new one from the website.");
        }
        throw new Error(`HTTP ${response.status}: ${JSON.stringify(response.json)}`);
    }

    /** Connect using API Key: fetch config and derive encryption key. */
    async connect(): Promise<boolean> {
        try {
            const config: ConfigResponse = await this.request("/config", { method: "GET" });

            this.plugin.settings.userId = config.userId;
            this.plugin.settings.email = config.email;
            await this.plugin.saveSettings();

            // Derive encryption key if salt is available
            if (config.encryptionSalt) {
                const salt = new Uint8Array(base64ToArrayBuffer(config.encryptionSalt));
                const passphrase = `${config.userId}:${config.email}`;
                this.encryptionKey = await deriveEncryptionKey(passphrase, salt);
                console.log("[Satset Sync] Encryption key derived ✓");
            } else {
                console.warn("[Satset Sync] No encryption salt found. Encrypted notes will be skipped.");
                new Notice("⚠️ No encryption salt. Encrypted notes will be skipped.");
                this.encryptionKey = null;
            }

            new Notice(`✅ Connected as ${config.email}`);
            return true;
        } catch (error: any) {
            new Notice(`❌ Connection failed: ${error.message}`);
            console.error("[Satset Sync] Connection error:", error);
            return false;
        }
    }

    /** Disconnect: clear API Key and user data. */
    async disconnect(): Promise<void> {
        this.plugin.settings.apiKey = "";
        this.plugin.settings.userId = "";
        this.plugin.settings.email = "";
        this.encryptionKey = null;
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

        console.log(`[Satset Sync] Indexed ${this.idToFileMap.size} files by satset_id.`);
    }

    /** Main sync function. */
    async syncNotes(): Promise<void> {
        const { apiKey, syncFolder, lastSyncTime } = this.plugin.settings;

        if (!apiKey) {
            new Notice("⚠️ Please connect with an API Key first.");
            return;
        }

        // Ensure encryption key is ready
        if (!this.encryptionKey && this.plugin.settings.userId) {
            try {
                const config: ConfigResponse = await this.request("/config", { method: "GET" });
                if (config.encryptionSalt) {
                    const salt = new Uint8Array(base64ToArrayBuffer(config.encryptionSalt));
                    const passphrase = `${config.userId}:${config.email}`;
                    this.encryptionKey = await deriveEncryptionKey(passphrase, salt);
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

            console.log(`[Satset Sync] Fetching notes: ${query}`);
            new Notice("🔄 Syncing notes...");

            const result = await this.request(`/${query}`, { method: "GET" });
            const notes: SatsetNote[] = result.notes || [];

            if (notes.length === 0) {
                new Notice("✅ Already up to date.");
                return;
            }

            await this.ensureFolder(syncFolder);

            let created = 0;
            let updated = 0;
            let skipped = 0;
            let renamed = 0;
            let decryptFailed = 0;
            let maxUpdatedAt = lastSyncTime;

            for (const note of notes) {
                // Decrypt if needed
                if (note.encrypted && this.encryptionKey) {
                    try {
                        note.title = await decryptText(note.title, this.encryptionKey);
                        note.content = note.content ? await decryptText(note.content, this.encryptionKey) : "";
                    } catch (err) {
                        console.warn(`[Satset Sync] Decrypt failed for ${note.id}:`, err);
                        note.title = `Decryption Failed ${note.id.substring(0, 8)}`;
                        note.content = `> [!ERROR] Decryption Failed\n> Could not decrypt this note. It might use a different key or be corrupted.\n\nRaw content length: ${note.content?.length ?? 0}`;
                        decryptFailed++;
                    }
                } else if (note.encrypted && !this.encryptionKey) {
                    // Skip if we can't decrypt at all (no key derived)
                    skipped++;
                    continue;
                }

                const result = await this.writeNoteSmartSync(note, syncFolder);
                if (result === "created") created++;
                else if (result === "updated") updated++;
                else if (result === "renamed") renamed++;
                else if (result === "skipped") skipped++;

                if (note.updated_at > maxUpdatedAt) {
                    maxUpdatedAt = note.updated_at;
                }
            }

            this.plugin.settings.lastSyncTime = maxUpdatedAt;
            await this.plugin.saveSettings();

            const parts: string[] = [];
            if (created > 0) parts.push(`${created} created`);
            if (updated > 0) parts.push(`${updated} updated`);
            if (renamed > 0) parts.push(`${renamed} renamed`);
            if (skipped > 0) parts.push(`${skipped} skipped`);
            if (decryptFailed > 0) parts.push(`${decryptFailed} errors`);

            new Notice(`✅ Sync complete: ${parts.join(", ") || "no changes"}`);
        } catch (error: any) {
            console.error("[Satset Sync] Sync error:", error);
            new Notice(`❌ Sync error: ${error.message}`);
        }
    }

    /**
     * Smart Sync write logic:
     * 1. Check ID index for existing file with same satset_id.
     * 2. If found: compare updated_at, skip if unchanged, update if changed, rename if title changed.
     * 3. If not found: find a UNIQUE filename (handle collisions) and create.
     */
    private async writeNoteSmartSync(
        note: SatsetNote, folderPath: string
    ): Promise<"created" | "updated" | "renamed" | "skipped"> {
        const vault: Vault = this.plugin.app.vault;
        const title = this.sanitizeFilename(note.title || "Untitled");
        const content = this.noteToMarkdown(note);

        // Step 1: Check if a file with this satset_id already exists (mapped by previous syncs)
        const existingPath = this.idToFileMap.get(note.id);

        if (existingPath) {
            const existingFile = vault.getAbstractFileByPath(existingPath);
            if (existingFile instanceof TFile) {
                const existingContent = await vault.read(existingFile);
                const existingUpdatedAt = this.extractFrontmatterValue(existingContent, "updated_at");

                // Skip if local file is already up to date
                if (existingUpdatedAt && existingUpdatedAt >= note.updated_at) {
                    return "skipped";
                }

                // Determine target path (handling renames if title changed)
                // We want to keep the SAME filename if title matches, or rename if it changed.
                // If renaming, we must ensure the NEW name doesn't collide.
                // But wait, if we are just updating, we usually keep the filename unless we force rename on title change.
                // Let's stick to: Rename if title changed.

                // Construct ideal path from current title
                let targetPath = normalizePath(`${folderPath}/${title}.md`);

                // Only rename if the path implies a title change
                if (existingFile.path !== targetPath) {
                    // Ensure targetPath is unique (could match another note's title)
                    targetPath = await this.getUniquePath(targetPath, note.id);

                    try {
                        await vault.rename(existingFile, targetPath);
                        const renamedFile = vault.getAbstractFileByPath(targetPath);
                        if (renamedFile instanceof TFile) {
                            await vault.modify(renamedFile, content);
                        }
                        this.idToFileMap.set(note.id, targetPath);
                        return "renamed";
                    } catch (err) {
                        console.warn(`[Satset Sync] Rename failed for ${note.id}, updating in place:`, err);
                        await vault.modify(existingFile, content);
                        return "updated";
                    }
                }

                // Same filename, just update content
                await vault.modify(existingFile, content);
                return "updated";
            }
        }

        // Step 2: New file (or not found in index)
        // Ensure we don't overwrite an existing file that belongs to a different ID (collision)
        let targetPath = normalizePath(`${folderPath}/${title}.md`);
        targetPath = await this.getUniquePath(targetPath, note.id);

        await vault.create(targetPath, content);
        this.idToFileMap.set(note.id, targetPath);
        return "created";
    }

    /**
     * Generates a unique file path by appending (1), (2), etc. if the path exists
     * and belongs to a different note (or is unmanaged).
     */
    private async getUniquePath(basePath: string, noteId: string): Promise<string> {
        const vault: Vault = this.plugin.app.vault;
        let candidatePath = basePath;
        let counter = 1;

        while (true) {
            const file = vault.getAbstractFileByPath(candidatePath);
            if (!file) {
                // Path is free!
                return candidatePath;
            }

            // File exists. Does it belong to THIS note?
            if (file instanceof TFile) {
                // Check in-memory map first (fastest)
                // If this file path is mapped to OUR noteId, then it's ours.
                // iterate map? No, map is id -> path.
                // We want path -> id.

                // Let's check if the file content has our ID.
                // Optimization: Check if the file path matches what we *expect* for this ID? 
                // No, we are deciding the path.

                // If the existing file has our ID, then we can overwrite it (it's the same note).
                // BUT, `writeNoteSmartSync` Step 1 handles "Known existing file".
                // We only call this when:
                // A) We are creating a NEW note (Step 2) -> We shouldn't overwrite anything unless it's a ghost.
                // B) We are RENAMING a note (Step 1) -> We shouldn't overwrite another note.

                // So, if file exists, we MUST check its ID.
                try {
                    const content = await vault.cachedRead(file);
                    const existingId = this.extractFrontmatterValue(content, "satset_id");

                    if (existingId === noteId) {
                        // It's us! (Maybe map was out of sync, or we are renaming to same name?)
                        return candidatePath;
                    }
                } catch {
                    // Can't read? Treat as taken.
                }
            }

            // Collision! Append counter.
            // strip extension
            const extIndex = basePath.lastIndexOf(".");
            const base = extIndex > -1 ? basePath.substring(0, extIndex) : basePath;
            const ext = extIndex > -1 ? basePath.substring(extIndex) : "";

            candidatePath = `${base} (${counter})${ext}`;
            counter++;
        }
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
}
