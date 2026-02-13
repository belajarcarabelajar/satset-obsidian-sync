/**
 * Satset Sync - Sync Service
 *
 * Handles communication directly with Supabase via REST API
 * (Auth + PostgREST) and writing/updating Markdown files.
 * Includes AES-GCM decryption for encrypted notes.
 */
import { Notice, Vault, TFile, normalizePath, requestUrl } from "obsidian";
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

interface AuthResponse {
    access_token: string;
    refresh_token: string;
    user: { id: string; email: string };
    expires_in: number;
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

    constructor(plugin: SatsetSyncPlugin) {
        this.plugin = plugin;
    }

    /** Parse JWT payload to extract userId and email (fallback). */
    private parseJwt(token: string): { sub: string; email: string } | null {
        try {
            const payload = JSON.parse(atob(token.split(".")[1]));
            return { sub: payload.sub || "", email: payload.email || "" };
        } catch (e) {
            return null;
        }
    }

    /** Ensure userId/email are in settings (recover from JWT if needed). */
    private async ensureUserInfo(): Promise<{ userId: string; email: string } | null> {
        let { userId, email, accessToken } = this.plugin.settings;
        if (userId && email) return { userId, email };

        // Fallback: extract from JWT
        if (accessToken) {
            const jwt = this.parseJwt(accessToken);
            if (jwt && jwt.sub) {
                userId = jwt.sub;
                email = email || jwt.email;
                this.plugin.settings.userId = userId;
                this.plugin.settings.email = email;
                await this.plugin.saveSettings();
                console.log(`[Satset Sync] Recovered userId from JWT: ${userId}`);
                return { userId, email };
            }
        }
        return null;
    }

    /** HTTP request helper. */
    private async request(endpoint: string, options: any): Promise<any> {
        const { supabaseUrl } = this.plugin.settings;
        if (!supabaseUrl) throw new Error("Supabase URL not configured.");

        const url = `${supabaseUrl}${endpoint}`;
        const response = await requestUrl({
            url,
            ...options,
            headers: { "Content-Type": "application/json", ...options.headers },
        });

        if (response.status >= 200 && response.status < 300) {
            return response.json;
        }
        throw new Error(`HTTP ${response.status}: ${JSON.stringify(response.json)}`);
    }

    /** Login with email/password. Derives encryption key afterwards. */
    async login(email: string, password: string): Promise<boolean> {
        const { supabaseUrl, supabaseKey } = this.plugin.settings;
        if (!supabaseUrl || !supabaseKey) {
            new Notice("❌ Configure Supabase URL and Key first.");
            return false;
        }

        try {
            const data: AuthResponse = await this.request("/auth/v1/token?grant_type=password", {
                method: "POST",
                headers: { apikey: supabaseKey },
                body: JSON.stringify({ email, password }),
            });

            this.plugin.settings.accessToken = data.access_token;
            this.plugin.settings.refreshToken = data.refresh_token;
            this.plugin.settings.email = data.user.email;
            this.plugin.settings.userId = data.user.id;
            await this.plugin.saveSettings();

            await this.initEncryptionKey(data.access_token, data.user.id, data.user.email);

            new Notice(`✅ Logged in as ${data.user.email}`);
            return true;
        } catch (error: any) {
            new Notice("❌ Login failed. Check console for details.");
            console.error("Login error:", error);
            return false;
        }
    }

    /** Fetch encryption salt from profiles table, derive decryption key. */
    private async initEncryptionKey(token: string, userId: string, email: string): Promise<void> {
        const { supabaseKey } = this.plugin.settings;
        try {
            const profiles = await this.request(
                `/rest/v1/profiles?id=eq.${userId}&select=encryption_salt`,
                {
                    method: "GET",
                    headers: { apikey: supabaseKey, Authorization: `Bearer ${token}` },
                }
            );

            if (!profiles || profiles.length === 0 || !profiles[0].encryption_salt) {
                console.warn("[Satset Sync] No encryption salt found.");
                new Notice("⚠️ No encryption salt found. Encrypted notes will be skipped.");
                this.encryptionKey = null;
                return;
            }

            const salt = new Uint8Array(base64ToArrayBuffer(profiles[0].encryption_salt));
            const passphrase = `${userId}:${email}`;
            this.encryptionKey = await deriveEncryptionKey(passphrase, salt);
            console.log("[Satset Sync] Encryption key derived ✓");
        } catch (error) {
            console.error("[Satset Sync] Encryption key derivation failed:", error);
            new Notice("⚠️ Encryption key failed. Check console.");
            this.encryptionKey = null;
        }
    }

    /** Logout and clear all stored credentials. */
    async logout(): Promise<void> {
        this.plugin.settings.accessToken = "";
        this.plugin.settings.refreshToken = "";
        this.plugin.settings.email = "";
        this.plugin.settings.userId = "";
        this.encryptionKey = null;
        await this.plugin.saveSettings();
        new Notice("👋 Logged out.");
    }

    /** Refresh access token using refresh token. */
    async refreshSession(): Promise<boolean> {
        const { supabaseKey, refreshToken } = this.plugin.settings;
        if (!refreshToken) return false;

        try {
            const data: AuthResponse = await this.request("/auth/v1/token?grant_type=refresh_token", {
                method: "POST",
                headers: { apikey: supabaseKey },
                body: JSON.stringify({ refresh_token: refreshToken }),
            });

            this.plugin.settings.accessToken = data.access_token;
            this.plugin.settings.refreshToken = data.refresh_token;
            await this.plugin.saveSettings();

            if (!this.encryptionKey) {
                const userInfo = await this.ensureUserInfo();
                if (userInfo) {
                    await this.initEncryptionKey(data.access_token, userInfo.userId, userInfo.email);
                }
            }

            console.log("[Satset Sync] Session refreshed.");
            return true;
        } catch (error) {
            console.error("[Satset Sync] Refresh failed:", error);
            await this.logout();
            new Notice("⚠️ Session expired. Please login again.");
            return false;
        }
    }

    /** Main sync function. */
    async syncNotes(): Promise<void> {
        const { supabaseKey, accessToken, syncFolder, lastSyncTime, includeArchived } =
            this.plugin.settings;

        if (!accessToken) {
            new Notice("⚠️ Please login first.");
            return;
        }

        // Ensure encryption key is ready (after plugin reload or upgrade from old version)
        if (!this.encryptionKey) {
            const userInfo = await this.ensureUserInfo();
            if (userInfo) {
                await this.initEncryptionKey(accessToken, userInfo.userId, userInfo.email);
            }
        }

        try {
            let query = "/rest/v1/notes?select=*&order=updated_at.asc";
            if (lastSyncTime) {
                query += `&updated_at=gt.${encodeURIComponent(lastSyncTime)}`;
            }
            if (!includeArchived) {
                query += `&archived=is.false`;
            }

            console.log(`[Satset Sync] Requesting: ${query}`);
            new Notice("🔄 Syncing notes...");

            try {
                await this.fetchAndProcessNotes(query, supabaseKey, accessToken, syncFolder);
            } catch (error: any) {
                if (error.message && error.message.includes("401")) {
                    console.log("[Satset Sync] 401, trying refresh...");
                    const refreshed = await this.refreshSession();
                    if (refreshed) {
                        await this.fetchAndProcessNotes(
                            query, supabaseKey, this.plugin.settings.accessToken, syncFolder
                        );
                    }
                } else {
                    throw error;
                }
            }
        } catch (error: any) {
            console.error("[Satset Sync] Sync error:", error);
            new Notice(`❌ Sync error: ${error.message}`);
        }
    }

    private async fetchAndProcessNotes(
        endpoint: string, apiKey: string, token: string, syncFolder: string
    ): Promise<void> {
        const notes: SatsetNote[] = await this.request(endpoint, {
            method: "GET",
            headers: { apikey: apiKey, Authorization: `Bearer ${token}` },
        });

        if (!notes || notes.length === 0) {
            new Notice("✅ Already up to date.");
            return;
        }

        await this.ensureFolder(syncFolder);

        let created = 0;
        let updated = 0;
        let skipped = 0;
        let decryptFailed = 0;
        let maxUpdatedAt = this.plugin.settings.lastSyncTime;

        for (const note of notes) {
            if (note.encrypted && this.encryptionKey) {
                try {
                    note.title = await decryptText(note.title, this.encryptionKey);
                    note.content = note.content ? await decryptText(note.content, this.encryptionKey) : "";
                } catch (err) {
                    console.warn(`[Satset Sync] Decrypt failed for ${note.id}:`, err);
                    decryptFailed++;
                    continue;
                }
            } else if (note.encrypted && !this.encryptionKey) {
                skipped++;
                continue;
            }

            const result = await this.writeNote(note, syncFolder);
            if (result === "created") created++;
            else if (result === "updated") updated++;

            if (note.updated_at > maxUpdatedAt) {
                maxUpdatedAt = note.updated_at;
            }
        }

        this.plugin.settings.lastSyncTime = maxUpdatedAt;
        await this.plugin.saveSettings();

        const parts: string[] = [];
        if (created > 0) parts.push(`${created} created`);
        if (updated > 0) parts.push(`${updated} updated`);
        if (skipped > 0) parts.push(`${skipped} skipped (no key)`);
        if (decryptFailed > 0) parts.push(`${decryptFailed} decrypt failed`);

        new Notice(`✅ Sync complete: ${parts.join(", ") || "no changes"}`);
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

    private async writeNote(note: SatsetNote, folderPath: string): Promise<"created" | "updated" | "skipped"> {
        const vault: Vault = this.plugin.app.vault;
        const title = this.sanitizeFilename(note.title || "Untitled");
        const filePath = normalizePath(`${folderPath}/${title}.md`);
        const content = this.noteToMarkdown(note);

        const existingFile = vault.getAbstractFileByPath(filePath);

        if (existingFile instanceof TFile) {
            const existingContent = await vault.read(existingFile);
            const existingUpdatedAt = this.extractFrontmatterValue(existingContent, "updated_at");
            if (existingUpdatedAt && existingUpdatedAt >= note.updated_at) {
                return "skipped";
            }
            await vault.modify(existingFile, content);
            return "updated";
        } else {
            await vault.create(filePath, content);
            return "created";
        }
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
