/**
 * Satset Sync - Settings
 *
 * Defines the plugin settings interface and the Settings Tab UI.
 */
import { App, PluginSettingTab, Setting, Notice } from "obsidian";
import type SatsetSyncPlugin from "./main";

export interface SatsetSyncSettings {
    /** Supabase Project URL */
    supabaseUrl: string;

    /** Supabase Anon Public Key */
    supabaseKey: string;

    /** User Email (for login) */
    email: string;

    /** Saved Access Token (JWT) */
    accessToken: string;

    /** Saved Refresh Token */
    refreshToken: string;

    /** User ID (for encryption key derivation) */
    userId: string;

    /** Folder inside the vault where synced notes are stored */
    syncFolder: string;

    /** Auto-sync interval in minutes (0 = manual only) */
    syncIntervalMinutes: number;

    /** ISO timestamp of the last successful sync */
    lastSyncTime: string;

    /** Whether to include archived notes */
    includeArchived: boolean;
}

export const DEFAULT_SETTINGS: SatsetSyncSettings = {
    supabaseUrl: "https://ixvbsexujxdbbvzvmybj.supabase.co",
    supabaseKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Iml4dmJzZXh1anhkYmJ2enZteWJqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDk5Mzg4MDAsImV4cCI6MjA2NTUxNDgwMH0.CYpokPpeceFYzh9gMh-ymGYte9iCWcNamCCIc56Fh1I",
    email: "",
    accessToken: "",
    refreshToken: "",
    userId: "",
    syncFolder: "Satset",
    syncIntervalMinutes: 5,
    lastSyncTime: "",
    includeArchived: false,
};

export class SatsetSyncSettingTab extends PluginSettingTab {
    plugin: SatsetSyncPlugin;
    passwordInput: string = ""; // Temporary storage for password input

    constructor(app: App, plugin: SatsetSyncPlugin) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display(): void {
        const { containerEl } = this;
        containerEl.empty();

        containerEl.createEl("h2", { text: "Satset Sync Settings" });

        // --- Authentication Section ---
        containerEl.createEl("h3", { text: "Authentication" });

        const isLoggedIn = !!this.plugin.settings.accessToken;

        if (isLoggedIn) {
            const statusDiv = containerEl.createDiv({ cls: "satset-status-box" });
            statusDiv.createEl("p", {
                text: `✅ Logged in as ${this.plugin.settings.email}`,
                style: "color: var(--text-success); font-weight: bold;"
            });

            new Setting(containerEl)
                .setName("Logout")
                .setDesc("Sign out and clear stored tokens.")
                .addButton((button: any) =>
                    button
                        .setButtonText("Logout")
                        .setWarning()
                        .onClick(async () => {
                            await this.plugin.syncService.logout();
                            this.display(); // Refresh UI
                        })
                );
        } else {
            // Login form — Supabase URL and Key are pre-configured
            new Setting(containerEl)
                .setName("Email")
                .setDesc("Your Satset account email")
                .addText((text: any) =>
                    text
                        .setPlaceholder("email@example.com")
                        .setValue(this.plugin.settings.email)
                        .onChange(async (value: string) => {
                            this.plugin.settings.email = value.trim();
                            await this.plugin.saveSettings();
                        })
                );

            new Setting(containerEl)
                .setName("Password")
                .setDesc("Your Satset account password")
                .addText((text: any) => {
                    text.inputEl.type = "password";
                    text
                        .setPlaceholder("Password")
                        .setValue(this.passwordInput)
                        .onChange((value: string) => {
                            this.passwordInput = value;
                        });
                });

            new Setting(containerEl)
                .setName("Login")
                .addButton((button: any) =>
                    button
                        .setButtonText("Login")
                        .setCta()
                        .onClick(async () => {
                            button.setButtonText("Logging in...");
                            button.setDisabled(true);
                            const success = await this.plugin.syncService.login(
                                this.plugin.settings.email,
                                this.passwordInput
                            );
                            if (success) {
                                this.passwordInput = ""; // Clear password from memory
                                this.display(); // Refresh UI to show logged-in state
                            } else {
                                button.setButtonText("Login Failed");
                                button.setDisabled(false);
                            }
                        })
                );
        }

        // --- Sync Configuration ---
        containerEl.createEl("h3", { text: "Sync Configuration" });

        new Setting(containerEl)
            .setName("Sync Folder")
            .setDesc("The folder inside your vault where Satset notes will be saved.")
            .addText((text: any) =>
                text
                    .setPlaceholder("Satset")
                    .setValue(this.plugin.settings.syncFolder)
                    .onChange(async (value: string) => {
                        this.plugin.settings.syncFolder = value.trim() || "Satset";
                        await this.plugin.saveSettings();
                    })
            );

        new Setting(containerEl)
            .setName("Auto-sync Interval (minutes)")
            .setDesc("How often to automatically sync. Set to 0 to disable auto-sync.")
            .addText((text: any) =>
                text
                    .setPlaceholder("5")
                    .setValue(String(this.plugin.settings.syncIntervalMinutes))
                    .onChange(async (value: string) => {
                        const num = parseInt(value, 10);
                        this.plugin.settings.syncIntervalMinutes = isNaN(num) ? 5 : Math.max(0, num);
                        await this.plugin.saveSettings();
                        this.plugin.restartAutoSync();
                    })
            );

        new Setting(containerEl)
            .setName("Include Archived Notes")
            .setDesc("Whether to also sync notes that you've archived in Satset.")
            .addToggle((toggle: any) =>
                toggle
                    .setValue(this.plugin.settings.includeArchived)
                    .onChange(async (value: boolean) => {
                        this.plugin.settings.includeArchived = value;
                        await this.plugin.saveSettings();
                    })
            );

        new Setting(containerEl)
            .setName("Force Full Resync")
            .setDesc("Clear sync history and re-download all notes.")
            .addButton((button: any) =>
                button
                    .setButtonText("Reset Sync History")
                    .setWarning()
                    .onClick(async () => {
                        this.plugin.settings.lastSyncTime = "";
                        await this.plugin.saveSettings();
                        this.display();
                        new Notice("History cleared. Click 'Sync Now' to re-download all notes.");
                    })
            );

        // --- Status Section ---
        containerEl.createEl("h3", { text: "Status" });

        const lastSync = this.plugin.settings.lastSyncTime
            ? new Date(this.plugin.settings.lastSyncTime).toLocaleString()
            : "Never";

        new Setting(containerEl)
            .setName("Last Sync")
            .setDesc(lastSync)
            .addButton((button: any) =>
                button
                    .setButtonText("Sync Now")
                    .setDisabled(!isLoggedIn)
                    .onClick(async () => {
                        button.setButtonText("Syncing...");
                        button.setDisabled(true);
                        try {
                            await this.plugin.syncService.syncNotes();
                            this.display();
                        } catch (e) {
                            console.error("Sync failed:", e);
                            button.setButtonText("Failed");
                        } finally {
                            button.setDisabled(false);
                            setTimeout(() => { if (button) button.setButtonText("Sync Now") }, 2000);
                        }
                    })
            );
    }
}
