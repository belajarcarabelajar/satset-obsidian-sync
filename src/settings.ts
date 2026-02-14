/**
 * Satset Sync - Settings
 *
 * Defines the plugin settings interface and the Settings Tab UI.
 * Uses API Key authentication instead of Email/Password for security.
 */
import { App, PluginSettingTab, Setting, Notice, ButtonComponent, TextComponent } from "obsidian";
import type SatsetSyncPlugin from "./main";

export interface SatsetSyncSettings {
    /** Supabase Project URL */
    supabaseUrl: string;

    /** API Key for sync-notes authentication */
    apiKey: string;

    /** User ID (resolved from API Key) */
    userId: string;

    /** User Email (resolved from API Key) */
    email: string;

    /** Folder inside the vault where synced notes are stored */
    syncFolder: string;

    /** Auto-sync interval in minutes (0 = manual only) */
    syncIntervalMinutes: number;

    /** ISO timestamp of the last successful sync */
    lastSyncTime: string;

    /** Map of satset_id -> SHA-256 hash of the content (excluding frontmatter) */
    syncedFiles: Record<string, string>;
}

export const DEFAULT_SETTINGS: SatsetSyncSettings = {
    supabaseUrl: "https://ixvbsexujxdbbvzvmybj.supabase.co",
    apiKey: "",
    userId: "",
    email: "",
    syncFolder: "Satset",
    syncIntervalMinutes: 5,
    lastSyncTime: "",
    syncedFiles: {},
};

export class SatsetSyncSettingTab extends PluginSettingTab {
    plugin: SatsetSyncPlugin;

    constructor(app: App, plugin: SatsetSyncPlugin) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display(): void {
        const { containerEl } = this;
        containerEl.empty();

        new Setting(containerEl).setName("Satset Sync settings").setHeading();

        // --- Authentication Section ---
        new Setting(containerEl).setName("Authentication").setHeading();

        const isConnected = !!this.plugin.settings.apiKey && !!this.plugin.settings.userId;

        if (isConnected) {
            const statusDiv = containerEl.createDiv({ cls: "satset-status-connected" });
            statusDiv.createEl("p", {
                text: `✅ Connected as ${this.plugin.settings.email}`,
            });

            new Setting(containerEl)
                .setName("Disconnect")
                .setDesc("Remove API key and clear stored data.")
                .addButton((button: ButtonComponent) =>
                    button
                        .setButtonText("Disconnect")
                        .setWarning()
                        .onClick(async () => {
                            await this.plugin.syncService.disconnect();
                            this.display();
                        })
                );
        } else {
            new Setting(containerEl)
                .setName("Supabase project URL")
                .setDesc("Your Supabase project URL")
                .addText((text: TextComponent) =>
                    text
                        .setPlaceholder("https://your-project.supabase.co")
                        .setValue(this.plugin.settings.supabaseUrl)
                        .onChange(async (value: string) => {
                            this.plugin.settings.supabaseUrl = value.trim();
                            await this.plugin.saveSettings();
                        })
                );

            new Setting(containerEl)
                .setName("API key")
                .setDesc("Generate an API key from the Satset website (Integrations page).")
                .addText((text: TextComponent) => {
                    text.inputEl.type = "password";
                    text.inputEl.style.width = "100%";
                    text
                        .setPlaceholder("satset_sk_...")
                        .setValue(this.plugin.settings.apiKey)
                        .onChange(async (value: string) => {
                            this.plugin.settings.apiKey = value.trim();
                            await this.plugin.saveSettings();
                        });
                });

            new Setting(containerEl)
                .setName("Connect")
                .addButton((button: ButtonComponent) =>
                    button
                        .setButtonText("Connect")
                        .setCta()
                        .onClick(async () => {
                            if (!this.plugin.settings.apiKey) {
                                new Notice("❌ Please enter an API key first.");
                                return;
                            }
                            button.setButtonText("Connecting...");
                            button.setDisabled(true);
                            const success = await this.plugin.syncService.connect();
                            if (success) {
                                this.display();
                            } else {
                                button.setButtonText("Connect");
                                button.setDisabled(false);
                            }
                        })
                );
        }

        // --- Sync Configuration ---
        new Setting(containerEl).setName("Sync configuration").setHeading();

        new Setting(containerEl)
            .setName("Sync folder")
            .setDesc("The folder inside your vault where Satset notes will be saved.")
            .addText((text: TextComponent) =>
                text
                    .setPlaceholder("Satset")
                    .setValue(this.plugin.settings.syncFolder)
                    .onChange(async (value: string) => {
                        this.plugin.settings.syncFolder = value.trim() || "Satset";
                        await this.plugin.saveSettings();
                    })
            );

        new Setting(containerEl)
            .setName("Auto-sync interval (minutes)")
            .setDesc("How often to automatically sync. Set to 0 to disable auto-sync.")
            .addText((text: TextComponent) =>
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
            .setName("Force full resync")
            .setDesc("Clear sync history and re-download all notes.")
            .addButton((button: ButtonComponent) =>
                button
                    .setButtonText("Reset sync history")
                    .setWarning()
                    .onClick(async () => {
                        this.plugin.settings.lastSyncTime = "";
                        this.plugin.settings.syncedFiles = {};
                        await this.plugin.saveSettings();
                        this.display();
                        new Notice("History cleared. Click 'Sync now' to re-download all notes.");
                    })
            );

        // --- Status Section ---
        new Setting(containerEl).setName("Status").setHeading();

        const lastSync = this.plugin.settings.lastSyncTime
            ? new Date(this.plugin.settings.lastSyncTime).toLocaleString()
            : "Never";

        new Setting(containerEl)
            .setName("Last sync")
            .setDesc(lastSync)
            .addButton((button: ButtonComponent) =>
                button
                    .setButtonText("Sync now")
                    .setDisabled(!isConnected)
                    .onClick(async () => {
                        button.setButtonText("Syncing...");
                        button.setDisabled(true);
                        try {
                            await this.plugin.syncService.syncNotes();
                            this.display();
                        } catch (e: unknown) {
                            console.error("Sync failed:", e);
                            button.setButtonText("Failed");
                        } finally {
                            button.setDisabled(false);
                            setTimeout(() => { if (button) button.setButtonText("Sync now") }, 2000);
                        }
                    })
            );
    }
}
