/**
 * Satset Sync - Main Plugin Entry Point
 *
 * This Obsidian plugin synchronizes notes from Satset Note-taking
 * into the user's local Obsidian vault.
 */
import { Plugin } from "obsidian";
import {
    SatsetSyncSettings,
    DEFAULT_SETTINGS,
    SatsetSyncSettingTab,
} from "./settings";
import { SyncService } from "./sync";

export default class SatsetSyncPlugin extends Plugin {
    settings: SatsetSyncSettings = DEFAULT_SETTINGS;
    syncService: SyncService = new SyncService(this);
    private autoSyncInterval: number | null = null;

    async onload() {
        await this.loadSettings();

        // Add settings tab
        this.addSettingTab(new SatsetSyncSettingTab(this.app, this));

        // Add ribbon icon for manual sync
        this.addRibbonIcon("refresh-cw", "Sync notes from Satset", async () => {
            await this.syncService.syncNotes();
        });

        // Add command: Sync Now
        this.addCommand({
            id: "sync-now",
            name: "Sync notes from Satset",
            callback: async () => {
                await this.syncService.syncNotes();
            },
        });

        // Start auto-sync if configured
        this.startAutoSync();
    }

    onunload() {
        this.stopAutoSync();
    }

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
    }

    async saveSettings() {
        await this.saveData(this.settings);
    }

    /**
     * Start the auto-sync interval timer.
     */
    startAutoSync() {
        this.stopAutoSync();

        const minutes = this.settings.syncIntervalMinutes;
        if (minutes <= 0 || !this.settings.apiKey) return;

        const ms = minutes * 60 * 1000;
        this.autoSyncInterval = window.setInterval(() => {
            this.syncService.syncNotes();
        }, ms);

        // Register the interval so Obsidian can clean it up
        this.registerInterval(this.autoSyncInterval);
    }

    /**
     * Stop the auto-sync interval timer.
     */
    stopAutoSync() {
        if (this.autoSyncInterval !== null) {
            window.clearInterval(this.autoSyncInterval);
            this.autoSyncInterval = null;
        }
    }

    /**
     * Restart auto-sync (called when settings change).
     */
    restartAutoSync() {
        this.startAutoSync();
    }
}
