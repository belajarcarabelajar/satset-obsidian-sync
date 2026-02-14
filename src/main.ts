/**
 * Satset Sync - Main Plugin Entry Point
 *
 * This Obsidian plugin synchronizes notes from Satset Note-taking
 * into the user's local Obsidian vault.
 *
 * Auto-sync includes exponential backoff: after repeated failures,
 * the plugin progressively skips sync cycles to avoid hammering
 * an unreachable server.
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

    /**
     * Cycle counter used by backoff logic.
     * Incremented every auto-sync tick; compared against a skip factor
     * derived from consecutiveFailures to decide whether to sync or skip.
     */
    private backoffCycleCount = 0;

    async onload() {
        await this.loadSettings();

        // Add settings tab
        this.addSettingTab(new SatsetSyncSettingTab(this.app, this));

        // Add ribbon icon for manual sync
        this.addRibbonIcon("refresh-cw", "Sync notes from Satset", async () => {
            // Manual sync always runs immediately (no backoff)
            await this.syncService.syncNotes();
        });

        // Add command: Sync Now
        this.addCommand({
            id: "sync-now",
            name: "Sync notes from Satset",
            callback: async () => {
                // Manual sync always runs immediately (no backoff)
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
     * Start the auto-sync interval timer with backoff support.
     *
     * Backoff behaviour:
     * - 0–2 consecutive failures  → sync every cycle (normal)
     * - 3–5 consecutive failures  → sync every 2nd cycle
     * - 6–8 consecutive failures  → sync every 4th cycle
     * - 9–11 consecutive failures → sync every 8th cycle
     * - 12+ consecutive failures  → sync every 16th cycle (max)
     *
     * Example: with a 5-min interval and 6 failures, effective interval
     * becomes ~20 min. Manual sync always bypasses this backoff.
     */
    startAutoSync() {
        this.stopAutoSync();

        const minutes = this.settings.syncIntervalMinutes;
        if (minutes <= 0 || !this.settings.apiKey) return;

        const ms = minutes * 60 * 1000;
        this.backoffCycleCount = 0;

        this.autoSyncInterval = window.setInterval(() => {
            const failures = this.syncService.consecutiveFailures;

            if (failures >= 3) {
                // Calculate skip factor: 2^(tier-1), capped at 16
                const tier = Math.floor(failures / 3); // 1, 2, 3, 4+
                const skipFactor = Math.min(Math.pow(2, tier), 16);

                this.backoffCycleCount++;

                if (this.backoffCycleCount % skipFactor !== 0) {
                    console.debug(
                        `[Satset Sync] Auto-sync backed off ` +
                        `(${failures} consecutive failures, ` +
                        `syncing every ${skipFactor} cycles, ` +
                        `~${minutes * skipFactor} min effective interval)`
                    );
                    return;
                }
            } else {
                // Reset counter when healthy
                this.backoffCycleCount = 0;
            }

            void this.syncService.syncNotes();
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
