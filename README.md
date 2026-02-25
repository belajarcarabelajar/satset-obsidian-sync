# Satset Sync for Obsidian

Synchronize your [Satset Note-taking](https://satset-notetaking.pages.dev) notes directly into your Obsidian vault — including **encrypted notes** with automatic decryption.

## ✨ Features

- **One-way sync** (Satset → Obsidian) — your notes in Obsidian are read-only copies
- **End-to-end encryption support** — encrypted notes are decrypted locally using your credentials
- **Automatic sync** — configurable interval (default: every 5 minutes)
- **Manual sync** — via ribbon icon or command palette
- **Frontmatter metadata** — each note includes `satset_id`, `created_at`, `updated_at`, tags, pinned/archived status
- **Force resync** — button to re-download all notes from scratch
- **Deduplication** — existing notes are updated in-place, never duplicated

## 📦 Installation

### From Community Plugins (Recommended)

1. Open **Settings** → **Community Plugins** → **Browse**
2. Search for **"Satset Sync"**
3. Click **Install**, then **Enable**

### Manual Installation

1. Download the latest release from [GitHub Releases](https://github.com/belajarcarabelajar/satset-obsidian-sync/releases)
2. Create the plugin folder (if it doesn't exist):  
   `<your-vault>/.obsidian/plugins/satset-sync/`
3. Copy these files into the folder:
   - `main.js`
   - `manifest.json`
   - `styles.css`
4. Restart Obsidian
5. Enable the plugin in **Settings** → **Community Plugins**
6. Go to **Settings** → **Satset Sync** and enter your **API Key** (see [Getting Started](#-getting-started))
7. Click **Connect** and verify the status shows "Connected"

> [!NOTE]
> The plugin stores its configuration in `data.json` inside the plugin folder.  
> If you update the plugin files manually, the old `data.json` is preserved — which means **previously saved settings (including API keys) will persist**.  
> If you experience authentication errors (e.g., 401) after an update, check that the `apiKey` value in `data.json` is correct, or delete `data.json` to reset all settings.

## 🚀 Getting Started

### 1. Create a Satset Account

If you don't have one, sign up at [satset-notetaking.pages.dev](https://satset-notetaking.pages.dev).

### 2. Get Your API Key

1. Log in to [Satset Note-taking](https://satset-notetaking.pages.dev)
2. Go to **Settings** → **API Keys**
3. Generate a new API key and copy it

> **Important**: Keep your API key secure. Do not share it publicly.

### 3. Connect in Obsidian

1. Open **Settings** → **Satset Sync**
2. Paste your **API Key** into the API Key field
3. Click **Connect**
4. You should see **✅ Connected as <your-email@example.com>**

> **Note**: Your API key is stored locally in the plugin's `data.json` file. It is never sent to any third-party service.

### 4. Sync Your Notes

- Click the 🔄 icon in the left ribbon, or
- Use the command palette: `Satset Sync: Sync notes from Satset`

Your notes will appear in the `Satset/` folder (configurable in settings).

## ⚙️ Settings

| Setting | Description | Default |
| :--- | :--- | :--- |
| **API Key** | Your Satset API key for authentication | — |
| **Sync Folder** | Vault folder for synced notes | `Satset` |
| **Auto-sync Interval** | Minutes between auto-syncs (0 = manual only) | `5` |
| **Include Archived** | Also sync archived notes | `false` |
| **Force Full Resync** | Clear sync history and re-download everything | — |

## 🔐 Encryption & Privacy

> [!WARNING]
> **Important Security Note:**  
> When you sync notes to Obsidian using this plugin, they are **decrypted** and stored as standard Markdown (`.md`) files in your vault.  
>
> **These files are NOT encrypted at rest by the plugin.**  
>
> "End-to-end encryption" in Satset applies to **transmission** (HTTPS) and **server-side storage** (AES-GCM 256-bit). Once notes reach your device, the plugin decrypts them and writes plaintext Markdown files.  
>
> If you require security for your local notes, you **must** use full-disk encryption (e.g., BitLocker, FileVault, LUKS) or an encrypted container (e.g., VeraCrypt) for your Obsidian vault.  
>
> For a detailed explanation, see [Security Overview](docs/SECURITY_OVERVIEW.md).

- All notes in Satset are encrypted using **AES-GCM 256-bit** with **PBKDF2** key derivation
- The decryption key is derived locally from your credentials — it never leaves your device
- The plugin communicates directly with Supabase (the backend) using HTTPS
- No third-party servers or analytics are involved

## 🏗 How It Works

```text
Satset Web App → Supabase (encrypted) → Obsidian Plugin (decrypt locally) → Markdown files
```

1. Plugin authenticates using your API key via a Supabase Edge Function
2. Fetches notes updated since the last sync
3. Encrypted notes are decrypted locally using your encryption key
4. Notes are written as `.md` files with YAML frontmatter

## 🔧 Troubleshooting

### 401 Unauthorized Error on Connect

**Cause**: The API key stored in `data.json` is invalid or outdated.

**Fix**:

1. Close Obsidian completely (check Task Manager / System Tray)
2. Navigate to `<your-vault>/.obsidian/plugins/satset-sync/`
3. Open `data.json` in a text editor
4. Verify the `apiKey` field contains your current, valid API key
5. Save the file, then reopen Obsidian
6. Go to **Settings** → **Satset Sync** → **Connect**

Alternatively, delete `data.json` entirely to reset all plugin settings, then reconfigure.

### "Decrypt failed" on Some Notes

A small number of notes may have been created with a different encryption format. This is rare and won't affect other notes. These notes will be skipped during sync.

### Sync Completes But Notes Are Missing

- Check if the notes are archived — enable **Include Archived** in settings
- Try **Force Full Resync** to re-download all notes from scratch
- Verify you are connected with the correct account

### Plugin Not Appearing After Manual Install

- Ensure the folder is named exactly `satset-sync` (not `satset-obsidian-sync`)
- Verify all three files (`main.js`, `manifest.json`, `styles.css`) are present
- Restart Obsidian completely and enable the plugin in **Community Plugins**

## ❓ FAQ

**Q: Will editing/deleting notes in Obsidian affect my Satset data?**  
A: **No.** Sync is one-way (Satset → Obsidian). Your original notes are always safe.

**Q: What happens if I sync again?**  
A: Only notes updated since the last sync are downloaded. Existing files with matching titles are updated in-place.

**Q: Are my notes encrypted in Obsidian?**  
A: **No.** Notes are decrypted by the plugin and stored as plaintext Markdown files. Use full-disk encryption on your device for local security. See [Security Overview](docs/SECURITY_OVERVIEW.md).

**Q: What is stored in `data.json`?**  
A: Your plugin configuration including API key, sync folder, sync interval, last sync timestamp, and authentication tokens. This file persists across plugin updates.

## 🛠 Development

```bash
# Install dependencies
npm install

# Build the plugin
npm run build

# Watch for changes during development
npm run dev
```

## 📄 License

[MIT](LICENSE)

## 🔗 Links

- [Satset Note-taking](https://satset-notetaking.pages.dev) — The web app
- [GitHub Repository](https://github.com/belajarcarabelajar/satset-obsidian-sync) — Source code & issues
- [Security Overview](docs/SECURITY_OVERVIEW.md) — Detailed security documentation
