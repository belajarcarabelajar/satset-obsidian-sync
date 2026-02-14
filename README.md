# Satset Sync for Obsidian

Synchronize your [Satset Note-taking](https://satset-notetaking.lovable.app) notes directly into your Obsidian vault — including **encrypted notes** with automatic decryption.

## ✨ Features

- **One-way sync** (Satset → Obsidian) — your notes in Obsidian are read-only copies
- **End-to-end encryption support** — encrypted notes are decrypted locally using your credentials (**stored as plaintext in Obsidian**)
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
2. Extract `main.js`, `manifest.json`, and `styles.css` into:  
   `<your-vault>/.obsidian/plugins/satset-sync/`
3. Restart Obsidian
4. Enable the plugin in **Settings** → **Community Plugins**

## 🚀 Getting Started

### 1. Create a Satset Account

If you don't have one, sign up at [satset-notetaking.lovable.app](https://satset-notetaking.lovable.app).

### 2. Login in Obsidian

1. Open **Settings** → **Satset Sync**
2. Enter your **email** and **password**
3. Click **Login**

> **Note**: Your password is only used for authentication and is never stored. Only the session token is saved locally.

### 3. Sync Your Notes

- Click the 🔄 icon in the left ribbon, or
- Use the command palette: `Satset Sync: Sync notes from Satset`

Your notes will appear in the `Satset/` folder (configurable in settings).

## ⚙️ Settings

| Setting | Description | Default |
| :--- | :--- | :--- |
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
> If you require security for your local notes, you **must** use full-disk encryption (e.g., BitLocker, FileVault, LUKS) or an encrypted container (e.g., VeraCrypt) for your Obsidian vault.

- All notes in Satset are encrypted using **AES-GCM 256-bit** with **PBKDF2** key derivation
- The decryption key is derived locally from your credentials — it never leaves your device
- The plugin communicates directly with Supabase (the backend) using HTTPS
- No third-party servers or analytics are involved

## 🏗 How It Works

```text
Satset Web App → Supabase (encrypted) → Obsidian Plugin (decrypt locally) → Markdown files
```

1. Plugin authenticates with your Satset credentials
2. Fetches notes updated since the last sync
3. Encrypted notes are decrypted locally using your encryption key
4. Notes are written as `.md` files with YAML frontmatter

## ❓ FAQ

**Q: Will editing/deleting notes in Obsidian affect my Satset data?**  
A: **No.** Sync is one-way (Satset → Obsidian). Your original notes are always safe.

**Q: What happens if I sync again?**  
A: Only notes updated since the last sync are downloaded. Existing files with matching titles are updated in-place.

**Q: Some notes show "decrypt failed" — what does that mean?**  
A: A small number of notes may have been created with a different encryption format. This is rare and won't affect other notes.

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

- [Satset Note-taking](https://satset-notetaking.lovable.app) — The web app
- [GitHub Repository](https://github.com/belajarcarabelajar/satset-obsidian-sync) — Source code & issues
