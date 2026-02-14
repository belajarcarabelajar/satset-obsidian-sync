# Security Overview — Satset Sync for Obsidian

This document describes the security model of the Satset Sync plugin for Obsidian, including encryption boundaries, local storage considerations, and recommendations for securing your data.

## Encryption Model

Satset uses a layered encryption approach:

```text
┌─────────────────────────────────────────────────────────────────────┐
│  Satset Web App                                                     │
│  Notes encrypted with AES-GCM 256-bit (PBKDF2 key derivation)     │
└──────────────────────┬──────────────────────────────────────────────┘
                       │ HTTPS (TLS 1.2+)
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Supabase Server                                                    │
│  Notes stored as encrypted blobs — server cannot read content      │
└──────────────────────┬──────────────────────────────────────────────┘
                       │ HTTPS (TLS 1.2+)
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Obsidian Plugin (your device)                                      │
│  Decrypts notes locally → writes plaintext .md files to vault      │
└─────────────────────────────────────────────────────────────────────┘
```

## What "End-to-End Encryption" Covers

| Segment | Encrypted? | Details |
| :--- | :--- | :--- |
| Satset Web App → Supabase | ✅ Yes | AES-GCM 256-bit + HTTPS |
| Stored on Supabase server | ✅ Yes | Encrypted blobs; server has no decryption key |
| Supabase → Obsidian Plugin | ✅ Yes | HTTPS (TLS 1.2+); payload still encrypted |
| **Inside Obsidian vault (local)** | **❌ No** | **Plugin decrypts and writes plaintext Markdown** |

> [!IMPORTANT]
> The "end" in end-to-end encryption refers to the Satset application endpoints (web app and plugin). Once the plugin decrypts your notes, they exist as **standard plaintext files** on your local filesystem. The plugin does **not** re-encrypt them at rest.

## Local Storage Security

### What Is Stored Locally

The plugin creates and manages these files in your vault:

- **Synced notes** (`<vault>/Satset/*.md`) — plaintext Markdown files with YAML frontmatter
- **Plugin settings** (`<vault>/.obsidian/plugins/satset-sync/data.json`) — contains your API key, sync configuration, and authentication tokens

### Risks

- Anyone with access to your filesystem can read your synced notes
- The `data.json` file contains your API key in plaintext
- Backups of your vault (e.g., cloud sync, Time Machine) will include plaintext notes

### Recommendations

1. **Enable full-disk encryption** on all devices where you use Obsidian:
   - **Windows**: BitLocker
   - **macOS**: FileVault
   - **Linux**: LUKS / dm-crypt
2. **Use an encrypted container** (e.g., VeraCrypt) if full-disk encryption is not available
3. **Be cautious with cloud backup services** — plaintext notes will be synced to cloud providers (Dropbox, Google Drive, iCloud, OneDrive) unless you exclude the vault folder
4. **Lock your device** when unattended — disk encryption only protects when the device is powered off or locked
5. **Rotate your API key** periodically via the Satset web app settings

## Authentication Flow

```text
1. User enters API Key in plugin settings
2. Plugin sends API Key to Supabase Edge Function (validate-api-key)
3. Edge Function verifies key against hashed keys in database
4. On success: returns user profile + Supabase access/refresh tokens
5. Plugin stores tokens locally for subsequent sync requests
6. Tokens are used to fetch encrypted notes from Supabase
7. Notes are decrypted locally using derived encryption key
```

- The API key is transmitted over HTTPS only
- The Edge Function validates against **hashed** keys (bcrypt) — raw keys are not stored server-side
- Access tokens expire and are refreshed automatically

## Network Security

- All communication uses **HTTPS (TLS 1.2+)**
- The plugin communicates **only** with Supabase (`*.supabase.co`) — no third-party servers
- No analytics, telemetry, or tracking is included in the plugin
- API keys are sent via the `x-api-key` HTTP header, not in URL parameters

## Threat Model

| Threat | Mitigated? | How |
| :--- | :--- | :--- |
| Server breach (Supabase) | ✅ | Notes stored as encrypted blobs |
| Network interception (MITM) | ✅ | HTTPS/TLS encryption |
| Local device theft (powered off) | ⚠️ Partial | Only if full-disk encryption is enabled |
| Local device access (unlocked) | ❌ | Notes are plaintext; no additional protection |
| Cloud backup exposure | ❌ | Plaintext notes synced to backup providers |
| API key leakage | ⚠️ Partial | Key stored in plaintext in `data.json` |

## Responsible Disclosure

If you discover a security vulnerability in Satset Sync, please report it responsibly by opening a private issue on the [GitHub repository](https://github.com/belajarcarabelajar/satset-obsidian-sync) or contacting the maintainer directly.

## Related Documentation

- [README — Encryption & Privacy](../README.md#-encryption--privacy)
- [README — Troubleshooting](../README.md#-troubleshooting)
