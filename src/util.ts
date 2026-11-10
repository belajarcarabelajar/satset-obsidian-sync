/**
 * Satset Sync - pure helpers.
 *
 * This file must not import obsidian, so its rules can run under bun test.
 */

/** An error that a retry cannot fix (bad settings, 4xx, unreadable response). */
export class PermanentError extends Error {
    readonly permanent = true;

    constructor(message: string) {
        super(message);
        this.name = "PermanentError";
    }
}

/** Checks the flag, not the class, so it also holds if the bundler rewrites classes. */
export function isPermanentError(error: unknown): boolean {
    return typeof error === "object" && error !== null && (error as { permanent?: unknown }).permanent === true;
}

const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i;

/** Turn a note title into a file name that every desktop OS accepts. */
export function sanitizeFilename(title: string): string {
    let name = title
        .replace(/[\\/:*?"<>|]/g, "-")
        .replace(/\s+/g, " ")
        // eslint-disable-next-line no-control-regex
        .replace(/[\x00-\x1f\x7f]/g, "")
        .trim()
        .slice(0, 100)
        // Windows drops trailing dots and spaces, which would make the name differ from the vault path.
        .replace(/[. ]+$/, "");

    if (!name) return "Untitled";

    // Windows reserves these names with or without an extension.
    const dot = name.indexOf(".");
    const base = dot === -1 ? name : name.slice(0, dot);
    if (WINDOWS_RESERVED.test(base)) {
        name = `${base}_${dot === -1 ? "" : name.slice(dot)}`;
    }
    return name;
}

/** Serialize a scalar as a one-line YAML double-quoted string (JSON strings are valid YAML). */
export function yamlQuote(value: string): string {
    return JSON.stringify(String(value).replace(/\s*[\r\n]+\s*/g, " "));
}

/** Span of the text between the first two `---` lines, or null when the file has no frontmatter. */
function frontmatterSpan(content: string): { start: number; end: number } | null {
    const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/);
    if (!match) return null;
    const start = content.indexOf("\n") + 1;
    return { start, end: start + match[1].length };
}

function escapeRegExp(text: string): string {
    return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Read `key` from the frontmatter block only; a matching line in the body is ignored. */
export function extractFrontmatterValue(content: string, key: string): string | null {
    const span = frontmatterSpan(content);
    if (!span) return null;
    const block = content.slice(span.start, span.end);
    const match = block.match(new RegExp(`^${escapeRegExp(key)}:\\s*"?([^"\\r\\n]+)"?`, "m"));
    return match ? match[1].trim() : null;
}

/** Rename a top-level frontmatter key; the body is never touched. */
export function renameFrontmatterKey(content: string, fromKey: string, toKey: string): string {
    const span = frontmatterSpan(content);
    if (!span) return content;
    const block = content
        .slice(span.start, span.end)
        .replace(new RegExp(`^${escapeRegExp(fromKey)}:`, "m"), `${toKey}:`);
    return content.slice(0, span.start) + block + content.slice(span.end);
}

/** True when `candidate` is a later instant than `reference`. An empty or unparsable reference counts as earliest. */
export function isLaterTime(candidate: string, reference: string): boolean {
    const candidateMs = Date.parse(candidate);
    if (Number.isNaN(candidateMs)) return false;
    const referenceMs = Date.parse(reference);
    if (Number.isNaN(referenceMs)) return true;
    return candidateMs > referenceMs;
}

/**
 * Cursor to save after a run: the earlier of `newest` and 1 ms before the earliest
 * note that could not be written, so the next sync fetches that note again.
 */
export function holdCursor(newest: string, earliestHeld: string | null): string {
    // Return the server string as is: a Date round trip drops sub-millisecond digits and would refetch the last note forever.
    if (earliestHeld === null) return newest;
    const newestMs = Date.parse(newest);
    if (Number.isNaN(newestMs)) return newest;
    const heldMs = Date.parse(earliestHeld) - 1;
    if (Number.isNaN(heldMs) || newestMs <= heldMs) return newest;
    return new Date(heldMs).toISOString();
}

/** Returns an error message when the API key must not be sent to this URL, else null. */
export function checkSupabaseUrl(supabaseUrl: string): string | null {
    let parsed: URL;
    try {
        parsed = new URL(supabaseUrl);
    } catch {
        return "Supabase URL is not a valid URL.";
    }
    if (parsed.protocol === "https:") return null;
    const local = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
    if (parsed.protocol === "http:" && local) return null;
    return "Supabase URL must use https.";
}
