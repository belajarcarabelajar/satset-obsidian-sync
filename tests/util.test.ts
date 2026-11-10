import { describe, expect, test } from "bun:test";
import {
    PermanentError,
    checkSupabaseUrl,
    extractFrontmatterValue,
    holdCursor,
    isLaterTime,
    isPermanentError,
    renameFrontmatterKey,
    sanitizeFilename,
    yamlQuote,
} from "../src/util";

describe("sanitizeFilename", () => {
    test("suffixes a Windows reserved name", () => {
        expect(sanitizeFilename("NUL")).toBe("NUL_");
    });

    test("matches reserved names case-insensitively", () => {
        expect(sanitizeFilename("com1")).toBe("com1_");
    });

    test("suffixes the base of a reserved name that has an extension", () => {
        expect(sanitizeFilename("nul.txt")).toBe("nul_.txt");
    });

    test("leaves a title that only starts with a reserved name", () => {
        expect(sanitizeFilename("Console")).toBe("Console");
    });

    test("removes control characters", () => {
        expect(sanitizeFilename("a\u0001b")).toBe("ab");
    });

    test("turns a newline into one space", () => {
        expect(sanitizeFilename("a\nb")).toBe("a b");
    });

    test("removes a trailing dot", () => {
        expect(sanitizeFilename("x.")).toBe("x");
    });

    test("removes mixed trailing dots and spaces", () => {
        expect(sanitizeFilename("x. . ")).toBe("x");
    });

    test("falls back to Untitled when nothing is left", () => {
        expect(sanitizeFilename("...")).toBe("Untitled");
    });

    test("still replaces path separators and forbidden characters", () => {
        expect(sanitizeFilename("Meeting notes: Q3/Q4")).toBe("Meeting notes- Q3-Q4");
    });

    test("keeps a normal title unchanged", () => {
        expect(sanitizeFilename("Belanja mingguan v1.2")).toBe("Belanja mingguan v1.2");
    });

    test("does not end with a dot after the 100 character cut", () => {
        const title = "a".repeat(99) + ".b";
        expect(sanitizeFilename(title)).toBe("a".repeat(99));
    });
});

describe("yamlQuote", () => {
    test("escapes double quotes", () => {
        expect(yamlQuote('C++ "x"')).toBe('"C++ \\"x\\""');
    });

    test("parses back to the original value", () => {
        expect(JSON.parse(yamlQuote('C++ "x"'))).toBe('C++ "x"');
    });

    test("keeps a value with a newline on one line", () => {
        expect(yamlQuote("a\nb")).toBe('"a b"');
    });

    test("collapses a Windows line ending", () => {
        expect(yamlQuote("a\r\nb")).toBe('"a b"');
    });

    test("escapes a backslash", () => {
        expect(yamlQuote("a\\b")).toBe('"a\\\\b"');
    });

    test("wraps a plain value in double quotes only", () => {
        expect(yamlQuote("9f1c2d3e-0000-4000-8000-000000000001")).toBe(
            '"9f1c2d3e-0000-4000-8000-000000000001"'
        );
    });
});

describe("extractFrontmatterValue", () => {
    const file =
        '---\nsatset_id: "abc-123"\nupdated_at: "2026-01-02T03:04:05.123456+00:00"\n---\nBody text\n';

    test("reads a quoted id from the frontmatter", () => {
        expect(extractFrontmatterValue(file, "satset_id")).toBe("abc-123");
    });

    test("reads a timestamp from the frontmatter", () => {
        expect(extractFrontmatterValue(file, "updated_at")).toBe(
            "2026-01-02T03:04:05.123456+00:00"
        );
    });

    test("ignores a matching line in the body", () => {
        const conflict =
            '---\nsatset_conflict_of: "abc-123"\n---\nsatset_id: "other"\nmore\n';
        expect(extractFrontmatterValue(conflict, "satset_id")).toBeNull();
    });

    test("ignores a body line after a horizontal rule", () => {
        const text = '---\ncreated_at: "x"\n---\ntext\n\n---\nsatset_id: "other"\n---\n';
        expect(extractFrontmatterValue(text, "satset_id")).toBeNull();
    });

    test("returns null for a file without frontmatter", () => {
        expect(extractFrontmatterValue('satset_id: "other"\n', "satset_id")).toBeNull();
    });

    test("reads frontmatter with Windows line endings", () => {
        expect(
            extractFrontmatterValue('---\r\nsatset_id: "abc-123"\r\n---\r\nBody\r\n', "satset_id")
        ).toBe("abc-123");
    });
});

describe("renameFrontmatterKey", () => {
    test("renames the key in the frontmatter and leaves the body line", () => {
        const before = '---\nsatset_id: "abc"\ntags:\n  - "x"\n---\nsatset_id: "body"\n';
        const after = '---\nsatset_conflict_of: "abc"\ntags:\n  - "x"\n---\nsatset_id: "body"\n';
        expect(renameFrontmatterKey(before, "satset_id", "satset_conflict_of")).toBe(after);
    });

    test("leaves a file without frontmatter unchanged", () => {
        const text = 'satset_id: "body"\n';
        expect(renameFrontmatterKey(text, "satset_id", "satset_conflict_of")).toBe(text);
    });
});

describe("holdCursor", () => {
    test("returns the newest timestamp untouched when nothing is held", () => {
        expect(holdCursor("2026-01-02T03:04:05.123456+00:00", null)).toBe(
            "2026-01-02T03:04:05.123456+00:00"
        );
    });

    test("stops 1 ms before the earliest held note", () => {
        expect(holdCursor("2026-01-05T00:00:00.000Z", "2026-01-03T10:00:00.000Z")).toBe(
            "2026-01-03T09:59:59.999Z"
        );
    });

    test("compares mixed timestamp formats as times", () => {
        expect(holdCursor("2026-01-05T00:00:00Z", "2026-01-03T10:00:00.500000+00:00")).toBe(
            "2026-01-03T10:00:00.499Z"
        );
    });

    test("keeps the newest timestamp when it is already before the held note", () => {
        expect(holdCursor("2026-01-01T00:00:00+00:00", "2026-01-03T10:00:00.000Z")).toBe(
            "2026-01-01T00:00:00+00:00"
        );
    });

    test("keeps an empty cursor empty", () => {
        expect(holdCursor("", "2026-01-03T10:00:00.000Z")).toBe("");
    });
});

describe("isLaterTime", () => {
    test("is true for a later time in another format", () => {
        expect(isLaterTime("2026-01-03T10:00:00.500000+00:00", "2026-01-03T10:00:00.499Z")).toBe(true);
    });

    test("is false for the same instant written two ways", () => {
        expect(isLaterTime("2026-01-03T10:00:00+00:00", "2026-01-03T10:00:00.000Z")).toBe(false);
    });

    test("is false where a string comparison would say later", () => {
        expect(isLaterTime("2026-01-03T10:00:00Z", "2026-01-03T10:00:00.500Z")).toBe(false);
    });

    test("is true against an empty cursor", () => {
        expect(isLaterTime("2026-01-03T10:00:00Z", "")).toBe(true);
    });

    test("is false for an unparsable candidate", () => {
        expect(isLaterTime("not a time", "2026-01-03T10:00:00Z")).toBe(false);
    });
});

describe("checkSupabaseUrl", () => {
    test("accepts an https URL", () => {
        expect(checkSupabaseUrl("https://abc.supabase.co")).toBeNull();
    });

    test("rejects a plain http URL", () => {
        expect(checkSupabaseUrl("http://example.com")).toBe("Supabase URL must use https.");
    });

    test("accepts http on localhost", () => {
        expect(checkSupabaseUrl("http://localhost:54321")).toBeNull();
    });

    test("accepts http on 127.0.0.1", () => {
        expect(checkSupabaseUrl("http://127.0.0.1:54321")).toBeNull();
    });

    test("rejects a host that only starts with localhost", () => {
        expect(checkSupabaseUrl("http://localhost.example.com")).toBe("Supabase URL must use https.");
    });

    test("rejects text that is not a URL", () => {
        expect(checkSupabaseUrl("not a url")).toBe("Supabase URL is not a valid URL.");
    });
});

describe("PermanentError", () => {
    test("is recognised as permanent", () => {
        expect(isPermanentError(new PermanentError("HTTP 404: nope"))).toBe(true);
    });

    test("keeps its message", () => {
        expect(new PermanentError("HTTP 404: nope").message).toBe("HTTP 404: nope");
    });

    test("does not mark a plain error whose text mentions an API key", () => {
        expect(isPermanentError(new Error("API key lookup timed out"))).toBe(false);
    });
});
