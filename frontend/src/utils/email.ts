export interface ParsedAllowedEmails {
  emails: string[];
  invalid: string[];
}

export function parseAllowedEmails(raw: string): ParsedAllowedEmails {
  const parts = raw
    .split(/[\n,;]/)
    .map((value) => value.trim())
    .filter(Boolean);

  const seen = new Set<string>();
  const emails: string[] = [];
  const invalid: string[] = [];

  for (const value of parts) {
    const normalized = value.toLowerCase();
    if (seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    emails.push(normalized);
  }

  // Keep frontend validation permissive and rely on backend net/mail parsing
  // as the source of truth to avoid client/server validation drift.
  return { emails, invalid };
}
