export interface ParsedAllowedEmails {
  emails: string[];
  invalid: string[];
}

const allowedEmailRegex = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;

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
    if (!allowedEmailRegex.test(normalized)) {
      invalid.push(value);
      continue;
    }
    if (seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    emails.push(normalized);
  }

  return { emails, invalid };
}
