// Copyright (c) 2026 Mounir IDRASSI
// Affiliation: AM Crypto (https://amcrypto.jp)
// License: MIT

import { describe, expect, it } from 'vitest';
import { parseAllowedEmails } from './email';

describe('parseAllowedEmails', () => {
  it('parses, normalizes, and deduplicates emails from mixed separators', () => {
    const result = parseAllowedEmails(`
      Alice@Example.com; bob@example.com,
      ALICE@example.com
      carol@example.com
      Bob@example.com
    `);

    expect(result).toEqual({
      emails: ['alice@example.com', 'bob@example.com', 'carol@example.com'],
      invalid: [],
    });
  });

  it('returns empty arrays when input has only whitespace and separators', () => {
    const result = parseAllowedEmails('  \n , ; , \t ;');

    expect(result).toEqual({
      emails: [],
      invalid: [],
    });
  });

  it('preserves first occurrence order while skipping duplicates', () => {
    const result = parseAllowedEmails('c@example.com;a@example.com;C@example.com;b@example.com;a@example.com');

    expect(result.emails).toEqual(['c@example.com', 'a@example.com', 'b@example.com']);
    expect(result.invalid).toEqual([]);
  });
});
