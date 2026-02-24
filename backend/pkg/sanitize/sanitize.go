package sanitize

import (
	"strings"
	"unicode"
)

// SanitizeFilename removes potentially dangerous characters from a filename
// to prevent header injection and XSS attacks
func SanitizeFilename(filename string) string {
	// Remove any null bytes
	filename = strings.ReplaceAll(filename, "\x00", "")

	// Remove newlines and carriage returns (header injection prevention)
	filename = strings.ReplaceAll(filename, "\n", "")
	filename = strings.ReplaceAll(filename, "\r", "")

	// Remove quotes (prevents breaking out of Content-Disposition)
	filename = strings.ReplaceAll(filename, `"`, "")
	filename = strings.ReplaceAll(filename, `'`, "")

	// Remove backslashes (Windows path separator)
	filename = strings.ReplaceAll(filename, `\`, "")

	// Remove forward slashes (Unix path separator)
	filename = strings.ReplaceAll(filename, "/", "")

	// Remove control characters
	result := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, filename)

	// Trim spaces and dots from ends
	result = strings.TrimSpace(result)
	result = strings.Trim(result, ".")

	// If the result is empty, provide a default
	if result == "" {
		return "download"
	}

	// Limit length to prevent overly long headers
	if len(result) > 200 {
		result = result[:200]
	}

	return result
}

// SanitizeForHeader sanitizes a filename specifically for use in HTTP headers
// Uses ASCII-only fallback for maximum compatibility
func SanitizeForHeader(filename string) string {
	// First apply general sanitization
	safe := SanitizeFilename(filename)

	// For Content-Disposition, we want ASCII-only
	// Replace non-ASCII with underscore
	result := strings.Map(func(r rune) rune {
		if r > 127 {
			return '_'
		}
		return r
	}, safe)

	return result
}
