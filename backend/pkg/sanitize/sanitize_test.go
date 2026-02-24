package sanitize

import (
	"testing"
)

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal filename",
			input:    "document.pdf",
			expected: "document.pdf",
		},
		{
			name:     "filename with path traversal",
			input:    "../../../etc/passwd",
			expected: "etcpasswd",
		},
		{
			name:     "filename with null byte",
			input:    "file\x00.txt",
			expected: "file.txt",
		},
		{
			name:     "filename with newlines",
			input:    "file\nname.txt",
			expected: "filename.txt",
		},
		{
			name:     "filename with carriage return",
			input:    "file\rname.txt",
			expected: "filename.txt",
		},
		{
			name:     "filename with quotes",
			input:    `file"name.txt`,
			expected: "filename.txt",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "download",
		},
		{
			name:     "only dots",
			input:    "...",
			expected: "download",
		},
		{
			name:     "unicode characters preserved",
			input:    "日本語.txt",
			expected: "日本語.txt",
		},
		{
			name:     "filename with spaces",
			input:    "my document.pdf",
			expected: "my document.pdf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeFilename(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeFilename(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeForHeader(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal filename",
			input:    "hello-world.txt",
			expected: "hello-world.txt",
		},
		{
			name:     "filename with quotes",
			input:    `file" name.txt`,
			expected: "file name.txt",
		},
		{
			name:     "filename with newlines",
			input:    "file\nname.txt",
			expected: "filename.txt",
		},
		{
			name:     "filename with carriage return",
			input:    "file\rname.txt",
			expected: "filename.txt",
		},
		{
			name:     "filename with mixed special chars",
			input:    "file\r\n\"name\".txt",
			expected: "filename.txt",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "download",
		},
		{
			name:     "unicode characters replaced",
			input:    "日本語.txt",
			expected: "___.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeForHeader(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeForHeader(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeFilename_LengthLimit(t *testing.T) {
	// Create a very long filename
	longName := ""
	for i := 0; i < 300; i++ {
		longName += "a"
	}

	result := SanitizeFilename(longName)
	if len(result) > 200 {
		t.Errorf("Expected filename length <= 200, got %d", len(result))
	}
}
