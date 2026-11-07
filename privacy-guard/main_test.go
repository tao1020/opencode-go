package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeKeyFile(t *testing.T, mode os.FileMode, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "client.key")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile respects umask; force the exact mode we want to test.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadClientKeyFileAcceptsProtectedRegularFile(t *testing.T) {
	path := writeKeyFile(t, 0o600, "  secret-client-key-0123456789\n")
	key, err := readClientKeyFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "secret-client-key-0123456789" {
		t.Fatalf("key = %q", key)
	}
}

func TestReadClientKeyFileRejectsUnsafeFiles(t *testing.T) {
	t.Run("group readable", func(t *testing.T) {
		path := writeKeyFile(t, 0o640, "key-0123456789abcdef")
		if _, err := readClientKeyFile(path); err == nil {
			t.Fatal("expected rejection of group-readable file")
		}
	})

	t.Run("world readable", func(t *testing.T) {
		path := writeKeyFile(t, 0o604, "key-0123456789abcdef")
		if _, err := readClientKeyFile(path); err == nil {
			t.Fatal("expected rejection of world-readable file")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		target := writeKeyFile(t, 0o600, "key-0123456789abcdef")
		link := filepath.Join(t.TempDir(), "link.key")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readClientKeyFile(link); err == nil {
			t.Fatal("expected rejection of symlink")
		}
	})

	t.Run("relative path", func(t *testing.T) {
		if _, err := readClientKeyFile("client.key"); err == nil {
			t.Fatal("expected rejection of relative path")
		}
	})

	t.Run("directory", func(t *testing.T) {
		if _, err := readClientKeyFile(t.TempDir()); err == nil {
			t.Fatal("expected rejection of a directory")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		path := writeKeyFile(t, 0o600, "   \n")
		if _, err := readClientKeyFile(path); err == nil {
			t.Fatal("expected rejection of an empty key file")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := readClientKeyFile(filepath.Join(t.TempDir(), "nope")); err == nil {
			t.Fatal("expected rejection of a missing file")
		}
	})
}

func TestResolveClientKeySources(t *testing.T) {
	t.Run("from environment", func(t *testing.T) {
		t.Setenv("CLIENT_API_KEY", "env-key-0123456789abcdef")
		t.Setenv("CLIENT_API_KEY_FILE", "")
		key, err := resolveClientKey()
		if err != nil || key != "env-key-0123456789abcdef" {
			t.Fatalf("key=%q err=%v", key, err)
		}
	})

	t.Run("from file", func(t *testing.T) {
		path := writeKeyFile(t, 0o600, "file-key-0123456789abcdef")
		t.Setenv("CLIENT_API_KEY", "")
		t.Setenv("CLIENT_API_KEY_FILE", path)
		key, err := resolveClientKey()
		if err != nil || key != "file-key-0123456789abcdef" {
			t.Fatalf("key=%q err=%v", key, err)
		}
	})

	t.Run("both set is rejected", func(t *testing.T) {
		path := writeKeyFile(t, 0o600, "file-key-0123456789abcdef")
		t.Setenv("CLIENT_API_KEY", "env-key-0123456789abcdef")
		t.Setenv("CLIENT_API_KEY_FILE", path)
		if _, err := resolveClientKey(); err == nil {
			t.Fatal("expected rejection when both sources are set")
		}
	})

	t.Run("neither set is rejected", func(t *testing.T) {
		t.Setenv("CLIENT_API_KEY", "")
		t.Setenv("CLIENT_API_KEY_FILE", "")
		if _, err := resolveClientKey(); err == nil {
			t.Fatal("expected rejection when no source is set")
		} else if !strings.Contains(err.Error(), "CLIENT_API_KEY") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
