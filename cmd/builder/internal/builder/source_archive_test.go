// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// tarEntry describes a single file or directory to add to a test archive.
type tarEntry struct {
	name string
	body string // empty => directory
	mode int64
}

func buildTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: e.mode}
		if e.body == "" && e.name[len(e.name)-1] == '/' {
			hdr.Typeflag = tar.TypeDir
		} else {
			hdr.Typeflag = tar.TypeReg
			hdr.Size = int64(len(e.body))
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if hdr.Typeflag == tar.TypeReg {
			_, err := tw.Write([]byte(e.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

func buildZip(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		if e.body == "" && e.name[len(e.name)-1] == '/' {
			_, err := zw.Create(e.name)
			require.NoError(t, err)
			continue
		}
		w, err := zw.Create(e.name)
		require.NoError(t, err)
		_, err = w.Write([]byte(e.body))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func goModFor(module string) string {
	return fmt.Sprintf("module %s\n\ngo 1.25.0\n", module)
}

func writeArchiveFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, data, 0o600))
	return p
}

func fileURL(p string) string {
	return (&url.URL{Scheme: "file", Path: p}).String()
}

func newArchiveConfig(t *testing.T) *Config {
	cfg, err := NewDefaultConfig()
	require.NoError(t, err)
	cfg.Logger = zap.NewNop()
	cfg.downloadModules.numRetries = 1
	cfg.downloadModules.wait = 0
	cfg.sourceArchiveCacheRoot = t.TempDir()
	cfg.ConfmapProviders = nil
	return cfg
}

func TestExtractArchive(t *testing.T) {
	const module = "go.opentelemetry.io/example"

	tests := []struct {
		name       string
		fileName   string
		entries    []tarEntry
		subdir     string
		zip        bool
		wantErr    string
		wantRelDir string // relative to extraction root, "" means root
	}{
		{
			name:     "tar.gz auto strip single dir",
			fileName: "example-v1.tar.gz",
			entries: []tarEntry{
				{name: "example-v1/", mode: 0o755},
				{name: "example-v1/go.mod", body: goModFor(module), mode: 0o644},
				{name: "example-v1/main.go", body: "package main\n", mode: 0o644},
			},
			wantRelDir: "example-v1",
		},
		{
			name:     "tar.gz with subdir",
			fileName: "example-v1.tar.gz",
			entries: []tarEntry{
				{name: "go.mod", body: goModFor("go.opentelemetry.io/example/root"), mode: 0o644},
				{name: "collector/", mode: 0o755},
				{name: "collector/go.mod", body: goModFor(module), mode: 0o644},
			},
			subdir:     "collector",
			wantRelDir: "collector",
		},
		{
			name:     "zip auto strip single dir",
			fileName: "example-v1.zip",
			zip:      true,
			entries: []tarEntry{
				{name: "example-v1/"},
				{name: "example-v1/go.mod", body: goModFor(module)},
			},
			wantRelDir: "example-v1",
		},
		{
			name:     "path traversal rejected",
			fileName: "evil.tar.gz",
			entries: []tarEntry{
				{name: "../evil.txt", body: "x", mode: 0o644},
			},
			wantErr: "escapes the destination directory",
		},
		{
			name:     "module path mismatch rejected",
			fileName: "example-v1.tar.gz",
			entries: []tarEntry{
				{name: "go.mod", body: goModFor("go.opentelemetry.io/wrong"), mode: 0o644},
			},
			wantErr: "does not match configured gomod module",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcDir := t.TempDir()
			var data []byte
			if tt.zip {
				data = buildZip(t, tt.entries)
			} else {
				data = buildTarGz(t, tt.entries)
			}
			archivePath := writeArchiveFile(t, srcDir, tt.fileName, data)

			cfg := newArchiveConfig(t)
			mod := &Module{
				GoMod: module + " v1.0.0",
				SourceArchive: &SourceArchive{
					URL:    fileURL(archivePath),
					SHA256: sha256Hex(data),
					Subdir: tt.subdir,
				},
			}

			err := cfg.resolveSourceArchive(mod)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.True(t, mod.fromSourceArchive)
			assert.True(t, filepath.IsAbs(mod.Path))
			assert.FileExists(t, filepath.Join(mod.Path, "go.mod"))
		})
	}
}

func TestResolveSourceArchiveSHA256Mismatch(t *testing.T) {
	const module = "go.opentelemetry.io/example"
	srcDir := t.TempDir()
	data := buildTarGz(t, []tarEntry{{name: "go.mod", body: goModFor(module), mode: 0o644}})
	archivePath := writeArchiveFile(t, srcDir, "example.tar.gz", data)

	cfg := newArchiveConfig(t)
	mod := &Module{
		GoMod: module + " v1.0.0",
		SourceArchive: &SourceArchive{
			URL:    fileURL(archivePath),
			SHA256: sha256Hex([]byte("not the archive")),
		},
	}

	err := cfg.resolveSourceArchive(mod)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sha256 mismatch")
}

func TestResolveSourceArchiveHTTPAndCache(t *testing.T) {
	const module = "go.opentelemetry.io/example"
	data := buildTarGz(t, []tarEntry{
		{name: "example-v1/", mode: 0o755},
		{name: "example-v1/go.mod", body: goModFor(module), mode: 0o644},
	})

	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	// The httptest server serves plain http; openURL only honors the http scheme
	// when a client is injected (scheme validation happens in Validate, not here).
	cfg := newArchiveConfig(t)
	cfg.httpClient = srv.Client()
	mod := &Module{
		GoMod: module + " v1.0.0",
		SourceArchive: &SourceArchive{
			URL:    srv.URL + "/example-v1.tar.gz",
			SHA256: sha256Hex(data),
		},
	}

	require.NoError(t, cfg.resolveSourceArchive(mod))
	assert.Equal(t, int32(1), requests.Load())
	firstPath := mod.Path

	// Second resolution should hit the cache and not the server.
	mod2 := &Module{
		GoMod: module + " v1.0.0",
		SourceArchive: &SourceArchive{
			URL:    srv.URL + "/example-v1.tar.gz",
			SHA256: sha256Hex(data),
		},
	}
	require.NoError(t, cfg.resolveSourceArchive(mod2))
	assert.Equal(t, int32(1), requests.Load(), "second resolve must not hit the server")
	assert.Equal(t, firstPath, mod2.Path)
}

func TestResolveSourceArchiveSHA256URL(t *testing.T) {
	const module = "go.opentelemetry.io/example"
	data := buildTarGz(t, []tarEntry{
		{name: "example-v1/", mode: 0o755},
		{name: "example-v1/go.mod", body: goModFor(module), mode: 0o644},
	})
	srcDir := t.TempDir()
	archivePath := writeArchiveFile(t, srcDir, "example-v1.tar.gz", data)

	sumsBody := fmt.Sprintf("%s  some-other-file.tar.gz\n%s  example-v1.tar.gz\n", sha256Hex([]byte("x")), sha256Hex(data))
	sumsPath := writeArchiveFile(t, srcDir, "SHA256SUMS", []byte(sumsBody))

	cfg := newArchiveConfig(t)
	mod := &Module{
		GoMod: module + " v1.0.0",
		SourceArchive: &SourceArchive{
			URL:       fileURL(archivePath),
			SHA256URL: fileURL(sumsPath),
		},
	}

	require.NoError(t, cfg.resolveSourceArchive(mod))
	assert.FileExists(t, filepath.Join(mod.Path, "go.mod"))
}

func TestResolveSourceArchiveSHA256URLMissingEntry(t *testing.T) {
	const module = "go.opentelemetry.io/example"
	data := buildTarGz(t, []tarEntry{{name: "go.mod", body: goModFor(module), mode: 0o644}})
	srcDir := t.TempDir()
	archivePath := writeArchiveFile(t, srcDir, "example-v1.tar.gz", data)
	sumsPath := writeArchiveFile(t, srcDir, "SHA256SUMS", []byte(sha256Hex([]byte("x"))+"  unrelated.tar.gz\n"))

	cfg := newArchiveConfig(t)
	mod := &Module{
		GoMod: module + " v1.0.0",
		SourceArchive: &SourceArchive{
			URL:       fileURL(archivePath),
			SHA256URL: fileURL(sumsPath),
		},
	}

	err := cfg.resolveSourceArchive(mod)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not contain an entry")
}

// TestGenerateWithSourceArchive exercises the full ParseModules + Generate path
// for a module backed by a file:// source archive, without compiling.
func TestGenerateWithSourceArchive(t *testing.T) {
	const module = "go.opentelemetry.io/example/extension"
	data := buildTarGz(t, []tarEntry{
		{name: "extension-v1/", mode: 0o755},
		{name: "extension-v1/go.mod", body: goModFor(module), mode: 0o644},
	})
	srcDir := t.TempDir()
	archivePath := writeArchiveFile(t, srcDir, "extension-v1.tar.gz", data)

	cfg, err := NewDefaultConfig()
	require.NoError(t, err)
	cfg.Logger = zap.NewNop()
	cfg.sourceArchiveCacheRoot = t.TempDir()
	cfg.Distribution.OutputPath = t.TempDir()
	cfg.SkipGenerate = false
	cfg.SkipGetModules = true
	cfg.SkipCompilation = true
	cfg.Extensions = []Module{
		{
			GoMod: module + " v1.0.0",
			SourceArchive: &SourceArchive{
				URL:    fileURL(archivePath),
				SHA256: sha256Hex(data),
			},
		},
	}

	require.NoError(t, cfg.Validate())
	require.NoError(t, cfg.ParseModules())

	// The resolved path must be absolute and point inside the cache.
	resolved := cfg.Extensions[0].Path
	assert.True(t, filepath.IsAbs(resolved))
	assert.FileExists(t, filepath.Join(resolved, "go.mod"))

	require.NoError(t, Generate(cfg))
	assert.FileExists(t, filepath.Join(cfg.Distribution.OutputPath, "go.mod"))
}

func TestSanitizeEntryPath(t *testing.T) {
	dst := t.TempDir()
	for _, tt := range []struct {
		name    string
		entry   string
		wantErr bool
	}{
		{"regular", "foo/bar.go", false},
		{"nested", "a/b/c.go", false},
		{"absolute", "/etc/passwd", true},
		{"traversal", "../escape", true},
		{"traversal nested", "foo/../../escape", true},
		{"empty", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sanitizeEntryPath(dst, tt.entry)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
