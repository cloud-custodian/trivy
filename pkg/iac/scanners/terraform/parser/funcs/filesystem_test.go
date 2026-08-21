package funcs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "tilde only",
			input: "~",
			want:  home,
		},
		{
			name:  "tilde with forward slash path",
			input: "~/Documents/test.tf",
			want:  filepath.Join(home, "Documents/test.tf"),
		},
		{
			name:  "tilde with nested path",
			input: "~/a/b/c",
			want:  filepath.Join(home, "a/b/c"),
		},
		{
			name:  "absolute path unchanged",
			input: "/etc/passwd",
			want:  "/etc/passwd",
		},
		{
			name:  "relative path unchanged",
			input: "relative/path",
			want:  "relative/path",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "tilde in middle unchanged",
			input: "/foo/~/bar",
			want:  "/foo/~/bar",
		},
		{
			name:    "user-specific home dir is not supported",
			input:   "~username",
			wantErr: true,
		},
		{
			name:    "user-specific home dir with path is not supported",
			input:   "~foo/foo",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandHome(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVolumeRoot(t *testing.T) {
	// The absolute-path branch of MakeFileSetFunc uses volumeRoot both as an
	// os.DirFS root and as a filepath.Rel base, so the result has to be rooted
	// and has to be a valid base for any absolute path on the same volume.
	// Expressing it as an invariant keeps the check meaningful on every
	// platform; a bare volume name ("C:") satisfies neither.
	// Both inputs must be absolute paths, which is what the caller has already
	// established. A bare separator does not qualify on Windows, where "\\" is
	// rooted but drive-relative, so derive the second case from the first.
	nested := filepath.Join(t.TempDir(), "cfg", "files")
	paths := []string{nested, volumeRoot(nested)}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			root := volumeRoot(path)

			assert.True(t, filepath.IsAbs(root), "volumeRoot(%q) = %q is not rooted", path, root)

			rel, err := filepath.Rel(root, path)
			require.NoError(t, err, "volumeRoot(%q) = %q is not a usable Rel base", path, root)
			assert.False(t, filepath.IsAbs(rel), "%q should be relative to %q", rel, root)
		})
	}
}
