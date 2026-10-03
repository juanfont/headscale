package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/viper"
	"github.com/tailscale/hujson"
	"gopkg.in/yaml.v3"
)

const (
	Base8              = 8
	Base10             = 10
	BitSize16          = 16
	BitSize32          = 32
	BitSize64          = 64
	PermissionFallback = 0o700
)

// ErrDirectoryPermission is returned when creating a directory fails due to permission issues.
var ErrDirectoryPermission = errors.New("creating directory failed with permission error")

// ErrInvalidFileMode is returned by [ParseFileMode].
var ErrInvalidFileMode = errors.New("not an octal file mode between 0 and 0777")

// ErrUnknownFileFormat is returned for a file whose extension names no format
// [UnmarshalByExt] reads.
var ErrUnknownFileFormat = errors.New("unknown file format, want .json, .hujson, .yaml or .yml")

// UnmarshalByExt decodes data into a T in the format name's extension picks:
// .json, .hujson (JSON with comments and trailing commas), or .yaml/.yml.
// The extension decides, not the content: YAML parses JSON syntax, so sniffing
// cannot tell the two apart. YAML keys are the lowercased Go field names.
func UnmarshalByExt[T any](name string, data []byte) (T, error) {
	var (
		v   T
		err error
	)

	switch ext := strings.ToLower(filepath.Ext(name)); ext {
	case ".json":
		err = json.Unmarshal(data, &v)
	case ".hujson":
		data, err = hujson.Standardize(data)
		if err == nil {
			err = json.Unmarshal(data, &v)
		}
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &v)
	default:
		return v, fmt.Errorf("%s: %w", name, ErrUnknownFileFormat)
	}

	if err != nil {
		return v, fmt.Errorf("decoding %s: %w", name, err)
	}

	return v, nil
}

// ReadFileByExt reads the file at path and decodes it with [UnmarshalByExt].
func ReadFileByExt[T any](path string) (T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		var zero T

		return zero, err
	}

	return UnmarshalByExt[T](path, data)
}

func AbsolutePathFromConfigPath(path string) string {
	// If a relative path is provided, prefix it with the directory where
	// the config file was found.
	if (path != "") && !strings.HasPrefix(path, string(os.PathSeparator)) {
		dir, _ := filepath.Split(viper.ConfigFileUsed())
		if dir != "" {
			path = filepath.Join(dir, path)
		}
	}

	return path
}

// ParseFileMode parses an octal permission such as "0770", "770" or "0o770".
// Bits above [fs.ModePerm] are rejected: [os.Chmod] drops them, so "17777"
// would silently become 0777.
func ParseFileMode(s string) (fs.FileMode, error) {
	mode, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0o"), Base8, BitSize64)
	if err != nil || mode > uint64(fs.ModePerm) {
		return 0, fmt.Errorf("%w: %q", ErrInvalidFileMode, s)
	}

	return fs.FileMode(mode), nil
}

func EnsureDir(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) { //nolint:noinlineerr
		err := os.MkdirAll(dir, PermissionFallback)
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				return fmt.Errorf("%w: %s", ErrDirectoryPermission, dir)
			}

			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	return nil
}
