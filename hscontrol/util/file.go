package util

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

const (
	Base8              = 8
	Base10             = 10
	BitSize16          = 16
	BitSize32          = 32
	BitSize64          = 64
	PermissionFallback = 0o700
)

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

func GetFileMode(key string) fs.FileMode {
	modeStr := viper.GetString(key)

	mode, err := strconv.ParseUint(modeStr, Base8, BitSize64)
	if err != nil {
		return PermissionFallback
	}

	return fs.FileMode(mode)
}
