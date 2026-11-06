// Package tree owns the digest rules that let a baseline and a verification
// agree on the exact source tree they observed. A digest covers every regular
// file's slash-relative path, content digest, and permission bits, in lexical
// order, plus each symlink's target. .pocgate (the pipeline's own state) and
// .git (history) are skipped: they are not part of what is built or probed.
package tree

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// SkipDir reports whether a directory holds pipeline or version-control state
// that both the digest and the scratch copy leave out.
func SkipDir(name string) bool { return name == ".pocgate" || name == ".git" }

// SHA256 is a deterministic digest of root. Two trees with the same files,
// contents, and modes produce the same digest regardless of where they live.
func SHA256(root string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if rel != "." && SkipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "%s\x00link\x00%s\n", filepath.ToSlash(rel), target)
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%s\x00%s\x00%o\n", filepath.ToSlash(rel), sha256Hex(data), info.Mode().Perm())
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
