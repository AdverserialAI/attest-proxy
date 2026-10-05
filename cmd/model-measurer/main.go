// model-measurer deterministically binds a read-only model artifact to a
// sha256 tree manifest. It deliberately has no network client, credentials,
// or inference endpoint: its only inputs are MODEL_ROOT and MODEL_ID, and its
// only output is MODEL_MANIFEST_FILE on a dedicated evidence volume.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type manifest struct {
	Version    int     `json:"version"`
	Algorithm  string  `json:"algorithm"`
	ModelID    string  `json:"model_id"`
	FileCount  int     `json:"file_count"`
	TotalBytes int64   `json:"total_bytes"`
	Digest     string  `json:"digest"`
	Files      []entry `json:"files"`
}

func env(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func measure(root, modelID string) (manifest, error) {
	info, err := os.Stat(root)
	if err != nil {
		return manifest{}, err
	}
	if !info.IsDir() {
		return manifest{}, errors.New("MODEL_ROOT must be a directory")
	}
	var files []entry
	var total int64
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "../") || rel == ".." {
			return errors.New("model path escapes root")
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symlink not allowed in model artifact: %s", rel)
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("non-regular model artifact entry: %s", rel)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		sum, err := hashFile(path)
		if err != nil {
			return err
		}
		files = append(files, entry{Path: rel, Size: info.Size(), SHA256: sum})
		total += info.Size()
		return nil
	})
	if err != nil {
		return manifest{}, err
	}
	if len(files) == 0 {
		return manifest{}, errors.New("model artifact has no regular files")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	tree := sha256.New()
	for _, file := range files {
		// A line format with an explicit NUL separator prevents ambiguous
		// filename/size concatenation while remaining easy to reproduce.
		fmt.Fprintf(tree, "%s\x00%d\x00%s\n", file.Path, file.Size, file.SHA256)
	}
	return manifest{Version: 1, Algorithm: "sha256-tree-v1", ModelID: modelID, FileCount: len(files), TotalBytes: total, Digest: "sha256:" + hex.EncodeToString(tree.Sum(nil)), Files: files}, nil
}

func writeAtomic(path string, value manifest) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".model-manifest-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(encoded, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func main() {
	root, err := env("MODEL_ROOT")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	out, err := env("MODEL_MANIFEST_FILE")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	modelID, err := env("MODEL_ID")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	started := time.Now()
	result, err := measure(root, modelID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "measure model:", err)
		os.Exit(1)
	}
	if err := writeAtomic(out, result); err != nil {
		fmt.Fprintln(os.Stderr, "write manifest:", err)
		os.Exit(1)
	}
	fmt.Printf("model artifact measured: files=%d bytes=%d digest=%s elapsed=%s\n", result.FileCount, result.TotalBytes, result.Digest, time.Since(started).Round(time.Millisecond))
}
