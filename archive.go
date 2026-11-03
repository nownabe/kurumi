package main

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"time"
)

// writeArchive writes paths as a PAX tar stream to w and returns the number of
// regular files. skip lists files (by identity) that must not be archived.
func writeArchive(w io.Writer, paths, exclude []string, skip []os.FileInfo) (int64, error) {
	tw := tar.NewWriter(w)
	var files int64
	for _, root := range paths {
		root = filepath.Clean(root)
		fi, err := os.Lstat(root)
		if err != nil {
			return files, err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return files, fmt.Errorf("%s is a symlink; configure the real path", root)
		}
		if !fi.IsDir() {
			return files, fmt.Errorf("%s is not a directory", root)
		}
		base := filepath.Base(root)
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			name := path.Join(base, filepath.ToSlash(rel))
			for _, x := range exclude {
				if ok, _ := path.Match(x, name); ok {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			for _, s := range skip {
				if os.SameFile(info, s) {
					return nil
				}
			}
			n, err := addEntry(tw, p, name, info)
			files += n
			return err
		})
		if err != nil {
			return files, err
		}
	}
	return files, tw.Close()
}

func addEntry(tw *tar.Writer, p, name string, info os.FileInfo) (int64, error) {
	var link string
	switch m := info.Mode(); {
	case m.IsRegular(), m.IsDir():
	case m&fs.ModeSymlink != 0:
		var err error
		if link, err = os.Readlink(p); err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("%s: unsupported file type %s", p, m.Type())
	}
	if !info.Mode().IsRegular() {
		return 0, tw.WriteHeader(header(name, info, link))
	}
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Size() != info.Size() {
		return 0, fmt.Errorf("%s: changed while being archived", p)
	}
	if err := tw.WriteHeader(header(name, opened, "")); err != nil {
		return 0, err
	}
	if _, err := io.CopyN(tw, f, opened.Size()); err != nil {
		return 0, fmt.Errorf("%s: %w (did it shrink while being read?)", p, err)
	}
	if n, _ := f.Read(make([]byte, 1)); n > 0 {
		return 0, fmt.Errorf("%s: grew while being read", p)
	}
	if after, err := f.Stat(); err != nil || after.Size() != opened.Size() {
		return 0, errors.Join(fmt.Errorf("%s: changed size while being read", p), err)
	}
	return 1, nil
}

func header(name string, info os.FileInfo, link string) *tar.Header {
	h, _ := tar.FileInfoHeader(info, link)
	h.Name = name
	if info.IsDir() {
		h.Name += "/"
	}
	h.Uname, h.Gname = "", ""
	h.AccessTime, h.ChangeTime = time.Time{}, time.Time{}
	h.Format = tar.FormatPAX
	return h
}
