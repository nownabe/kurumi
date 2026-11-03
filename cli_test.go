package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runCLI(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(t.Context(), args, strings.NewReader(stdin), &o, &e)
	return code, o.String(), e.String()
}

func TestKeygen(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "id")
	code, _, stderr := runCLI(t, "", "keygen", "-o", keyFile)
	if code != exitOK {
		t.Fatal(stderr)
	}
	if fi, _ := os.Stat(keyFile); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	if code, out, _ := runCLI(t, "", "public-key", "--identity", keyFile); code != exitOK || !strings.Contains(stderr, out) {
		t.Errorf("public-key %q does not match keygen's %q", out, stderr)
	}
	if code, _, _ := runCLI(t, "", "keygen", "-o", keyFile); code != exitFailure {
		t.Error("existing key file overwritten")
	}
	target := filepath.Join(dir, "target")
	if os.Symlink(target, filepath.Join(dir, "link")) == nil {
		if code, _, _ := runCLI(t, "", "keygen", "-o", filepath.Join(dir, "link")); code != exitFailure {
			t.Error("followed a symlink")
		}
		if _, err := os.Stat(target); err == nil {
			t.Error("created the symlink target")
		}
	}
	code, priv, stderr := runCLI(t, "", "keygen")
	if code != exitOK {
		t.Fatal(stderr)
	}
	if _, out, _ := runCLI(t, priv, "public-key", "--identity", "-"); !strings.Contains(stderr, out) || out == "" {
		t.Errorf("public-key from stdin %q, keygen printed %q", out, stderr)
	}
	if runtime.GOOS == "linux" {
		tty, err := os.OpenFile("/dev/zero", os.O_WRONLY, 0) // a character device standing in for a terminal
		if err != nil {
			t.Fatal(err)
		}
		defer tty.Close()
		var e bytes.Buffer
		if code := run(t.Context(), []string{"keygen"}, nil, tty, &e); code != exitFailure || !strings.Contains(e.String(), "pipe") {
			t.Errorf("keygen wrote to a terminal: %d %s", code, &e)
		}
		null, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		defer null.Close()
		if code := run(t.Context(), []string{"keygen"}, nil, null, io.Discard); code != exitOK {
			t.Error("keygen refused /dev/null")
		}
	}
}

func TestIdentityInput(t *testing.T) {
	k := testKey(t)
	line := encodeKey(privateKeyPrefix, k.Bytes()) + "\n"
	pub := encodeKey(publicKeyPrefix, k.PublicKey().Bytes()) + "\n"
	if code, out, _ := runCLI(t, line, "public-key", "--identity", "-"); code != exitOK || out != pub {
		t.Errorf("stdin identity: %d %q", code, out)
	}
	if code, _, _ := runCLI(t, line+strings.Repeat("\n", maxKeyFileSize), "public-key", "--identity", "-"); code != exitFailure {
		t.Error("oversized identity accepted")
	}
	for _, cmd := range []string{"decrypt", "verify"} {
		if code, _, stderr := runCLI(t, line, cmd, "--identity", "-"); code != exitFailure || !strings.Contains(stderr, "required") {
			t.Errorf("%s with --identity - and no file: %d", cmd, code)
		}
	}
	if runtime.GOOS == "linux" {
		r, w, _ := os.Pipe()
		go func() { w.WriteString(line); w.Close() }()
		defer r.Close()
		if code, out, stderr := runCLI(t, "", "public-key", "--identity", fmt.Sprintf("/dev/fd/%d", r.Fd())); code != exitOK || out != pub {
			t.Errorf("/dev/fd identity: %d %s", code, stderr)
		}
	}
}
