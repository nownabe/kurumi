package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func tarNames(t *testing.T, b []byte) map[string]*tar.Header {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(b))
	m := map[string]*tar.Header{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return m
		}
		if err != nil {
			t.Fatal(err)
		}
		m[h.Name] = h
	}
}

// isolateTemp gives os.TempDir a fresh directory so leftovers can be detected.
func isolateTemp(t *testing.T) {
	dir := t.TempDir()
	for _, v := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(v, dir)
	}
}

func TestArchive(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	for _, d := range []string{"keep", "tmp", "tmp/deep"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	os.WriteFile(filepath.Join(root, "keep", "a"), []byte("a"), 0o640)
	os.WriteFile(filepath.Join(root, "keep", "skip.log"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(root, "tmp", "deep", "b"), []byte("b"), 0o644)
	outside := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(outside, []byte("secret"), 0o644)
	if err := os.Symlink(outside, filepath.Join(root, "keep", "link")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	var b bytes.Buffer
	files, err := writeArchive(&b, []string{root}, []string{"data/tmp", "data/*/*.log"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := tarNames(t, b.Bytes())
	want := []string{"data/", "data/keep/", "data/keep/a", "data/keep/link"}
	if names := slices.Sorted(func(yield func(string) bool) {
		for n := range got {
			yield(n)
		}
	}); !slices.Equal(names, want) || files != 1 {
		t.Fatalf("archived %v (%d files), want %v", names, files, want)
	}
	link := got["data/keep/link"]
	if link.Typeflag != tar.TypeSymlink || link.Linkname != outside || link.Size != 0 {
		t.Fatalf("symlink stored as %+v", link)
	}
	if h := got["data/keep/a"]; h.Uname != "" || h.Gname != "" || (runtime.GOOS != "windows" && h.Mode&0o777 != 0o640) {
		t.Fatalf("metadata %+v", h)
	}
}

func TestArchiveRejects(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "data")
	os.Mkdir(root, 0o755)
	if runtime.GOOS != "windows" {
		l, err := net.Listen("unix", filepath.Join(root, "sock"))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		if _, err := writeArchive(io.Discard, []string{root}, nil, nil); err == nil {
			t.Error("socket archived")
		}
		if _, err := writeArchive(io.Discard, []string{root}, []string{"data/sock"}, nil); err != nil {
			t.Errorf("excluded socket: %v", err)
		}
	}
	link := filepath.Join(dir, "link")
	if os.Symlink(root, link) == nil {
		if _, err := writeArchive(io.Discard, []string{link}, nil, nil); err == nil {
			t.Error("symlinked path argument accepted")
		}
	}
	f := filepath.Join(root, "grows")
	os.WriteFile(f, []byte("a"), 0o644)
	info, _ := os.Lstat(f)
	os.WriteFile(f, []byte("abc"), 0o644)
	if _, err := addEntry(tar.NewWriter(io.Discard), f, "data/grows", info); err == nil {
		t.Error("file that changed size accepted")
	}
}

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

func TestBackupNames(t *testing.T) {
	if n := newBackupName(); !validBackupName(n) {
		t.Fatalf("generated invalid name %s", n)
	}
	for _, bad := range []string{
		"20261301T000000Z-0123abcd.kurumi", "20260230T000000Z-0123abcd.kurumi", "20260101T250000Z-0123abcd.kurumi",
		"20260101T000000Z-0123ABCD.kurumi", "../20260101T000000Z-0123abcd.kurumi", "app/20260101T000000Z-0123abcd.kurumi",
		"20260101T000000Z-0123abcd.kurumi.tmp", "",
	} {
		if validBackupName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

type localSetup struct {
	dir, cfg, key, data, out string
}

func newLocal(t *testing.T, outInside bool) localSetup {
	t.Helper()
	dir := t.TempDir()
	s := localSetup{dir: dir, cfg: filepath.Join(dir, "config.json"), key: filepath.Join(dir, "id"), data: filepath.Join(dir, "data")}
	s.out = filepath.Join(dir, "out")
	if outInside {
		s.out = filepath.Join(s.data, "out")
	}
	os.MkdirAll(s.data, 0o755)
	os.MkdirAll(s.out, 0o755)
	os.WriteFile(filepath.Join(s.data, "file"), []byte("content"), 0o644)
	k := testKey(t)
	os.WriteFile(s.key, []byte(encodeKey(privateKeyPrefix, k.Bytes())), 0o600)
	os.WriteFile(s.cfg, fmt.Appendf(nil, `{"version":1,"targets":{"app":{"output_dir":%q,"paths":[%q],"recipient":%q}}}`,
		s.out, s.data, encodeKey(publicKeyPrefix, k.PublicKey().Bytes())), 0o644)
	return s
}

type pushLine struct {
	Target, Object string
	DryRun         bool `json:"dry_run"`
	Bytes, Files   int64
}

func (s localSetup) push(t *testing.T, args ...string) pushLine {
	t.Helper()
	code, out, stderr := runCLI(t, "", append([]string{"push", "--config", s.cfg, "app"}, args...)...)
	if code != exitOK {
		t.Fatalf("push: %d %s", code, stderr)
	}
	var l pushLine
	if err := json.Unmarshal([]byte(out), &l); err != nil || strings.Count(out, "\n") != 1 {
		t.Fatalf("success line %q: %v", out, err)
	}
	return l
}

func TestLocalPushRestore(t *testing.T) {
	s := newLocal(t, true)
	dry := s.push(t, "--dry-run")
	if !dry.DryRun || dry.Object != "" || dry.Bytes == 0 {
		t.Fatalf("dry run line %+v", dry)
	}
	if entries, _ := os.ReadDir(s.out); len(entries) != 0 {
		t.Fatal("dry run wrote files")
	}
	first := s.push(t)
	second := s.push(t)
	if first.Files != 1 || filepath.Dir(first.Object) != s.out || !validBackupName(filepath.Base(first.Object)) {
		t.Fatalf("push line %+v", first)
	}
	if entries, _ := os.ReadDir(s.out); len(entries) != 2 {
		t.Fatalf("output dir has %d entries", len(entries))
	}
	newest := max(filepath.Base(first.Object), filepath.Base(second.Object))
	if code, _, stderr := runCLI(t, "", "restore", "--config", s.cfg, "--identity", s.key, "--verify-only", "app"); code != exitOK || !strings.Contains(stderr, newest) {
		t.Fatalf("restore did not pick the newest: %d %s", code, stderr)
	}
	code, out, stderr := runCLI(t, "", "restore", "--config", s.cfg, "--identity", s.key, "app", filepath.Base(second.Object))
	if code != exitOK {
		t.Fatalf("restore: %d %s", code, stderr)
	}
	names := tarNames(t, []byte(out))
	_, hasFile := names["data/file"]
	_, hasFirst := names["data/out/"+filepath.Base(first.Object)]
	if !hasFile || !hasFirst || len(names) != 4 { // the output file and its temporary file are not archived
		t.Fatalf("restored %v", names)
	}
	code, out, _ = runCLI(t, "", "restore", "--config", s.cfg, "--identity", s.key, "--verify-only", "app", filepath.Base(first.Object))
	var rep archiveReport
	if code != exitOK || json.Unmarshal([]byte(out), &rep) != nil || rep.Files != 1 {
		t.Fatalf("verify-only: %d %q", code, out)
	}
	code, out, _ = runCLI(t, "", "list", "--config", s.cfg, "app")
	if lines := strings.Split(strings.TrimSpace(out), "\n"); code != exitOK || len(lines) != 2 || !strings.HasPrefix(lines[1], newest) {
		t.Fatalf("list: %q", out)
	}
	for _, bad := range []string{"../x", first.Object, "app/" + filepath.Base(first.Object), "20260101T000000Z-00000000.kurumi"} {
		if code, out, _ := runCLI(t, "", "restore", "--config", s.cfg, "--identity", s.key, "app", bad); code != exitFailure || out != "" {
			t.Errorf("restore %q: %d", bad, code)
		}
	}
}

func TestLocalRestoreRefusals(t *testing.T) {
	isolateTemp(t)
	s := newLocal(t, false)
	l := s.push(t)
	bad := filepath.Join(s.out, "20260101T000000Z-00000000.kurumi")
	os.WriteFile(bad, []byte("not a backup"), 0o644)
	code, out, _ := runCLI(t, "", "restore", "--config", s.cfg, "--identity", s.key, "app", filepath.Base(bad))
	if code != exitFailure || out != "" {
		t.Errorf("failed verify wrote output: %d %q", code, out)
	}
	if tmps, _ := filepath.Glob(filepath.Join(os.TempDir(), "kurumi-restore-*")); len(tmps) != 0 {
		t.Errorf("temporary files left: %v", tmps)
	}
	link := filepath.Join(s.out, "20260101T000000Z-11111111.kurumi")
	if os.Symlink(l.Object, link) == nil {
		if code, _, _ := runCLI(t, "", "restore", "--config", s.cfg, "--identity", s.key, "app", filepath.Base(link)); code != exitFailure {
			t.Error("restored through a symlink")
		}
	}
	os.Mkdir(filepath.Join(s.out, "20260101T000000Z-22222222.kurumi"), 0o755)
	if code, _, _ := runCLI(t, "", "restore", "--config", s.cfg, "--identity", s.key, "app", "20260101T000000Z-22222222.kurumi"); code != exitFailure {
		t.Error("restored a directory")
	}

	// restore decrypts its private copy, so changing the original afterwards changes nothing
	tmp, _ := os.CreateTemp(t.TempDir(), "copy")
	defer tmp.Close()
	if err := copyLocal(l.Object, tmp); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(l.Object, []byte("tampered"), 0o644)
	k, _ := readIdentity(s.key, nil)
	if _, err := decryptFile(io.Discard, tmp, k); err != nil {
		t.Fatal(err)
	}
}

func TestPublishLocalNeverReplaces(t *testing.T) {
	dir := t.TempDir()
	existing := "20260101T000000Z-00000000.kurumi"
	os.WriteFile(filepath.Join(dir, existing), []byte("old"), 0o600)
	tmp, _ := os.CreateTemp(dir, ".tmp")
	tmp.WriteString("new")
	if _, err := publishLocal(tmp, dir, func() string { return existing }); err == nil {
		t.Fatal("replaced an existing backup")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, existing)); string(b) != "old" {
		t.Fatal("existing backup changed")
	}
	tmp2, _ := os.CreateTemp(dir, ".tmp")
	names := []string{existing, "20260101T000000Z-11111111.kurumi"}
	final, err := publishLocal(tmp2, dir, func() string { n := names[0]; names = names[1:]; return n })
	if err != nil || filepath.Base(final) != "20260101T000000Z-11111111.kurumi" {
		t.Fatalf("%s %v", final, err)
	}
	if _, err := os.Stat(tmp2.Name()); !errors.Is(err, os.ErrNotExist) {
		t.Error("temporary file left behind")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestPushExit3(t *testing.T) {
	s := newLocal(t, false)
	var stderr bytes.Buffer
	if code := run(t.Context(), []string{"push", "--config", s.cfg, "app"}, nil, brokenWriter{}, &stderr); code != exitNoSuccessLine {
		t.Fatalf("exit %d: %s", code, &stderr)
	}
	entries, _ := os.ReadDir(s.out)
	if len(entries) != 1 || !strings.Contains(stderr.String(), entries[0].Name()) {
		t.Fatalf("finalized backup not logged: %v %s", entries, &stderr)
	}
}

func TestPushRejectsSymlinkPath(t *testing.T) {
	s := newLocal(t, false)
	link := filepath.Join(s.dir, "link")
	if os.Symlink(s.data, link) != nil {
		t.Skip("symlinks unavailable")
	}
	cfg, _ := os.ReadFile(s.cfg)
	os.WriteFile(s.cfg, bytes.Replace(cfg, []byte(fmt.Sprintf("%q", s.data)), []byte(fmt.Sprintf("%q", link)), 1), 0o644)
	if code, _, _ := runCLI(t, "", "push", "--config", s.cfg, "app"); code != exitFailure {
		t.Fatal("symlinked path accepted")
	}
	if entries, _ := os.ReadDir(s.out); len(entries) != 0 {
		t.Fatalf("left files: %v", entries)
	}
}
