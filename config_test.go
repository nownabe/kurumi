package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testPub(t testing.TB) string {
	return encodeKey(publicKeyPrefix, testKey(t).PublicKey().Bytes())
}

func TestConfigRejects(t *testing.T) {
	pub := testPub(t)
	dir := t.TempDir()
	abs := filepath.Join(dir, "data")
	target := func(body string) string {
		return fmt.Sprintf(`{"version":1,"targets":{"app":{%s}}}`, body)
	}
	ok := fmt.Sprintf(`"bucket":"b","paths":[%q],"recipient":%q`, abs, pub)
	if _, errs := parseConfig([]byte(target(ok)), dir); errs != nil {
		t.Fatalf("valid config rejected: %v", errs)
	}
	cases := map[string]string{
		"unknown key":          target(ok + `,"extra":1`),
		"case variant":         target(ok + `,"Compress":true`),
		"case variant top":     fmt.Sprintf(`{"Version":1,"targets":{"app":{%s}}}`, ok),
		"duplicate key":        target(ok + `,"bucket":"c"`),
		"null":                 target(ok + `,"exclude":null`),
		"trailing data":        target(ok) + " {}",
		"trailing garbage":     target(ok) + "x",
		"both bucket and dir":  target(ok + `,"output_dir":"/tmp"`),
		"neither bucket/dir":   target(fmt.Sprintf(`"paths":[%q],"recipient":%q`, abs, pub)),
		"both recipients":      target(ok + `,"recipient_file":"k.pub"`),
		"neither recipient":    target(fmt.Sprintf(`"bucket":"b","paths":[%q]`, abs)),
		"relative path":        target(fmt.Sprintf(`"bucket":"b","paths":["rel"],"recipient":%q`, pub)),
		"root path":            target(fmt.Sprintf(`"bucket":"b","paths":[%q],"recipient":%q`, string(filepath.Separator), pub)),
		"duplicate base names": target(fmt.Sprintf(`"bucket":"b","paths":[%q,%q],"recipient":%q`, abs, filepath.Join(dir, "x", "data"), pub)),
		"bad target name":      strings.Replace(target(ok), `"app"`, `"App"`, 1),
		"malformed pattern":    target(ok + `,"exclude":["["]`),
		"bad recipient":        target(fmt.Sprintf(`"bucket":"b","paths":[%q],"recipient":"kurumi-public-key-v1:AAAA"`, abs)),
		"chunk too small":      target(ok + `,"chunk_size":1024`),
		"wrong type":           target(ok + `,"compress":"yes"`),
		"wrong version":        strings.Replace(target(ok), `"version":1`, `"version":2`, 1),
		"no targets":           `{"version":1,"targets":{}}`,
		"target not object":    `{"version":1,"targets":{"app":[]}}`,
		"prefix leading slash": target(ok + `,"prefix":"/a"`),
		"prefix trailing":      target(ok + `,"prefix":"a/"`),
		"prefix double slash":  target(ok + `,"prefix":"a//b"`),
		"prefix dot":           target(ok + `,"prefix":"a/./b"`),
		"prefix dotdot":        target(ok + `,"prefix":"../b"`),
		"prefix bad char":      target(ok + `,"prefix":"a b"`),
		"prefix too long":      target(ok + `,"prefix":"` + strings.Repeat("a", 201) + `"`),
	}
	for name, cfg := range cases {
		if _, errs := parseConfig([]byte(cfg), dir); errs == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestConfigListsEveryProblem(t *testing.T) {
	_, errs := parseConfig([]byte(`{"version":1,"targets":{"a":{"paths":["rel"]},"b":{"paths":["rel"]}}}`), t.TempDir())
	if len(errs) < 4 {
		t.Fatalf("got %d problems: %v", len(errs), errs)
	}
}

func TestConfigRelativeRecipientFile(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "keys"), 0o755)
	os.WriteFile(filepath.Join(dir, "keys", "app.pub"), []byte(testPub(t)+"\n"), 0o644)
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, fmt.Appendf(nil, `{"version":1,"targets":{"app":{"output_dir":"out","paths":[%q],"recipient_file":"keys/app.pub"}}}`, dir), 0o644)
	t.Chdir(t.TempDir())
	cfg, errs := loadConfig(cfgPath)
	if errs != nil {
		t.Fatal(errs)
	}
	if got := cfg.Targets["app"].OutputDir; got != filepath.Join(dir, "out") {
		t.Fatalf("output_dir resolved to %s", got)
	}
}

func TestConfigLookup(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) string {
		p := filepath.Join(dir, name, "kurumi", "config.json")
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, nil, 0o644)
		return p
	}
	flagPath, envPath := write("flag"), write("env")
	xdgPath := write("xdg")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg"))
	t.Setenv("KURUMI_CONFIG", envPath)
	for _, tc := range []struct{ flag, want string }{{flagPath, flagPath}, {"", envPath}} {
		if got, _ := findConfig(tc.flag); got != tc.want {
			t.Errorf("findConfig(%q) = %s, want %s", tc.flag, got, tc.want)
		}
	}
	t.Setenv("KURUMI_CONFIG", "")
	if got, _ := findConfig(""); got != xdgPath {
		t.Errorf("XDG_CONFIG_HOME not honoured: %s", got)
	}
	missing := filepath.Join(dir, "missing.json")
	t.Setenv("KURUMI_CONFIG", missing+"2")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "none"))
	_, err := findConfig(missing)
	for _, p := range []string{missing, missing + "2", filepath.Join(dir, "none", "kurumi", "config.json")} {
		if err == nil || !strings.Contains(err.Error(), p) {
			t.Errorf("error %v does not name %s", err, p)
		}
	}
}

func TestConfigCheckCommand(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	os.WriteFile(p, []byte(`{"version":1,"targets":{"app":{"bucket":"b","paths":["rel"],"exclude":["["]}}}`), 0o644)
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"config", "check", "--config", p}, nil, &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"not absolute", "malformed exclude", "recipient"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr lacks %q: %s", want, &stderr)
		}
	}
}
