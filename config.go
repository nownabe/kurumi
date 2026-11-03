package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
)

type Config struct {
	Version int                `json:"version"`
	Targets map[string]*Target `json:"targets"`
}

type Target struct {
	Bucket        string   `json:"bucket"`
	Prefix        string   `json:"prefix"`
	OutputDir     string   `json:"output_dir"`
	Paths         []string `json:"paths"`
	Exclude       []string `json:"exclude"`
	Recipient     string   `json:"recipient"`
	RecipientFile string   `json:"recipient_file"`
	Compress      *bool    `json:"compress"`
	ChunkSize     *int     `json:"chunk_size"`

	name      string
	recipient *ecdh.PublicKey
}

func (t *Target) compress() bool { return t.Compress == nil || *t.Compress }

func (t *Target) chunkSize() int {
	if t.ChunkSize == nil {
		return defaultChunkSize
	}
	return *t.ChunkSize
}

type shape struct {
	fields map[string]*shape // object with exactly these keys; a nil value accepts anything
	values *shape            // object with free-form keys
}

var configShape = &shape{fields: map[string]*shape{
	"version": nil,
	"targets": {values: &shape{fields: map[string]*shape{
		"bucket": nil, "prefix": nil, "output_dir": nil, "paths": nil, "exclude": nil,
		"recipient": nil, "recipient_file": nil, "compress": nil, "chunk_size": nil,
	}}},
}}

var (
	targetNameRE = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
	prefixRE     = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
)

func configCandidates(flagPath string) []string {
	var c []string
	if flagPath != "" {
		c = append(c, flagPath)
	}
	if p := os.Getenv("KURUMI_CONFIG"); p != "" {
		c = append(c, p)
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		c = append(c, filepath.Join(x, "kurumi", "config.json"))
	} else if runtime.GOOS == "windows" {
		if d, err := os.UserConfigDir(); err == nil {
			c = append(c, filepath.Join(d, "kurumi", "config.json"))
		}
	} else if h, err := os.UserHomeDir(); err == nil {
		c = append(c, filepath.Join(h, ".config", "kurumi", "config.json"))
	}
	return c
}

func findConfig(flagPath string) (string, error) {
	tried := configCandidates(flagPath)
	for _, p := range tried {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no configuration file found; tried: %s", strings.Join(tried, ", "))
}

// loadConfig returns the parsed configuration and every problem found in it.
func loadConfig(flagPath string) (*Config, []error) {
	p, err := findConfig(flagPath)
	if err != nil {
		return nil, []error{err}
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, []error{err}
	}
	cfg, errs := parseConfig(data, filepath.Dir(p))
	for i, e := range errs {
		errs[i] = fmt.Errorf("%s: %w", p, e)
	}
	return cfg, errs
}

func parseConfig(data []byte, dir string) (*Config, []error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var errs []error
	if err := checkJSON(dec, configShape, "", &errs); err != nil {
		return nil, []error{err}
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, []error{errors.New("trailing data after the JSON object")}
	}
	if errs != nil {
		return nil, errs
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, []error{err}
	}
	if cfg.Version != 1 {
		errs = append(errs, errors.New("version must be 1"))
	}
	if len(cfg.Targets) == 0 {
		errs = append(errs, errors.New("targets is required"))
	}
	for _, name := range slices.Sorted(maps.Keys(cfg.Targets)) {
		t := cfg.Targets[name]
		t.name = name
		for _, e := range t.validate(dir) {
			errs = append(errs, fmt.Errorf("target %q: %w", name, e))
		}
	}
	return &cfg, errs
}

func checkJSON(dec *json.Decoder, sh *shape, at string, errs *[]error) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	switch tok {
	case nil:
		*errs = append(*errs, fmt.Errorf("%s: null is not allowed", at))
	case json.Delim('['):
		for i := 0; dec.More(); i++ {
			if err := checkJSON(dec, nil, fmt.Sprintf("%s[%d]", at, i), errs); err != nil {
				return err
			}
		}
		_, err = dec.Token()
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return fmt.Errorf("invalid JSON: %w", err)
			}
			k := kt.(string)
			where := at + "." + k
			if seen[k] {
				*errs = append(*errs, fmt.Errorf("%s: duplicate key", where))
			}
			seen[k] = true
			var sub *shape
			if sh != nil && sh.fields != nil {
				s, ok := sh.fields[k]
				if !ok {
					*errs = append(*errs, fmt.Errorf("%s: unknown key", where))
				}
				sub = s
			} else if sh != nil {
				sub = sh.values
			}
			if err := checkJSON(dec, sub, where, errs); err != nil {
				return err
			}
		}
		_, err = dec.Token()
	default:
		if sh != nil {
			*errs = append(*errs, fmt.Errorf("%s: must be an object", at))
		}
	}
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func (t *Target) validate(dir string) []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if !targetNameRE.MatchString(t.name) {
		add("target name must match [a-z0-9-]{1,63}")
	}
	if (t.Bucket == "") == (t.OutputDir == "") {
		add("exactly one of bucket and output_dir is required")
	}
	if t.OutputDir != "" {
		if t.Prefix != "" {
			add("prefix applies only to bucket targets")
		}
		t.OutputDir = resolve(dir, t.OutputDir)
	}
	if t.Prefix == "" {
		t.Prefix = t.name
	}
	if t.Bucket != "" && !validPrefix(t.Prefix) {
		add("invalid prefix %q", t.Prefix)
	}
	if len(t.Paths) == 0 {
		add("paths is required")
	}
	bases := map[string]bool{}
	for _, p := range t.Paths {
		c := filepath.Clean(p)
		switch {
		case !filepath.IsAbs(p):
			add("path %q is not absolute", p)
		case filepath.Dir(c) == c:
			add("path %q is the filesystem root", p)
		case bases[filepath.Base(c)]:
			add("two paths have the base name %q", filepath.Base(c))
		}
		bases[filepath.Base(c)] = true
	}
	for _, x := range t.Exclude {
		if _, err := path.Match(x, ""); err != nil {
			add("malformed exclude pattern %q", x)
		}
	}
	switch {
	case (t.Recipient == "") == (t.RecipientFile == ""):
		add("exactly one of recipient and recipient_file is required")
	case t.Recipient != "":
		k, err := parsePublicKey([]byte(t.Recipient))
		if err != nil {
			add("recipient: %v", err)
		}
		t.recipient = k
	default:
		t.RecipientFile = resolve(dir, t.RecipientFile)
		k, err := readRecipientFile(t.RecipientFile)
		if err != nil {
			add("recipient_file: %v", err)
		}
		t.recipient = k
	}
	if c := t.chunkSize(); c < minChunkSize || c > maxChunkSize {
		add("chunk_size must be between %d and %d", minChunkSize, maxChunkSize)
	}
	return errs
}

func resolve(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

func validPrefix(p string) bool {
	if !prefixRE.MatchString(p) || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
