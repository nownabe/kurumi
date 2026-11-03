package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"
)

const (
	exitOK = iota
	exitFailure
	exitUnknown
	exitNoSuccessLine
)

// Set at release build time with -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "unknown"
)

// transport is replaced by tests to reach a fake server under the real URLs.
var transport http.RoundTripper = http.DefaultTransport

// Tests shrink these to exercise chunking and retries quickly.
var (
	uploadBufSize = defaultUploadBuf
	retryBackoff  = time.Second
)

const usage = `usage:
  kurumi keygen [-o <private-key-file>]
  kurumi public-key --identity <file|->
  kurumi push [--config <file>] [--credentials <file>] [--dry-run] <target>
  kurumi list [--config <file>] [--credentials <file>] [--format text|json] <target>
  kurumi restore [--config <file>] [--credentials <file>] --identity <file|-> [--verify-only] <target> [<name>]
  kurumi decrypt --identity <file|-> [<file>]
  kurumi verify --identity <file|-> [<file>]
  kurumi config check [--config <file>]
  kurumi --version
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

type cli struct {
	ctx    context.Context
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	log    *slog.Logger
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	c := &cli{ctx: ctx, stdin: stdin, stdout: stdout, stderr: stderr, log: slog.New(slog.NewTextHandler(stderr, nil))}
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitFailure
	}
	cmds := map[string]func([]string) int{
		"keygen": c.keygen, "public-key": c.publicKey, "push": c.push, "list": c.list,
		"restore": c.restore, "decrypt": c.decrypt, "verify": c.verify, "config": c.config,
	}
	if args[0] == "--version" || args[0] == "-version" {
		fmt.Fprintf(stdout, "kurumi %s (commit %s)\n", version, commit)
		return exitOK
	}
	cmd, ok := cmds[args[0]]
	if !ok {
		fmt.Fprint(stderr, usage)
		return exitFailure
	}
	return cmd(args[1:])
}

func (c *cli) fail(err error) int {
	c.log.Error(err.Error())
	return exitFailure
}

// parse accepts flags before, between, and after positional arguments.
func (c *cli) parse(fs *flag.FlagSet, args []string, minPos, maxPos int) ([]string, bool) {
	fs.SetOutput(c.stderr)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, false
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) < minPos || len(pos) > maxPos {
		fmt.Fprint(c.stderr, usage)
		return nil, false
	}
	return pos, true
}

func (c *cli) keygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("o", "", "write the private key to this new file")
	if _, ok := c.parse(fs, args, 0, 0); !ok {
		return exitFailure
	}
	if *out == "" {
		if f, ok := c.stdout.(*os.File); ok && isTerminal(f) {
			return c.fail(errors.New("refusing to print a private key to a terminal; pipe it, e.g. kurumi keygen | pass insert -m kurumi/app"))
		}
	}
	k, err := generateKey()
	if err != nil {
		return c.fail(err)
	}
	priv := []byte(encodeKey(privateKeyPrefix, k.Bytes()) + "\n")
	defer clear(priv)
	if *out == "" {
		_, err = c.stdout.Write(priv)
	} else {
		err = writeNewFile(*out, priv)
		if err == nil && runtime.GOOS == "windows" {
			c.log.Warn("file permissions are not restricted on Windows; protect the key file yourself", "path", *out)
		}
	}
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintln(c.stderr, encodeKey(publicKeyPrefix, k.PublicKey().Bytes()))
	return exitOK
}

func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return errors.Join(err, f.Close())
}

func (c *cli) publicKey(args []string) int {
	fs := flag.NewFlagSet("public-key", flag.ContinueOnError)
	id := fs.String("identity", "", "private key file, or - for standard input")
	if _, ok := c.parse(fs, args, 0, 0); !ok {
		return exitFailure
	}
	k, err := readIdentity(*id, c.stdin)
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintln(c.stdout, encodeKey(publicKeyPrefix, k.PublicKey().Bytes()))
	return exitOK
}

func (c *cli) config(args []string) int {
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprint(c.stderr, usage)
		return exitFailure
	}
	fs := flag.NewFlagSet("config check", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	if _, ok := c.parse(fs, args[1:], 0, 0); !ok {
		return exitFailure
	}
	_, errs := loadConfig(*cfgPath)
	for _, e := range errs {
		c.log.Error(e.Error())
	}
	if errs != nil {
		return exitFailure
	}
	fmt.Fprintln(c.stderr, "configuration OK")
	return exitOK
}

func (c *cli) target(cfgPath, name string) (*Target, error) {
	cfg, errs := loadConfig(cfgPath)
	if errs != nil {
		return nil, errors.Join(errs...)
	}
	t, ok := cfg.Targets[name]
	if !ok {
		return nil, fmt.Errorf("no target %q in the configuration", name)
	}
	return t, nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (cw *countWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += int64(n)
	return n, err
}

var backupNameRE = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\.kurumi$`)

const nameTimeLayout = "20060102T150405Z"

func newBackupName() string {
	var b [4]byte
	rand.Read(b[:])
	return time.Now().UTC().Format(nameTimeLayout) + "-" + hex.EncodeToString(b[:]) + ".kurumi"
}

func validBackupName(s string) bool {
	if !backupNameRE.MatchString(s) {
		return false
	}
	_, err := time.Parse(nameTimeLayout, s[:16])
	return err == nil
}

func (c *cli) push(args []string) int {
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	creds := fs.String("credentials", "", "service account key file (upload-only)")
	dryRun := fs.Bool("dry-run", false, "encrypt into nowhere and report the size")
	pos, ok := c.parse(fs, args, 1, 1)
	if !ok {
		return exitFailure
	}
	t, err := c.target(*cfgPath, pos[0])
	if err != nil {
		return c.fail(err)
	}
	started := time.Now().UTC()
	c.log.Info("push started", "target", t.name, "dry_run", *dryRun)

	var sink io.Writer = io.Discard
	var skip []os.FileInfo
	finalize := func() (string, error) { return "", nil }
	switch {
	case *dryRun:
	case t.OutputDir != "":
		tmp, err := os.CreateTemp(t.OutputDir, ".kurumi-*.tmp")
		if err != nil {
			return c.fail(err)
		}
		defer os.Remove(tmp.Name())
		defer tmp.Close()
		fi, err := tmp.Stat()
		if err != nil {
			return c.fail(err)
		}
		sink, skip = tmp, []os.FileInfo{fi}
		finalize = func() (string, error) { return publishLocal(tmp, t.OutputDir, newBackupName) }
	default:
		gc, err := newGCSClient(*creds, scopeWrite, transport, c.log)
		if err != nil {
			return c.fail(err)
		}
		object, session, err := gc.startUpload(c.ctx, t.Bucket, func() string { return t.Prefix + "/" + newBackupName() })
		if err != nil {
			return c.fail(err)
		}
		c.log.Info("upload session started", "bucket", t.Bucket, "object", object)
		up := &uploader{c: gc, ctx: c.ctx, session: session, bufSize: uploadBufSize}
		sink = up
		finalize = func() (string, error) { return object, up.finish() }
	}

	cw := &countWriter{w: sink}
	ew, err := newEncryptWriter(cw, t.recipient, t.compress(), t.chunkSize())
	if err != nil {
		return c.fail(err)
	}
	files, err := writeArchive(ew, t.Paths, t.Exclude, skip)
	if err == nil {
		err = ew.Close()
	}
	if err != nil {
		return c.fail(fmt.Errorf("nothing was finalized: %w", err))
	}
	object, err := finalize()
	if errors.Is(err, errOutcomeUnknown) {
		c.log.Error(err.Error(), "object", object)
		return exitUnknown
	}
	if err != nil {
		return c.fail(fmt.Errorf("nothing was finalized: %w", err))
	}
	if !*dryRun {
		c.log.Info("backup finalized", "target", t.name, "object", object, "bytes", cw.n, "files", files)
	}
	line, _ := json.Marshal(struct {
		Target     string `json:"target"`
		Object     string `json:"object"`
		DryRun     bool   `json:"dry_run"`
		Bytes      int64  `json:"bytes"`
		Files      int64  `json:"files"`
		StartedAt  string `json:"started_at"`
		FinishedAt string `json:"finished_at"`
	}{t.name, object, *dryRun, cw.n, files, started.Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339)})
	if _, err := c.stdout.Write(append(line, '\n')); err != nil {
		c.log.Error("backup finalized but the success line could not be written", "object", object, "error", err)
		return exitNoSuccessLine
	}
	return exitOK
}

// publishLocal links the finished temporary file under a fresh backup name;
// os.Link fails rather than replace an existing file.
func publishLocal(tmp *os.File, dir string, newName func() string) (string, error) {
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	for attempt := 0; ; attempt++ {
		final := filepath.Join(dir, newName())
		err := os.Link(tmp.Name(), final)
		if errors.Is(err, os.ErrExist) && attempt < 3 {
			continue
		}
		if err != nil {
			return "", err
		}
		return final, os.Remove(tmp.Name())
	}
}

type backup struct {
	name    string
	size    int64
	created time.Time
	obj     objectInfo
}

func (c *cli) backups(t *Target, gc *gcsClient) ([]backup, error) {
	var bs []backup
	if t.Bucket != "" {
		objs, err := gc.listObjects(c.ctx, t.Bucket, t.Prefix)
		if err != nil {
			return nil, err
		}
		for _, o := range objs {
			name, ok := strings.CutPrefix(o.Name, t.Prefix+"/")
			if !ok || !validBackupName(name) {
				continue
			}
			var b backup
			b.name, b.obj = name, o
			fmt.Sscan(o.Size, &b.size)
			b.created, _ = time.Parse(time.RFC3339, o.TimeCreated)
			bs = append(bs, b)
		}
	} else {
		entries, err := os.ReadDir(t.OutputDir)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !validBackupName(e.Name()) {
				continue
			}
			info, err := e.Info()
			if err != nil {
				return nil, err
			}
			bs = append(bs, backup{name: e.Name(), size: info.Size(), created: info.ModTime()})
		}
	}
	if len(bs) == 0 {
		return nil, fmt.Errorf("no backups found for target %q", t.name)
	}
	slices.SortFunc(bs, func(a, b backup) int { return strings.Compare(a.name, b.name) })
	return bs, nil
}

func (c *cli) readClient(t *Target, creds string) (*gcsClient, error) {
	if t.Bucket == "" {
		return nil, nil
	}
	return newGCSClient(creds, scopeRead, transport, c.log)
}

func (c *cli) list(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	creds := fs.String("credentials", "", "service account key file (read-only)")
	format := fs.String("format", "text", "text or json")
	pos, ok := c.parse(fs, args, 1, 1)
	if !ok {
		return exitFailure
	}
	if *format != "text" && *format != "json" {
		return c.fail(errors.New("--format must be text or json"))
	}
	t, err := c.target(*cfgPath, pos[0])
	if err != nil {
		return c.fail(err)
	}
	gc, err := c.readClient(t, *creds)
	if err != nil {
		return c.fail(err)
	}
	bs, err := c.backups(t, gc)
	if err != nil {
		return c.fail(err)
	}
	for _, b := range bs {
		created := b.created.UTC().Format(time.RFC3339)
		if *format == "json" {
			line, _ := json.Marshal(map[string]any{"name": b.name, "size": b.size, "created": created})
			fmt.Fprintf(c.stdout, "%s\n", line)
		} else {
			fmt.Fprintf(c.stdout, "%s\t%d\t%s\n", b.name, b.size, created)
		}
	}
	return exitOK
}

func (c *cli) restore(args []string) int {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	creds := fs.String("credentials", "", "service account key file (read-only)")
	id := fs.String("identity", "", "private key file, or - for standard input")
	verifyOnly := fs.Bool("verify-only", false, "download and verify, write no archive")
	pos, ok := c.parse(fs, args, 1, 2)
	if !ok {
		return exitFailure
	}
	priv, err := readIdentity(*id, c.stdin)
	if err != nil {
		return c.fail(err)
	}
	if len(pos) == 2 && !validBackupName(pos[1]) {
		return c.fail(fmt.Errorf("%q is not a backup name (expected e.g. 20260101T000000Z-0123abcd.kurumi)", pos[1]))
	}
	t, err := c.target(*cfgPath, pos[0])
	if err != nil {
		return c.fail(err)
	}
	gc, err := c.readClient(t, *creds)
	if err != nil {
		return c.fail(err)
	}
	bs, err := c.backups(t, gc)
	if err != nil {
		return c.fail(err)
	}
	b := bs[len(bs)-1]
	if len(pos) == 2 {
		i := slices.IndexFunc(bs, func(b backup) bool { return b.name == pos[1] })
		if i < 0 {
			return c.fail(fmt.Errorf("backup %s not found in target %q", pos[1], t.name))
		}
		b = bs[i]
	}
	c.log.Info("restoring", "target", t.name, "name", b.name)

	tmp, err := os.CreateTemp("", "kurumi-restore-*")
	if err != nil {
		return c.fail(err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if gc != nil {
		err = gc.download(c.ctx, t.Bucket, b.obj, tmp)
	} else {
		err = copyLocal(filepath.Join(t.OutputDir, b.name), tmp)
	}
	if err != nil {
		return c.fail(err)
	}
	rep, err := decryptFile(io.Discard, tmp, priv)
	if err != nil {
		return c.fail(fmt.Errorf("verify failed, nothing written: %w", err))
	}
	if *verifyOnly {
		return c.report(rep)
	}
	if _, err := decryptFile(c.stdout, tmp, priv); err != nil {
		return c.fail(err)
	}
	return exitOK
}

func decryptFile(out io.Writer, f *os.File, priv *ecdh.PrivateKey) (archiveReport, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return archiveReport{}, err
	}
	return decryptTo(out, f, priv)
}

// copyLocal copies a backup that must be a regular file, so the bytes cannot
// change between verifying and decrypting.
func copyLocal(path string, dst io.Writer) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) {
		return fmt.Errorf("%s changed while being opened", path)
	}
	_, err = io.Copy(dst, f)
	return err
}

func (c *cli) report(rep archiveReport) int {
	line, _ := json.Marshal(rep)
	if _, err := fmt.Fprintf(c.stdout, "%s\n", line); err != nil {
		return c.fail(err)
	}
	return exitOK
}

func (c *cli) decryptOrVerify(name string, args []string, out io.Writer) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	id := fs.String("identity", "", "private key file, or - for standard input")
	pos, ok := c.parse(fs, args, 0, 1)
	if !ok {
		return exitFailure
	}
	if *id == "-" && len(pos) == 0 {
		return c.fail(errors.New("<file> is required with --identity - (standard input carries the key)"))
	}
	priv, err := readIdentity(*id, c.stdin)
	if err != nil {
		return c.fail(err)
	}
	in := c.stdin
	if len(pos) == 1 {
		f, err := os.Open(pos[0])
		if err != nil {
			return c.fail(err)
		}
		defer f.Close()
		in = f
	}
	rep, err := decryptTo(out, in, priv)
	if err != nil {
		return c.fail(err)
	}
	if name == "verify" {
		return c.report(rep)
	}
	return exitOK
}

func (c *cli) decrypt(args []string) int {
	return c.decryptOrVerify("decrypt", args, c.stdout)
}

func (c *cli) verify(args []string) int {
	return c.decryptOrVerify("verify", args, io.Discard)
}
