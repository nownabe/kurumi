package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
)

const (
	exitOK = iota
	exitFailure
)

// Set at release build time with -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "unknown"
)

const usage = `usage:
  kurumi keygen [-o <private-key-file>]
  kurumi public-key --identity <file|->
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
		"keygen": c.keygen, "public-key": c.publicKey, "decrypt": c.decrypt, "verify": c.verify,
		"config": c.config,
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
