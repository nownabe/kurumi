package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func testKey(t testing.TB) *ecdh.PrivateKey {
	t.Helper()
	k, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type entry struct {
	name string
	data []byte
}

func makeTar(t testing.TB, entries ...entry) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data)), ModTime: time.Unix(1700000000, 0), Format: tar.FormatPAX}
		if strings.HasSuffix(e.name, "/") {
			h.Typeflag, h.Mode = tar.TypeDir, 0o755
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write(e.data)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func randomBytes(n int, seed uint64) []byte {
	b := make([]byte, n)
	rand.NewChaCha8([32]byte{byte(seed), byte(seed >> 8)}).Read(b)
	return b
}

func encrypt(t testing.TB, pub *ecdh.PublicKey, compress bool, chunk int, plaintext []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := newEncryptWriter(&out, pub, compress, chunk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// encryptRaw writes plaintext straight into the record layer, bypassing gzip,
// under a header that may still claim compression.
func encryptRaw(t testing.TB, pub *ecdh.PublicKey, compressFlag bool, chunk int, plaintext []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := newEncryptWriter(&out, pub, compressFlag, chunk)
	if err != nil {
		t.Fatal(err)
	}
	sw := w.(*encryptWriter).sw
	sw.Write(plaintext)
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// records splits a file into its header and records.
func records(t testing.TB, file []byte) (header []byte, recs [][]byte) {
	t.Helper()
	header, rest := file[:headerPrefixLen+encLen], file[headerPrefixLen+encLen:]
	for len(rest) > 0 {
		n := recordHeaderLen + int(binary.BigEndian.Uint32(rest[1:5])) + tagLen
		recs, rest = append(recs, rest[:n]), rest[n:]
	}
	return header, recs
}

func openRecords(file []byte, priv *ecdh.PrivateKey) ([]byte, error) {
	rr, err := newRecordReader(bytes.NewReader(file), priv)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(rr)
}

func TestRoundTrip(t *testing.T) {
	k := testKey(t)
	many := make([]entry, 300)
	for i := range many {
		many[i] = entry{fmt.Sprintf("d/f%03d", i), []byte(strings.Repeat("x", i))}
	}
	tests := map[string][]byte{
		"empty archive":     makeTar(t),
		"empty directory":   makeTar(t, entry{name: "d/"}),
		"one empty file":    makeTar(t, entry{name: "d/empty"}),
		"many small files":  makeTar(t, many...),
		"several records":   makeTar(t, entry{"d/big", randomBytes(3*minChunkSize+123, 1)}),
		"exact chunk tar":   makeTar(t, entry{"d/x", randomBytes(minChunkSize-512-1024, 2)}),
		"exact 2 chunk tar": makeTar(t, entry{"d/x", randomBytes(2*minChunkSize-512-1024, 3)}),
	}
	for name, plain := range tests {
		for _, compress := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/compress=%v", name, compress), func(t *testing.T) {
				file := encrypt(t, k.PublicKey(), compress, minChunkSize, plain)
				var out bytes.Buffer
				if _, err := decryptTo(&out, bytes.NewReader(file), k); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(out.Bytes(), plain) {
					t.Fatal("plaintext differs")
				}
			})
		}
	}
	if n := len(tests["exact chunk tar"]); n != minChunkSize {
		t.Fatalf("exact chunk tar is %d bytes", n)
	}
}

func TestCanonicalRecords(t *testing.T) {
	k := testKey(t)
	for _, n := range []int{0, 1, minChunkSize - 1, minChunkSize, minChunkSize + 1, 3 * minChunkSize} {
		file := encrypt(t, k.PublicKey(), false, minChunkSize, randomBytes(n, 4))
		_, recs := records(t, file)
		want := max(1, (n+minChunkSize-1)/minChunkSize)
		if len(recs) != want {
			t.Fatalf("n=%d: %d records, want %d", n, len(recs), want)
		}
		for i, r := range recs {
			final := i == len(recs)-1
			if (r[0] == flagFinal) != final {
				t.Fatalf("n=%d: record %d flag %d", n, i, r[0])
			}
		}
		got, err := openRecords(file, k)
		if err != nil || len(got) != n {
			t.Fatalf("n=%d: %d bytes, %v", n, len(got), err)
		}
	}
}

// TestCompressedExactMultiple pads the gzip header's extra field until the
// compressed stream is exactly one chunk, so the case does not depend on how a
// Go version compresses.
func TestCompressedExactMultiple(t *testing.T) {
	k := testKey(t)
	plain := makeTar(t, entry{"d/x", randomBytes(minChunkSize-4096, 5)})
	gz := func(extra []byte) []byte {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		zw.Extra = extra
		zw.Write(plain)
		zw.Close()
		return b.Bytes()
	}
	member := gz(make([]byte, minChunkSize-len(gz(nil))-2)) // the extra field has a 2-byte length
	if len(member) != minChunkSize {
		t.Fatalf("gzip member is %d bytes", len(member))
	}
	file := encryptRaw(t, k.PublicKey(), true, minChunkSize, member)
	if _, recs := records(t, file); len(recs) != 1 || len(recs[0]) != recordHeaderLen+minChunkSize+tagLen {
		t.Fatal("expected one full final record")
	}
	if _, err := decryptTo(io.Discard, bytes.NewReader(file), k); err != nil {
		t.Fatal(err)
	}
}

func TestRejectFlippedBytes(t *testing.T) {
	k := testKey(t)
	file := encrypt(t, k.PublicKey(), false, minChunkSize, randomBytes(minChunkSize+10, 6))
	workers := runtime.GOMAXPROCS(0)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for i := w; i < len(file); i += workers {
				bad := bytes.Clone(file)
				bad[i] ^= 0x01
				if _, err := openRecords(bad, k); err == nil {
					t.Errorf("flipping byte %d was accepted", i)
				}
			}
		})
	}
	wg.Wait()
}

func TestRejectRecordManipulation(t *testing.T) {
	k := testKey(t)
	file := encrypt(t, k.PublicKey(), false, minChunkSize, randomBytes(3*minChunkSize+10, 7))
	hdr, recs := records(t, file)
	join := func(rs ...[]byte) []byte { return bytes.Join(append([][]byte{hdr}, rs...), nil) }
	nonFinalLast := bytes.Clone(recs[2])
	finalEarly := bytes.Clone(recs[0])
	finalEarly[0] = flagFinal
	bigPlen := bytes.Clone(recs[3])
	binary.BigEndian.PutUint32(bigPlen[1:5], minChunkSize+1)
	shortNonFinal := bytes.Clone(recs[0])
	binary.BigEndian.PutUint32(shortNonFinal[1:5], minChunkSize-1)
	badFlag := bytes.Clone(recs[0])
	badFlag[0] = 2
	cases := map[string][]byte{
		"dropped":                join(recs[0], recs[2], recs[3]),
		"dropped final":          join(recs[0], recs[1], recs[2]),
		"duplicated":             join(recs[0], recs[0], recs[1], recs[2], recs[3]),
		"reordered":              join(recs[1], recs[0], recs[2], recs[3]),
		"final flag on first":    join(finalEarly, recs[1], recs[2], recs[3]),
		"non-final last":         join(recs[0], recs[1], recs[2], nonFinalLast),
		"trailing byte":          append(bytes.Clone(file), 0),
		"trailing record":        join(recs[0], recs[1], recs[2], recs[3], recs[3]),
		"plen over chunk":        join(recs[0], recs[1], recs[2], bigPlen),
		"short non-final record": join(shortNonFinal, recs[1], recs[2], recs[3]),
		"bad flag":               join(badFlag, recs[1], recs[2], recs[3]),
	}
	for name, bad := range cases {
		if _, err := openRecords(bad, k); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	cuts := []int{0, 1, headerPrefixLen, headerPrefixLen + encLen - 1}
	end := len(hdr)
	for _, r := range recs {
		cuts = append(cuts, end, end+1, end+recordHeaderLen-1, end+recordHeaderLen, end+len(r)/2, end+len(r)-1)
		end += len(r)
	}
	for _, n := range cuts {
		if _, err := openRecords(file[:n], k); err == nil {
			t.Errorf("truncation at %d accepted", n)
		}
	}
}

func TestRejectHeaderFields(t *testing.T) {
	k := testKey(t)
	file := encrypt(t, k.PublicKey(), false, minChunkSize, nil)
	set := func(off int, v ...byte) []byte {
		b := bytes.Clone(file)
		copy(b[off:], v)
		return b
	}
	cases := map[string][]byte{
		"magic":           set(0, 'X'),
		"version":         set(8, 2),
		"kem":             set(9, 0, 0x21),
		"kdf":             set(11, 0, 2),
		"aead":            set(13, 0, 1),
		"compression":     set(15, 2),
		"chunk too small": set(16, 0, 0, 0xff, 0xff),
		"chunk too large": set(16, 1, 0, 0, 1),
		"enc_len":         set(20, 0, 33),
	}
	for name, bad := range cases {
		_, err := openRecords(bad, k)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWrongKey(t *testing.T) {
	k := testKey(t)
	file := encrypt(t, k.PublicKey(), true, minChunkSize, makeTar(t, entry{"d/a", []byte("a")}))
	if _, err := decryptTo(io.Discard, bytes.NewReader(file), testKey(t)); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestGzipBoundary(t *testing.T) {
	k := testKey(t)
	gz := func(b []byte) []byte {
		var out bytes.Buffer
		w := gzip.NewWriter(&out)
		w.Write(b)
		w.Close()
		return out.Bytes()
	}
	member := gz(makeTar(t, entry{"d/a", []byte("a")}))
	if _, err := decryptTo(io.Discard, bytes.NewReader(encryptRaw(t, k.PublicKey(), true, minChunkSize, member)), k); err != nil {
		t.Fatalf("single member rejected: %v", err)
	}
	for name, plain := range map[string][]byte{
		"second member": append(bytes.Clone(member), gz(nil)...),
		"garbage":       append(bytes.Clone(member), "garbage"...),
		"zero byte":     append(bytes.Clone(member), 0),
	} {
		if _, err := decryptTo(io.Discard, bytes.NewReader(encryptRaw(t, k.PublicKey(), true, minChunkSize, plain)), k); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTarTrailer(t *testing.T) {
	k := testKey(t)
	plain := makeTar(t, entry{"d/a", []byte("a")})
	for name, tc := range map[string]struct {
		plain []byte
		ok    bool
	}{
		"zero padding":    {append(bytes.Clone(plain), make([]byte, 9000)...), true},
		"data after tar":  {append(bytes.Clone(plain), 'x'), false},
		"missing trailer": {plain[:len(plain)-1024], true},
	} {
		_, err := decryptTo(io.Discard, bytes.NewReader(encryptRaw(t, k.PublicKey(), false, minChunkSize, tc.plain)), k)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// TestLateAuthentication: the tar stream is complete before a damaged or
// missing final record, which must still fail verify and decrypt.
func TestLateAuthentication(t *testing.T) {
	k := testKey(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "id")
	os.WriteFile(keyFile, []byte(encodeKey(privateKeyPrefix, k.Bytes())), 0o600)
	plain := append(makeTar(t, entry{"d/x", randomBytes(minChunkSize-512-1024, 8)}), make([]byte, 100)...)
	file := encryptRaw(t, k.PublicKey(), false, minChunkSize, plain)
	hdr, recs := records(t, file)
	damaged := bytes.Clone(file)
	damaged[len(damaged)-1] ^= 1
	for name, bad := range map[string][]byte{"damaged final": damaged, "missing final": append(hdr, recs[0]...)} {
		p := filepath.Join(dir, "bad")
		os.WriteFile(p, bad, 0o600)
		for _, cmd := range []string{"verify", "decrypt"} {
			var stdout, stderr bytes.Buffer
			if code := run(t.Context(), []string{cmd, "--identity", keyFile, p}, nil, &stdout, &stderr); code != exitFailure {
				t.Errorf("%s %s: exit %d", name, cmd, code)
			}
		}
	}
}

func TestKeyParsing(t *testing.T) {
	k := testKey(t)
	line := encodeKey(privateKeyPrefix, k.Bytes())
	for _, ok := range []string{line, line + "\n", line + "\r\n"} {
		if _, err := parsePrivateKey([]byte(ok)); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	short := encodeKey(privateKeyPrefix, k.Bytes()[:31])
	for name, bad := range map[string]string{
		"two lines":      line + "\n" + line,
		"blank line":     line + "\n\n",
		"inner newline":  line[:30] + "\n" + line[30:],
		"short":          short,
		"no padding":     strings.TrimRight(line, "="),
		"wrong prefix":   strings.Replace(line, "private", "public", 1),
		"trailing space": line + " ",
		"public":         encodeKey(publicKeyPrefix, k.PublicKey().Bytes()),
	} {
		if _, err := parsePrivateKey([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

var update = flag.Bool("update", false, "regenerate test vectors")

const vectorDir = "testdata/vectors"

// vectorPlaintexts are the test vector inputs described in FORMAT.md.
func vectorPlaintexts() map[string][]byte {
	pattern := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i % 251)
		}
		return b
	}
	return map[string][]byte{
		"empty":    nil,
		"short":    []byte("kurumi test vector\n"),
		"one-full": pattern(minChunkSize),
		"several":  pattern(3*minChunkSize + 1000),
	}
}

// vectorKey is derived rather than stored, so no key literal is published.
func vectorKey(t testing.TB) *ecdh.PrivateKey {
	seed := sha256.Sum256([]byte("kurumi test vector"))
	k, err := ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestVectors(t *testing.T) {
	k := vectorKey(t)
	if *update {
		os.MkdirAll(vectorDir, 0o755)
		for name, plain := range vectorPlaintexts() {
			os.WriteFile(filepath.Join(vectorDir, name+".kurumi"), encrypt(t, k.PublicKey(), false, minChunkSize, plain), 0o644)
		}
	}
	for name, want := range vectorPlaintexts() {
		file, err := os.ReadFile(filepath.Join(vectorDir, name+".kurumi"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := openRecords(file, k)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
