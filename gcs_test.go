package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	fakeToken     = "ya29.fake-secret-token"
	sessionSecret = "SESSIONSECRET"
	uploadPath    = "/upload/storage/v1/b/bkt/o"
	listPath      = "/storage/v1/b/bkt/o"
)

type fakeSession struct {
	name string
	data []byte
	done bool
}

type fakeObject struct {
	data []byte
	crc  string
}

// fakeGCS implements exactly the allowlisted requests of section 6 and fails
// the test on anything else.
type fakeGCS struct {
	t        *testing.T
	pub      *rsa.PublicKey
	mu       sync.Mutex
	requests []string
	scopes   []string
	objects  map[string]*fakeObject
	sessions map[string]*fakeSession
	starts   []int // statuses returned by the next start requests
	puts     int
	// onPut may answer a data PUT itself; i counts data PUTs from 0.
	onPut    func(i int, s *fakeSession, first int64, final bool, body []byte, w http.ResponseWriter) bool
	onStatus func(s *fakeSession, w http.ResponseWriter) bool
}

var (
	saKeyOnce sync.Once
	saKey     *rsa.PrivateKey
)

func newFake(t *testing.T) (*fakeGCS, string) {
	saKeyOnce.Do(func() { saKey, _ = rsa.GenerateKey(rand.Reader, 2048) })
	f := &fakeGCS{t: t, pub: &saKey.PublicKey, objects: map[string]*fakeObject{}, sessions: map[string]*fakeSession{}}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	tr.TLSClientConfig.ServerName = "example.com"
	oldT, oldB, oldR := transport, uploadBufSize, retryBackoff
	transport, uploadBufSize, retryBackoff = tr, uploadQuantum, time.Millisecond
	t.Cleanup(func() { transport, uploadBufSize, retryBackoff = oldT, oldB, oldR })

	der, _ := x509.MarshalPKCS8PrivateKey(saKey)
	creds, _ := json.Marshal(map[string]string{
		"type": "service_account", "client_email": "kurumi@example.iam.gserviceaccount.com",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"token_uri":   tokenURL,
	})
	credPath := filepath.Join(t.TempDir(), "sa.json")
	os.WriteFile(credPath, creds, 0o600)
	return f, credPath
}

func (f *fakeGCS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.Host+r.URL.EscapedPath()+" "+r.Header.Get("Content-Range"))
	q := r.URL.Query()
	keys := slices.Sorted(func(yield func(string) bool) {
		for k := range q {
			yield(k)
		}
	})
	authed := r.Header.Get("Authorization") == "Bearer "+fakeToken
	switch {
	case r.Host == "oauth2.googleapis.com" && r.Method == http.MethodPost && r.URL.Path == "/token" && len(q) == 0:
		f.token(w, r)
	case r.Host == storageHost && r.Method == http.MethodPost && r.URL.Path == uploadPath && authed &&
		slices.Equal(keys, []string{"ifGenerationMatch", "name", "uploadType"}) && q.Get("uploadType") == "resumable" && q.Get("ifGenerationMatch") == "0":
		f.start(w, q.Get("name"))
	case r.Host == storageHost && r.Method == http.MethodPut && r.URL.Path == uploadPath && f.sessions[q.Get("upload_id")] != nil:
		f.put(w, r, f.sessions[q.Get("upload_id")])
	case r.Host == storageHost && r.Method == http.MethodGet && r.URL.EscapedPath() == listPath && authed &&
		(slices.Equal(keys, []string{"prefix"}) || slices.Equal(keys, []string{"pageToken", "prefix"})):
		f.list(w, q.Get("prefix"), q.Get("pageToken"))
	case r.Host == storageHost && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, listPath+"/") && authed &&
		slices.Equal(keys, []string{"alt", "generation"}) && q.Get("alt") == "media":
		name := strings.TrimPrefix(r.URL.Path, listPath+"/")
		o := f.objects[name]
		if o == nil || r.URL.EscapedPath() != listPath+"/"+url.PathEscape(name) || q.Get("generation") != "7" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Write(o.data)
	default:
		f.t.Errorf("request outside the allowlist: %s %s authed=%v", r.Method, r.URL, authed)
		http.Error(w, "forbidden", http.StatusForbidden)
	}
}

func (f *fakeGCS) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	parts := strings.Split(r.PostForm.Get("assertion"), ".")
	if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || len(parts) != 3 {
		f.t.Errorf("bad token request %v", r.PostForm)
		return
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(f.pub, crypto.SHA256, sum[:], sig); err != nil {
		f.t.Errorf("JWT signature: %v", err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	json.Unmarshal(payload, &c)
	if c["iss"] != "kurumi@example.iam.gserviceaccount.com" || c["aud"] != tokenURL || c["sub"] != nil ||
		c["exp"].(float64)-c["iat"].(float64) > 3600 {
		f.t.Errorf("JWT claims %v", c)
	}
	f.scopes = append(f.scopes, c["scope"].(string))
	fmt.Fprintf(w, `{"access_token":%q,"expires_in":3599,"token_type":"Bearer"}`, fakeToken)
}

func (f *fakeGCS) start(w http.ResponseWriter, name string) {
	if len(f.starts) > 0 {
		code := f.starts[0]
		f.starts = f.starts[1:]
		w.WriteHeader(code)
		return
	}
	if f.objects[name] != nil {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	id := sessionSecret + strconv.Itoa(len(f.sessions))
	f.sessions[id] = &fakeSession{name: name}
	w.Header().Set("Location", storageURL+uploadPath+"?uploadType=resumable&name="+url.QueryEscape(name)+"&upload_id="+id)
	w.WriteHeader(http.StatusOK)
}

func (f *fakeGCS) put(w http.ResponseWriter, r *http.Request, s *fakeSession) {
	body, _ := io.ReadAll(r.Body)
	rng, total, ok := strings.Cut(strings.TrimPrefix(r.Header.Get("Content-Range"), "bytes "), "/")
	if !ok {
		f.t.Errorf("bad Content-Range %q", r.Header.Get("Content-Range"))
		return
	}
	if rng == "*" {
		if f.onStatus != nil && f.onStatus(s, w) {
			return
		}
		f.respond(w, s, total)
		return
	}
	var first, last int64
	fmt.Sscanf(rng, "%d-%d", &first, &last)
	if int64(len(body)) != last-first+1 || first > int64(len(s.data)) || s.done {
		f.t.Errorf("inconsistent PUT %s/%s with %d bytes (server has %d)", rng, total, len(body), len(s.data))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if total == "*" && len(body)%uploadQuantum != 0 {
		f.t.Errorf("non-final chunk of %d bytes", len(body))
	}
	i := f.puts
	f.puts++
	if f.onPut != nil && f.onPut(i, s, first, total != "*", body, w) {
		return
	}
	f.accept(s, first, body)
	f.respond(w, s, total)
}

func (f *fakeGCS) accept(s *fakeSession, first int64, body []byte) {
	s.data = append(s.data, body[int64(len(s.data))-first:]...)
}

func (f *fakeGCS) respond(w http.ResponseWriter, s *fakeSession, total string) {
	if !s.done && total == strconv.Itoa(len(s.data)) {
		s.done = true
		f.objects[s.name] = &fakeObject{data: s.data}
	}
	if s.done {
		w.Write([]byte("{}"))
		return
	}
	if len(s.data) > 0 {
		w.Header().Set("Range", fmt.Sprintf("bytes=0-%d", len(s.data)-1))
	}
	w.WriteHeader(http.StatusPermanentRedirect)
}

func (f *fakeGCS) list(w http.ResponseWriter, prefix, token string) {
	var names []string
	for n := range f.objects {
		if strings.HasPrefix(n, prefix) {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	start, _ := strconv.Atoi(token)
	end := min(start+2, len(names))
	type item struct{ Name, Size, Generation, TimeCreated, Crc32c string }
	var page struct {
		Items         []item `json:"items"`
		NextPageToken string `json:"nextPageToken,omitempty"`
	}
	for _, n := range names[start:end] {
		o := f.objects[n]
		crc := o.crc
		if crc == "" {
			crc = base64.StdEncoding.EncodeToString(binary.BigEndian.AppendUint32(nil, crc32.Checksum(o.data, crc32.MakeTable(crc32.Castagnoli))))
		}
		page.Items = append(page.Items, item{n, strconv.Itoa(len(o.data)), "7", "2026-01-01T00:00:00.000Z", crc})
	}
	if end < len(names) {
		page.NextPageToken = strconv.Itoa(end)
	}
	json.NewEncoder(w).Encode(page)
}

func (f *fakeGCS) finalPuts() int {
	n := 0
	for _, r := range f.requests {
		if strings.HasPrefix(r, "PUT") && !strings.HasSuffix(r, "/*") {
			n++
		}
	}
	return n
}

type bucketSetup struct {
	cfg, creds, key, data string
	priv                  *ecdh.PrivateKey
}

func newBucket(t *testing.T, creds string, dataSize int) bucketSetup {
	dir := t.TempDir()
	s := bucketSetup{cfg: filepath.Join(dir, "config.json"), creds: creds, key: filepath.Join(dir, "id"), data: filepath.Join(dir, "data"), priv: testKey(t)}
	os.Mkdir(s.data, 0o755)
	os.WriteFile(filepath.Join(s.data, "big"), randomBytes(dataSize, 9), 0o644)
	os.WriteFile(s.key, []byte(encodeKey(privateKeyPrefix, s.priv.Bytes())), 0o600)
	os.WriteFile(s.cfg, fmt.Appendf(nil, `{"version":1,"targets":{"app":{"bucket":"bkt","paths":[%q],"recipient":%q}}}`,
		s.data, encodeKey(publicKeyPrefix, s.priv.PublicKey().Bytes())), 0o644)
	return s
}

func (s bucketSetup) push(t *testing.T) (code int, stdout, stderr string) {
	return runCLI(t, "", "push", "--config", s.cfg, "--credentials", s.creds, "app")
}

func assertNoSecrets(t *testing.T, logs string) {
	t.Helper()
	for _, secret := range []string{fakeToken, sessionSecret, "eyJ", "PRIVATE KEY", privateKeyPrefix} {
		if strings.Contains(logs, secret) {
			t.Errorf("log contains %q:\n%s", secret, logs)
		}
	}
}

func TestPushToBucket(t *testing.T) {
	f, creds := newFake(t)
	s := newBucket(t, creds, 5*uploadQuantum+1234)
	code, out, stderr := s.push(t)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	assertNoSecrets(t, stderr)
	var line pushLine
	json.Unmarshal([]byte(out), &line)
	obj := f.objects[line.Object]
	if obj == nil || !strings.HasPrefix(line.Object, "app/") || !validBackupName(strings.TrimPrefix(line.Object, "app/")) {
		t.Fatalf("object %q not stored; have %v", line.Object, f.objects)
	}
	if int64(len(obj.data)) != line.Bytes || f.puts < 5 || f.finalPuts() != 1 {
		t.Fatalf("%d bytes vs line %d, %d PUTs, %d final", len(obj.data), line.Bytes, f.puts, f.finalPuts())
	}
	if _, err := decryptTo(io.Discard, bytes.NewReader(obj.data), s.priv); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.scopes, []string{scopeWrite}) {
		t.Errorf("scopes %v", f.scopes)
	}
}

func TestPushNameCollision(t *testing.T) {
	f, creds := newFake(t)
	s := newBucket(t, creds, 100)
	f.starts = []int{http.StatusPreconditionFailed, http.StatusPreconditionFailed}
	if code, _, stderr := s.push(t); code != exitOK || len(f.objects) != 1 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var names []string
	for _, r := range f.requests {
		if strings.HasPrefix(r, "POST "+storageHost) {
			names = append(names, r)
		}
	}
	if len(names) != 3 {
		t.Fatalf("start requests %v", names)
	}
	f.starts = slices.Repeat([]int{http.StatusPreconditionFailed}, 4)
	if code, _, _ := s.push(t); code != exitFailure {
		t.Fatalf("exit %d after four collisions", code)
	}
}

func TestPushProducerFailureNeverFinalizes(t *testing.T) {
	for reject := range 4 {
		t.Run(fmt.Sprintf("reject chunk %d", reject), func(t *testing.T) {
			f, creds := newFake(t)
			s := newBucket(t, creds, 4*uploadQuantum)
			f.onPut = func(i int, _ *fakeSession, _ int64, final bool, _ []byte, w http.ResponseWriter) bool {
				if i == reject && !final {
					w.WriteHeader(http.StatusForbidden)
					return true
				}
				return false
			}
			if code, _, _ := s.push(t); code != exitFailure || f.finalPuts() != 0 || len(f.objects) != 0 {
				t.Fatalf("exit %d, %d final PUTs, objects %v", code, f.finalPuts(), f.objects)
			}
		})
	}
	if runtime.GOOS == "windows" {
		return
	}
	t.Run("unsupported file after data was sent", func(t *testing.T) {
		f, creds := newFake(t)
		s := newBucket(t, creds, 8*uploadQuantum)
		l, err := net.Listen("unix", filepath.Join(s.data, "zz.sock"))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		if code, _, _ := s.push(t); code != exitFailure || f.puts == 0 || f.finalPuts() != 0 || len(f.objects) != 0 {
			t.Fatalf("exit %d, %d PUTs, %d final", code, f.puts, f.finalPuts())
		}
	})
}

func TestPushLostFinalResponse(t *testing.T) {
	f, creds := newFake(t)
	s := newBucket(t, creds, 2*uploadQuantum)
	f.onPut = func(_ int, sess *fakeSession, first int64, final bool, body []byte, _ http.ResponseWriter) bool {
		if !final {
			return false
		}
		f.accept(sess, first, body)
		sess.done = true
		f.objects[sess.name] = &fakeObject{data: sess.data}
		panic(http.ErrAbortHandler)
	}
	if code, out, stderr := s.push(t); code != exitOK || out == "" {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}

func TestPushOutcomeUnknown(t *testing.T) {
	f, creds := newFake(t)
	s := newBucket(t, creds, 2*uploadQuantum)
	f.onPut = func(_ int, _ *fakeSession, _ int64, final bool, _ []byte, _ http.ResponseWriter) bool {
		if final {
			panic(http.ErrAbortHandler)
		}
		return false
	}
	f.onStatus = func(*fakeSession, http.ResponseWriter) bool { panic(http.ErrAbortHandler) }
	code, out, stderr := s.push(t)
	if code != exitUnknown || out != "" || !strings.Contains(stderr, "app/") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	assertNoSecrets(t, stderr)
}

// uploadDirect runs the uploader alone, writing data in pieces of size piece.
func uploadDirect(t *testing.T, f *fakeGCS, creds string, data []byte, piece int) []byte {
	t.Helper()
	gc, err := newGCSClient(creds, scopeWrite, transport, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	name, session, err := gc.startUpload(t.Context(), "bkt", func() string { return "app/x" })
	if err != nil {
		t.Fatal(err)
	}
	u := &uploader{c: gc, ctx: t.Context(), session: session, bufSize: uploadBufSize}
	for p := range slices.Chunk(data, piece) {
		if _, err := u.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := u.finish(); err != nil {
		t.Fatal(err)
	}
	return f.objects[name].data
}

func TestUploaderExactMultiples(t *testing.T) {
	for _, n := range []int{1, uploadQuantum, 2 * uploadQuantum, 3*uploadQuantum + 7} {
		for _, piece := range []int{1000, uploadQuantum, n} {
			f, creds := newFake(t)
			data := randomBytes(n, uint64(n))
			if got := uploadDirect(t, f, creds, data, piece); !bytes.Equal(got, data) {
				t.Fatalf("n=%d piece=%d: object differs", n, piece)
			}
			if want := (n + uploadQuantum - 1) / uploadQuantum; f.puts != want || f.finalPuts() != 1 {
				t.Fatalf("n=%d piece=%d: %d PUTs, want %d", n, piece, f.puts, want)
			}
		}
	}
}

func TestUploaderResends(t *testing.T) {
	cases := map[string]func(f *fakeGCS, s *fakeSession, first int64, body []byte, w http.ResponseWriter){
		"partial ack": func(f *fakeGCS, s *fakeSession, first int64, body []byte, w http.ResponseWriter) {
			f.accept(s, first, body[:len(body)/2])
			f.respond(w, s, "*")
		},
		"no range": func(f *fakeGCS, s *fakeSession, _ int64, _ []byte, w http.ResponseWriter) {
			w.WriteHeader(http.StatusPermanentRedirect)
		},
		"lost response": func(f *fakeGCS, s *fakeSession, first int64, body []byte, _ http.ResponseWriter) {
			f.accept(s, first, body)
			panic(http.ErrAbortHandler)
		},
		"server error": func(f *fakeGCS, s *fakeSession, _ int64, _ []byte, w http.ResponseWriter) {
			w.WriteHeader(http.StatusServiceUnavailable)
		},
	}
	for name, fault := range cases {
		ats := []int{0, 1, 3} // first, middle, and final chunk
		if name == "no range" {
			ats = ats[:1] // a 308 without Range means the server has nothing
		}
		for _, at := range ats {
			t.Run(fmt.Sprintf("%s at %d", name, at), func(t *testing.T) {
				f, creds := newFake(t)
				f.onPut = func(i int, s *fakeSession, first int64, _ bool, body []byte, w http.ResponseWriter) bool {
					if i != at {
						return false
					}
					fault(f, s, first, body, w)
					return true
				}
				data := randomBytes(3*uploadQuantum+100, 10)
				if got := uploadDirect(t, f, creds, data, 4096); !bytes.Equal(got, data) {
					t.Fatal("object differs")
				}
			})
		}
	}
}

func (f *fakeGCS) store(name string, data []byte) { f.objects[name] = &fakeObject{data: data} }

func TestListAndRestoreBucket(t *testing.T) {
	isolateTemp(t)
	f, creds := newFake(t)
	s := newBucket(t, creds, 10)
	backup := func(content string) []byte {
		return encrypt(t, s.priv.PublicKey(), true, minChunkSize, makeTar(t, entry{"data/f", []byte(content)}))
	}
	names := []string{"20260101T000000Z-00000002.kurumi", "20260101T000000Z-0000000a.kurumi", "20260301T000000Z-00000001.kurumi"}
	for i, n := range names {
		f.store("app/"+n, backup(fmt.Sprint("v", i)))
	}
	f.store("app/sub/20270101T000000Z-00000000.kurumi", backup("nested"))
	f.store("app/notes.txt", []byte("x"))
	f.store("app/20990101T000000Z-ffffffff.kurumi", []byte("garbage that fails verify"))
	f.store("app/20990101T000000Z-eeeeeeee.kurumi", backup("bad crc"))
	f.objects["app/20990101T000000Z-eeeeeeee.kurumi"].crc = "AAAAAA=="
	f.store("apple/20990101T000000Z-00000000.kurumi", backup("other prefix"))

	code, out, stderr := runCLI(t, "", "list", "--config", s.cfg, "--credentials", creds, "--format", "json", "app")
	if code != exitOK {
		t.Fatal(stderr)
	}
	var listed []string
	for l := range strings.Lines(out) {
		var e struct{ Name string }
		json.Unmarshal([]byte(l), &e)
		listed = append(listed, e.Name)
	}
	want := append(slices.Clone(names), "20990101T000000Z-eeeeeeee.kurumi", "20990101T000000Z-ffffffff.kurumi")
	if !slices.Equal(listed, want) {
		t.Fatalf("listed %v, want %v", listed, want)
	}

	restore := func(args ...string) (int, string, string) {
		return runCLI(t, "", append([]string{"restore", "--config", s.cfg, "--credentials", creds, "--identity", s.key, "app"}, args...)...)
	}
	for _, bad := range []string{"20990101T000000Z-ffffffff.kurumi", "20990101T000000Z-eeeeeeee.kurumi"} {
		if code, out, _ := restore(bad); code != exitFailure || out != "" {
			t.Errorf("%s: exit %d, %d bytes written", bad, code, len(out))
		}
	}
	if code, out, _ := restore(); code != exitFailure || out != "" {
		t.Errorf("newest (garbage) restored: %d", code)
	}
	delete(f.objects, "app/20990101T000000Z-ffffffff.kurumi")
	delete(f.objects, "app/20990101T000000Z-eeeeeeee.kurumi")
	code, out, stderr = restore()
	if code != exitOK || !strings.Contains(stderr, names[2]) {
		t.Fatalf("restore: %d %s", code, stderr)
	}
	if !strings.Contains(out, "v2") {
		t.Fatal("restored the wrong backup")
	}
	if code, out, _ := restore(names[0], "--verify-only"); code != exitOK || !strings.Contains(out, `"files":1`) {
		t.Fatalf("verify-only: %d %s", code, out)
	}
	if tmps, _ := filepath.Glob(filepath.Join(os.TempDir(), "kurumi-restore-*")); len(tmps) != 0 {
		t.Errorf("temporary files left: %v", tmps)
	}
	for _, sc := range f.scopes {
		if sc != scopeRead {
			t.Errorf("read command used scope %s", sc)
		}
	}
	assertNoSecrets(t, stderr)
}
