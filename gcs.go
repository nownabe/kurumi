package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	tokenURL    = "https://oauth2.googleapis.com/token"
	storageHost = "storage.googleapis.com"
	storageURL  = "https://" + storageHost
	scopeWrite  = "https://www.googleapis.com/auth/devstorage.read_write"
	scopeRead   = "https://www.googleapis.com/auth/devstorage.read_only"

	uploadQuantum     = 256 << 10
	defaultUploadBuf  = 8 << 20
	requestTimeout    = 5 * time.Minute
	downloadIdleLimit = 2 * time.Minute
	maxResponseBody   = 32 << 20
)

// errOutcomeUnknown means the final chunk was sent but whether the object
// was finalized could not be determined.
var errOutcomeUnknown = errors.New("upload outcome unknown")

type gcsClient struct {
	http    *http.Client
	email   string
	key     *rsa.PrivateKey
	scope   string
	token   string
	expiry  time.Time
	retries int
	backoff time.Duration
	log     *slog.Logger
}

func newHTTPClient(rt http.RoundTripper) *http.Client {
	return &http.Client{
		Transport:     rt,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func newGCSClient(credPath, scope string, rt http.RoundTripper, log *slog.Logger) (*gcsClient, error) {
	if credPath == "" {
		credPath = os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	}
	if credPath == "" {
		return nil, errors.New("no credentials: use --credentials or GOOGLE_APPLICATION_CREDENTIALS")
	}
	f, err := os.Open(credPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var sa struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&sa); err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}
	if sa.Type != "service_account" || sa.ClientEmail == "" {
		return nil, errors.New(`credentials: need type "service_account" and client_email`)
	}
	if sa.TokenURI != tokenURL {
		return nil, fmt.Errorf("credentials: token_uri must be %s", tokenURL)
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, errors.New("credentials: private_key is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	rk, ok := k.(*rsa.PrivateKey)
	if err != nil || !ok {
		return nil, errors.New("credentials: private_key is not a PKCS#8 RSA key")
	}
	return &gcsClient{http: newHTTPClient(rt), email: sa.ClientEmail, key: rk, scope: scope, retries: 6, backoff: retryBackoff, log: log}, nil
}

func (c *gcsClient) do(ctx context.Context, req *http.Request) (*http.Response, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		return nil, nil, withoutURL(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err == nil && len(body) > maxResponseBody {
		err = errors.New("response body too large")
	}
	return resp, body, err
}

// withoutURL drops the request URL from client errors: a session URI is a
// bearer capability and must never reach the logs.
func withoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s request: %w", ue.Op, ue.Err)
	}
	return err
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (c *gcsClient) accessToken(ctx context.Context) (string, error) {
	if c.token != "" && time.Until(c.expiry) > 5*time.Minute {
		return c.token, nil
	}
	now := time.Now()
	claims, _ := json.Marshal(map[string]any{
		"iss": c.email, "scope": c.scope, "aud": tokenURL,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	signing := b64url([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + b64url(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(nil, c.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signing + "." + b64url(sig)},
	}
	req, _ := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, body, err := c.do(ctx, req)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange: HTTP %d", resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return "", errors.New("token exchange: malformed response")
	}
	c.token, c.expiry = tok.AccessToken, now.Add(time.Duration(tok.ExpiresIn)*time.Second)
	return c.token, nil
}

func (c *gcsClient) authed(ctx context.Context, method, u string) (*http.Request, error) {
	tok, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return req, nil
}

func (c *gcsClient) sleep(ctx context.Context, attempt int) error {
	select {
	case <-time.After(c.backoff << attempt):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func retryable(code int) bool { return code == http.StatusTooManyRequests || code >= 500 }

func objectsURL(bucket string) string {
	return storageURL + "/storage/v1/b/" + url.PathEscape(bucket) + "/o"
}

// startUpload opens a resumable session for a new object. The name callback
// is asked again when the name is already taken.
func (c *gcsClient) startUpload(ctx context.Context, bucket string, newName func() string) (name, session string, err error) {
	for collisions, attempt := 0, 0; ; {
		name = newName()
		u := storageURL + "/upload/storage/v1/b/" + url.PathEscape(bucket) + "/o?uploadType=resumable&name=" + url.QueryEscape(name) + "&ifGenerationMatch=0"
		req, err := c.authed(ctx, http.MethodPost, u)
		if err != nil {
			return "", "", err
		}
		req.Header.Set("X-Upload-Content-Type", "application/octet-stream")
		resp, _, err := c.do(ctx, req)
		switch {
		case err == nil && resp.StatusCode == http.StatusOK:
			loc, err := url.Parse(resp.Header.Get("Location"))
			if err != nil || loc.Scheme != "https" || loc.Host != storageHost {
				return "", "", errors.New("start upload: unexpected session location")
			}
			return name, loc.String(), nil
		case err == nil && resp.StatusCode == http.StatusPreconditionFailed && collisions < 3:
			collisions++
			c.log.Warn("object name already taken; choosing a new name", "object", name)
			continue
		case (err != nil || retryable(resp.StatusCode)) && attempt < c.retries:
			c.log.Warn("start upload failed; retrying", "error", errOrStatus(err, resp))
			if err := c.sleep(ctx, attempt); err != nil {
				return "", "", err
			}
			attempt++
		default:
			return "", "", fmt.Errorf("start upload: %v", errOrStatus(err, resp))
		}
	}
}

func errOrStatus(err error, resp *http.Response) any {
	if err != nil {
		return err
	}
	return "HTTP " + strconv.Itoa(resp.StatusCode)
}

// uploader is the io.Writer at the end of the push pipeline. It never sends
// the last buffer before finish, so a producer failure never finalizes.
type uploader struct {
	c       *gcsClient
	ctx     context.Context
	session string
	bufSize int
	buf     []byte // bytes from offset on, not yet acknowledged
	offset  int64
	total   int64
	stalls  int
}

var errRejected = errors.New("rejected by the server")

func (u *uploader) Write(p []byte) (int, error) {
	u.buf = append(u.buf, p...)
	u.total += int64(len(p))
	for len(u.buf) > u.bufSize {
		if err := u.send(u.bufSize, false); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (u *uploader) finish() error { return u.send(len(u.buf), true) }

// send transmits buf[:n] (n is a multiple of 256 KiB unless final) and drops
// what the server acknowledged. A final send repeats until finalized.
func (u *uploader) send(n int, final bool) error {
	askStatus := false
	for attempt := 0; ; {
		var done bool
		var acked int64
		var err error
		if askStatus {
			done, acked, err = u.exchange(nil, "*", final)
		} else {
			done, acked, err = u.exchange(u.buf[:n], fmt.Sprintf("%d-%d", u.offset, u.offset+int64(n)-1), final)
		}
		if err != nil {
			if errors.Is(err, errRejected) {
				return err
			}
			if attempt == u.c.retries {
				return u.unknown(final, err)
			}
			u.c.log.Warn("upload request failed; will ask the session for its status", "error", err)
			if err := u.c.sleep(u.ctx, attempt); err != nil {
				return u.unknown(final, err)
			}
			attempt++
			askStatus = true
			continue
		}
		askStatus = false
		if done {
			if !final {
				return errors.New("upload: server finalized the object before the final chunk")
			}
			return nil
		}
		if acked < u.offset || acked > u.offset+int64(len(u.buf)) {
			return u.unknown(final, fmt.Errorf("server acknowledged %d bytes, outside [%d, %d]", acked, u.offset, u.offset+int64(len(u.buf))))
		}
		if acked == u.offset {
			u.stalls++
			if u.stalls > u.c.retries {
				return u.unknown(final, errors.New("upload makes no progress"))
			}
		} else {
			u.stalls = 0
		}
		u.buf = u.buf[acked-u.offset:]
		u.offset = acked
		if !final {
			return nil // anything unacknowledged stays in buf and goes with the next chunk
		}
		n = len(u.buf)
		askStatus = n == 0 // everything is there; "bytes */total" finalizes
	}
}

func (u *uploader) unknown(final bool, err error) error {
	if final {
		return fmt.Errorf("%w: %v", errOutcomeUnknown, err)
	}
	return fmt.Errorf("upload: %w", err)
}

// exchange sends one PUT to the session; an empty rng body is a status query.
// done reports a finalized object; acked is what the server has otherwise.
func (u *uploader) exchange(body []byte, rng string, final bool) (done bool, acked int64, err error) {
	total := "*"
	if final {
		total = strconv.FormatInt(u.total, 10)
	}
	req, _ := http.NewRequest(http.MethodPut, u.session, bytes.NewReader(body))
	req.Header.Set("Content-Range", "bytes "+rng+"/"+total)
	resp, _, err := u.c.do(u.ctx, req)
	switch {
	case err != nil:
		return false, 0, err
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated:
		return true, 0, nil
	case resp.StatusCode == http.StatusPermanentRedirect:
		acked, err := parseRange(resp)
		return false, acked, err
	case retryable(resp.StatusCode):
		return false, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	case final && (resp.StatusCode == http.StatusPreconditionFailed || resp.StatusCode == http.StatusForbidden):
		return false, 0, fmt.Errorf("upload: %w: finalization refused with HTTP %d; the name may already be taken, and the consumed stream cannot be resent under a new name", errRejected, resp.StatusCode)
	default:
		return false, 0, fmt.Errorf("upload: %w: HTTP %d", errRejected, resp.StatusCode)
	}
}

// parseRange returns how many bytes the server has: "bytes=0-N" means N+1,
// no header means none.
func parseRange(resp *http.Response) (int64, error) {
	r := resp.Header.Get("Range")
	if r == "" {
		return 0, nil
	}
	last, ok := strings.CutPrefix(r, "bytes=0-")
	n, err := strconv.ParseInt(last, 10, 64)
	if !ok || err != nil || n < 0 {
		return 0, fmt.Errorf("malformed Range header %q", r)
	}
	return n + 1, nil
}

type objectInfo struct {
	Name        string `json:"name"`
	Size        string `json:"size"`
	TimeCreated string `json:"timeCreated"`
	Generation  string `json:"generation"`
	CRC32C      string `json:"crc32c"`
}

func (c *gcsClient) listObjects(ctx context.Context, bucket, prefix string) ([]objectInfo, error) {
	var all []objectInfo
	pageToken := ""
	for {
		u := objectsURL(bucket) + "?prefix=" + url.QueryEscape(prefix+"/")
		if pageToken != "" {
			u += "&pageToken=" + url.QueryEscape(pageToken)
		}
		req, err := c.authed(ctx, http.MethodGet, u)
		if err != nil {
			return nil, err
		}
		resp, body, err := c.do(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("list: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("list: HTTP %d", resp.StatusCode)
		}
		var page struct {
			Items         []objectInfo `json:"items"`
			NextPageToken string       `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("list: %w", err)
		}
		all = append(all, page.Items...)
		if page.NextPageToken == "" {
			return all, nil
		}
		pageToken = page.NextPageToken
	}
}

// download writes the object to w and checks it against the listed CRC32C.
func (c *gcsClient) download(ctx context.Context, bucket string, obj objectInfo, w io.Writer) error {
	want, err := base64.StdEncoding.DecodeString(obj.CRC32C)
	if err != nil || len(want) != 4 {
		return errors.New("download: missing or malformed crc32c")
	}
	if _, err := strconv.ParseInt(obj.Generation, 10, 64); err != nil {
		return errors.New("download: malformed generation")
	}
	req, err := c.authed(ctx, http.MethodGet, objectsURL(bucket)+"/"+url.PathEscape(obj.Name)+"?alt=media&generation="+url.QueryEscape(obj.Generation))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := time.AfterFunc(downloadIdleLimit, cancel)
	defer idle.Stop()
	resp, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("download: %w", withoutURL(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	buf := make([]byte, 256<<10)
	for {
		idle.Reset(downloadIdleLimit)
		n, rerr := resp.Body.Read(buf)
		h.Write(buf[:n])
		if _, err := w.Write(buf[:n]); err != nil {
			return err
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("download: %w", rerr)
		}
	}
	if h.Sum32() != binary.BigEndian.Uint32(want) {
		return errors.New("download: CRC32C mismatch")
	}
	return nil
}
