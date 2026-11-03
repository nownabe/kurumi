package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	magic            = "KURUMI\x00\x00"
	formatVersion    = 0x01
	kemX25519        = 0x0020
	kdfHKDFSHA256    = 0x0001
	aeadAES256GCM    = 0x0002
	compressNone     = 0x00
	compressGzip     = 0x01
	headerPrefixLen  = 22
	encLen           = 32
	recordHeaderLen  = 5
	tagLen           = 16
	minChunkSize     = 1 << 16
	maxChunkSize     = 1 << 24
	defaultChunkSize = 1 << 20
	flagMore         = 0x00
	flagFinal        = 0x01
)

func headerPrefix(compress bool, chunkSize int) []byte {
	h := make([]byte, 0, headerPrefixLen)
	h = append(h, magic...)
	h = append(h, formatVersion)
	h = binary.BigEndian.AppendUint16(h, kemX25519)
	h = binary.BigEndian.AppendUint16(h, kdfHKDFSHA256)
	h = binary.BigEndian.AppendUint16(h, aeadAES256GCM)
	if compress {
		h = append(h, compressGzip)
	} else {
		h = append(h, compressNone)
	}
	h = binary.BigEndian.AppendUint32(h, uint32(chunkSize))
	return binary.BigEndian.AppendUint16(h, encLen)
}

// sealWriter turns plaintext into records. It always holds back the current
// record so the last one written by Close is the only final record.
type sealWriter struct {
	w     io.Writer
	s     *hpke.Sender
	buf   []byte
	chunk int
}

func (sw *sealWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		if len(sw.buf) == sw.chunk {
			if err := sw.seal(flagMore); err != nil {
				return n, err
			}
		}
		c := copy(sw.buf[len(sw.buf):sw.chunk], p)
		sw.buf = sw.buf[:len(sw.buf)+c]
		p = p[c:]
		n += c
	}
	return n, nil
}

func (sw *sealWriter) Close() error { return sw.seal(flagFinal) }

func (sw *sealWriter) seal(flag byte) error {
	aad := binary.BigEndian.AppendUint32([]byte{flag}, uint32(len(sw.buf)))
	ct, err := sw.s.Seal(aad, sw.buf)
	if err != nil {
		return err
	}
	sw.buf = sw.buf[:0]
	if _, err := sw.w.Write(aad); err != nil {
		return err
	}
	_, err = sw.w.Write(ct)
	return err
}

type encryptWriter struct {
	gz *gzip.Writer
	sw *sealWriter
}

func (e *encryptWriter) Write(p []byte) (int, error) {
	if e.gz != nil {
		return e.gz.Write(p)
	}
	return e.sw.Write(p)
}

func (e *encryptWriter) Close() error {
	if e.gz != nil {
		if err := e.gz.Close(); err != nil {
			return err
		}
	}
	return e.sw.Close()
}

// newEncryptWriter writes the header to w and returns a writer for the plaintext
// layer (the tar stream). Close finishes gzip and writes the final record.
func newEncryptWriter(w io.Writer, pub *ecdh.PublicKey, compress bool, chunkSize int) (io.WriteCloser, error) {
	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return nil, err
	}
	prefix := headerPrefix(compress, chunkSize)
	enc, s, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), prefix)
	if err != nil {
		return nil, err
	}
	if len(enc) != encLen {
		return nil, fmt.Errorf("unexpected enc length %d", len(enc))
	}
	if _, err := w.Write(append(prefix, enc...)); err != nil {
		return nil, err
	}
	e := &encryptWriter{sw: &sealWriter{w: w, s: s, buf: make([]byte, 0, chunkSize), chunk: chunkSize}}
	if compress {
		e.gz = gzip.NewWriter(e.sw)
	}
	return e, nil
}

type fileHeader struct {
	compress  bool
	chunkSize int
}

func parseHeaderPrefix(h []byte) (fileHeader, error) {
	be := binary.BigEndian
	switch {
	case string(h[0:8]) != magic:
		return fileHeader{}, errors.New("not a kurumi file: bad magic")
	case h[8] != formatVersion:
		return fileHeader{}, fmt.Errorf("unsupported version %d", h[8])
	case be.Uint16(h[9:11]) != kemX25519:
		return fileHeader{}, fmt.Errorf("unsupported kem_id 0x%04x", be.Uint16(h[9:11]))
	case be.Uint16(h[11:13]) != kdfHKDFSHA256:
		return fileHeader{}, fmt.Errorf("unsupported kdf_id 0x%04x", be.Uint16(h[11:13]))
	case be.Uint16(h[13:15]) != aeadAES256GCM:
		return fileHeader{}, fmt.Errorf("unsupported aead_id 0x%04x", be.Uint16(h[13:15]))
	case h[15] != compressNone && h[15] != compressGzip:
		return fileHeader{}, fmt.Errorf("unsupported compression %d", h[15])
	case be.Uint32(h[16:20]) < minChunkSize || be.Uint32(h[16:20]) > maxChunkSize:
		return fileHeader{}, fmt.Errorf("chunk_size %d out of range", be.Uint32(h[16:20]))
	case be.Uint16(h[20:22]) != encLen:
		return fileHeader{}, fmt.Errorf("unsupported enc_len %d", be.Uint16(h[20:22]))
	}
	return fileHeader{compress: h[15] == compressGzip, chunkSize: int(be.Uint32(h[16:20]))}, nil
}

// recordReader yields authenticated plaintext. It returns io.EOF only after the
// final record was opened and the input is proven to end right after it.
type recordReader struct {
	r     io.Reader
	rcp   *hpke.Recipient
	hdr   fileHeader
	buf   []byte
	plain []byte
	done  bool
}

func newRecordReader(r io.Reader, priv *ecdh.PrivateKey) (*recordReader, error) {
	h := make([]byte, headerPrefixLen+encLen)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, fmt.Errorf("reading header: %w", truncated(err))
	}
	hdr, err := parseHeaderPrefix(h[:headerPrefixLen])
	if err != nil {
		return nil, err
	}
	sk, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	rcp, err := hpke.NewRecipient(h[headerPrefixLen:], sk, hpke.HKDFSHA256(), hpke.AES256GCM(), h[:headerPrefixLen])
	if err != nil {
		return nil, fmt.Errorf("decapsulating key: %w", err)
	}
	return &recordReader{r: r, rcp: rcp, hdr: hdr, buf: make([]byte, hdr.chunkSize+tagLen)}, nil
}

func truncated(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

func (rr *recordReader) Read(p []byte) (int, error) {
	for len(rr.plain) == 0 {
		if rr.done {
			return 0, io.EOF
		}
		if err := rr.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, rr.plain)
	rr.plain = rr.plain[n:]
	return n, nil
}

func (rr *recordReader) next() error {
	var aad [recordHeaderLen]byte
	if _, err := io.ReadFull(rr.r, aad[:]); err != nil {
		return fmt.Errorf("truncated before final record: %w", truncated(err))
	}
	flag, plen := aad[0], int(binary.BigEndian.Uint32(aad[1:]))
	switch {
	case flag != flagMore && flag != flagFinal:
		return fmt.Errorf("invalid record flag %d", flag)
	case flag == flagMore && plen != rr.hdr.chunkSize:
		return fmt.Errorf("non-final record has plen %d, want %d", plen, rr.hdr.chunkSize)
	case plen > rr.hdr.chunkSize:
		return fmt.Errorf("final record plen %d exceeds chunk_size", plen)
	}
	ct := rr.buf[:plen+tagLen]
	if _, err := io.ReadFull(rr.r, ct); err != nil {
		return fmt.Errorf("truncated record: %w", truncated(err))
	}
	pt, err := rr.rcp.Open(aad[:], ct)
	if err != nil {
		return errors.New("record authentication failed (wrong key or damaged file)")
	}
	rr.plain = pt
	if flag == flagFinal {
		var b [1]byte
		if n, err := rr.r.Read(b[:]); n > 0 || err == nil {
			return errors.New("trailing data after final record")
		} else if err != io.EOF {
			return err
		}
		rr.done = true
	}
	return nil
}

type archiveReport struct {
	Files       int64     `json:"files"`
	Bytes       int64     `json:"bytes"`
	NewestMtime time.Time `json:"newest_mtime"`
}

// decryptTo reads an encrypted file through every layer and writes the tar
// stream to out as it is authenticated. A nil error means every byte up to and
// including the final record was authenticated and every layer ended cleanly.
func decryptTo(out io.Writer, in io.Reader, priv *ecdh.PrivateKey) (archiveReport, error) {
	var rep archiveReport
	rr, err := newRecordReader(in, priv)
	if err != nil {
		return rep, err
	}
	var plain io.Reader = rr
	var gz *gzip.Reader
	var br *bufio.Reader
	if rr.hdr.compress {
		br = bufio.NewReader(rr)
		if gz, err = gzip.NewReader(br); err != nil {
			return rep, fmt.Errorf("gzip: %w", truncated(err))
		}
		gz.Multistream(false)
		plain = gz
	}
	tee := io.TeeReader(plain, out)
	tr := tar.NewReader(tee)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return rep, fmt.Errorf("tar: %w", err)
		}
		if h.Typeflag == tar.TypeReg {
			rep.Files++
			rep.Bytes += h.Size
		}
		if h.ModTime.After(rep.NewestMtime) {
			rep.NewestMtime = h.ModTime
		}
	}
	if err := drainZeros(tee); err != nil {
		return rep, err
	}
	if gz != nil {
		if err := gz.Close(); err != nil {
			return rep, fmt.Errorf("gzip: %w", err)
		}
		if n, err := io.Copy(io.Discard, br); err != nil {
			return rep, err
		} else if n > 0 {
			return rep, errors.New("data after the gzip member")
		}
	}
	return rep, nil
}

func drainZeros(r io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		for _, b := range buf[:n] {
			if b != 0 {
				return errors.New("non-zero data after the tar end-of-archive marker")
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("after tar end: %w", err)
		}
	}
}
