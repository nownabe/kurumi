# kurumi file format, version 1

A `.kurumi` file is a tar archive, optionally gzip-compressed, encrypted with HPKE ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)) **base mode** to an X25519 public key, and split into authenticated records. This document is enough to decrypt a file without kurumi.

All integers are big-endian.

## Header (22 bytes, then `enc`)

| Offset | Length | Field       | v1 value                                                                              |
| ------ | ------ | ----------- | ------------------------------------------------------------------------------------- |
| 0      | 8      | magic       | ASCII `KURUMI` + `0x00 0x00`                                                          |
| 8      | 1      | version     | `0x01`                                                                                |
| 9      | 2      | kem_id      | `0x0020` = DHKEM(X25519, HKDF-SHA256)                                                 |
| 11     | 2      | kdf_id      | `0x0001` = HKDF-SHA256                                                                |
| 13     | 2      | aead_id     | `0x0002` = AES-256-GCM                                                                |
| 15     | 1      | compression | `0x00` = none, `0x01` = gzip                                                          |
| 16     | 4      | chunk_size  | plaintext bytes per record (uint32). Allowed: 65,536 to 16,777,216. Default 1,048,576 |
| 20     | 2      | enc_len     | must be 32                                                                            |
| 22     | 32     | enc         | HPKE encapsulated key                                                                 |

- The HPKE `info` is the **22-byte prefix** (offsets 0–21). `enc` is not part of `info`; DHKEM already binds it into the key schedule.
- A reader validates magic, version, the exact suite, compression, the chunk_size range, and `enc_len == 32` before allocating buffers or starting HPKE, and rejects anything else.

## Records (after the header)

| Length    | Field                                                     |
| --------- | --------------------------------------------------------- |
| 1         | flag: `0x00` = more records follow, `0x01` = final record |
| 4         | plen: plaintext length of this record (uint32)            |
| plen + 16 | `Seal(aad = flag ‖ plen, plaintext)` (ciphertext and tag) |

- One HPKE context per file. Records are sealed and opened strictly in order; the HPKE sequence number is the nonce, so reordering, dropping, or duplicating records fails.
- A non-final record has `plen == chunk_size`. The final record has `0 ≤ plen ≤ chunk_size`.
- There is exactly one final record and it is the last thing in the file. EOF before it (truncation), any byte after it, and any length outside these rules are errors.
- Writers emit the canonical form: an input that is an exact multiple of chunk_size ends with a full-size final record; an empty input is a single final record with `plen = 0`.

## Plaintext

The concatenated record plaintexts are a POSIX tar stream (PAX format). With `compression = 0x01` they are a **single** gzip member containing that tar stream.

A reader must consume every layer to its physical end before declaring success: the tar end-of-archive marker, then only zero bytes to the end of the (decompressed) stream; for gzip, the member trailer, and then zero further plaintext bytes (a second member or trailing garbage is an error); then the final record. Stopping when tar reports end-of-archive is a bug: the final record would never be authenticated.

## Keys

- Private key file: one line, `kurumi-private-key-v1:` followed by the standard base64 (with padding) of the 32-byte X25519 private key (the RFC 7748 scalar as stored, i.e. what `DeserializePrivateKey` of RFC 9180 accepts).
- Public key: `kurumi-public-key-v1:` followed by base64 of the 32-byte X25519 public key.
- A key line may end in `\n` or `\r\n`; nothing else is allowed.

## Decrypting with any RFC 9180 implementation

1. Read the private key line, strip the prefix, base64-decode to 32 bytes `skR`.
2. Read 54 bytes. Check the header fields as above. Let `info` = bytes 0–21, `enc` = bytes 22–53, `chunk_size` = bytes 16–19.
3. `ctx = SetupBaseR(enc, skR, info)` with suite KEM `0x0020`, KDF `0x0001`, AEAD `0x0002`.
4. Repeat: read 5 bytes `aad` (flag and plen). Check the length rules above. Read `plen + 16` bytes `ct`. `pt = ctx.Open(aad, ct)`; fail on any error. Append `pt` to the output. If flag is `0x01`, require end of file and stop.
5. If compression is `0x01`, gunzip the output (single member). The result is a tar archive.

`testdata/vectors/decrypt.py` does steps 1–4 in about 40 lines with [pyhpke](https://github.com/dajiaji/pyhpke).

## Test vectors

The vectors exercise the record layer, so their plaintexts are arbitrary bytes rather than tar archives, and `compression` is `0x00`. chunk_size is 65,536 in all of them. Their private key is the SHA-256 of the ASCII string `kurumi test vector`, used as the 32-byte X25519 private key. In hex:

```
d19802d5e6f092a79e225befd5dbc7c110533103cac163d9200e69acce6debca
```

| Vector            | Plaintext                                      | Plaintext SHA-256                                                  | File SHA-256                                                       |
| ----------------- | ---------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| `empty.kurumi`    | empty                                          | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `36e5d61f92f8979a1bd8f114e78549930238c9cc1d09d60bcd6c50da8b6d9d5e` |
| `short.kurumi`    | ASCII `kurumi test vector` and `\n` (19 bytes) | `9e6181493274b9366eb18d0bc7c13bee90a47aa7763f44453bd68a662bd03175` | `427bfa5c5cce1c05dc923c3781e5a7932a7569bd774ba3780dd379e2eaef41f6` |
| `one-full.kurumi` | 65,536 bytes, byte _i_ = _i_ mod 251           | `4b640d85ab3ba30fd02c9fc9db4a8928f416322ad27022ea58a65aaee68a4df2` | `6c7fa42f2705b96f9c6939f64414cdff18bd35e7ea9763b9d7b23d4a1dc8be68` |
| `several.kurumi`  | 197,608 bytes (3 × 65,536 + 1,000), same rule  | `40602b124f7d64f151f641d9f4103e9deccc3fd28009d6784dbd5f0c4ccb8dd6` | `8a9ddd0bdda13f0d79fc517eac65833e60e4f6dca3c5e82035c52552aa048bfd` |

`one-full` is a single, full-size final record; `several` is three full records and a final record of 1,000 bytes. The files are in [`testdata/vectors`](testdata/vectors). The two small ones in hex:

`empty.kurumi`:

```
4b5552554d4900000100200001000200000100000020ea0a76aeab2a0938c306
453dfe2bb60cfa976568555ee630df5141f1cf97e9310100000000e3c65e5221
e6d06accf4c70135f9df4c
```

`short.kurumi`:

```
4b5552554d490000010020000100020000010000002081b10ef6583401fd961b
d762256ff3bcc43d5b91659f0cc948f6bf3c6b2157680100000013d723431267
5ff0524a931b7681aca5d5fde08dfaa4d02f7a4adf36d50207fb2281ceae
```

All four vectors decrypt to the expected plaintext with kurumi (`go test -run TestVectors`) and with [pyhpke](https://github.com/dajiaji/pyhpke) 0.6.5, a pure-Python RFC 9180 implementation:

```sh
pip install pyhpke==0.6.5
cd testdata/vectors
key=$(printf 'kurumi test vector' | sha256sum | cut -d' ' -f1)
for v in empty short one-full several; do python decrypt.py "$key" $v.kurumi | sha256sum; done
```
