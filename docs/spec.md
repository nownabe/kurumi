# Requirements: kurumi — an append-only backup writer for Cloud Storage

A CLI that packs directories into one archive, encrypts it to a public key, and uploads it to a Google Cloud Storage bucket as a **new object that never replaces or deletes anything**. It is meant to run on a server that may one day be compromised. **The top priority is that a stolen upload credential from that server cannot be used to destroy existing backups.** The second priority is that a backup can be opened years later without this tool.

Name: `kurumi` (a walnut that a squirrel buries for later). License: MIT (tentative). File extension: `.kurumi`.

## 1. Threat model

### What kurumi protects against

- The server running kurumi is compromised and the attacker obtains everything on it: the upload credential, the public key, and the kurumi binary
- With that, the attacker must not be able to **read, list, overwrite, or delete** existing backup objects through the stolen credential, and must not be able to **decrypt** existing backups (the server holds only the public key)

### What kurumi does not protect against (state these in the README)

- **Stopping or poisoning future backups.** An attacker can stop kurumi from running, or upload well-formed backups with arbitrary contents (anyone with the public key can produce a valid file; HPKE base mode authenticates integrity, not the sender). If this goes unnoticed until the bucket's lifecycle rules expire every good backup, nothing good is left. Detecting it is the operator's job: alert when no successful run has been seen for a set time, and run restore tests that check application-level contents (section 5, `verify` and `restore --verify-only`). Retention must be longer than the time it takes to notice. Note that kurumi's own success line (section 5) is produced on the server the attacker controls, so an alert on a missing success line catches operational failures only; poisoning is caught only by restore tests scheduled and run from elsewhere
- **Data that is still on the server.** Offline decryption keys do not protect plaintext that is still present on the compromised server, or future backups if the attacker replaces the configured public key
- **Cost abuse.** The attacker can upload large amounts of data to the bucket
- **Anyone with administrative access to the bucket or project.** Retention settings, lifecycle rules, and restore credentials must be managed from somewhere other than the server

### Resulting design

- The server's credential is a dedicated service account bound **only on the bucket, only with `roles/storage.objectCreator`** (or a custom role containing only `storage.objects.create`). The predefined role also contains a few unrelated permissions (e.g. `orgpolicy.policy.get`, multipart-upload permissions), but none that read, list, overwrite, or delete objects. Creating a new object requires only `storage.objects.create`; overwriting an existing one would also require `storage.objects.delete`
- `push` calls **only the operations in section 6's push allowlist**. It never reads, lists, or modifies objects or buckets, not even to check whether a name exists. Reading (`list`, `restore`) is a separate command used on another machine with a separate read-only credential; the server never has that credential, so the read code in the same binary gives it nothing
- Deleting old backups is the bucket's job (lifecycle rules, optionally a locked retention policy). kurumi has no prune or delete command and will not get one
- Every backup is a full, self-contained archive. There is no deduplication or incremental mode, so deleting any object by age never breaks another one

## 2. Assumptions and constraints

- Use **only the Go standard library**. `go.mod` has no `require` lines (no `golang.org/x/...`, no cloud SDK). Minimum Go version: 1.26 (the release that added `crypto/hpke`)
- Do not design cryptography. Use HPKE (RFC 9180) **base mode** from `crypto/hpke` exactly as in section 3
- Stream throughout; memory use must not grow with input size. Must handle at least tens of GiB
- Every network request has a deadline. Response bodies are read with a size limit

## 3. File format (v1)

### Header (22 bytes, then `enc`)

| Offset | Length | Field | v1 value |
| --- | --- | --- | --- |
| 0 | 8 | magic | ASCII `KURUMI` + `0x00 0x00` |
| 8 | 1 | version | `0x01` |
| 9 | 2 | kem_id | `0x0020` = DHKEM(X25519, HKDF-SHA256) |
| 11 | 2 | kdf_id | `0x0001` = HKDF-SHA256 |
| 13 | 2 | aead_id | `0x0002` = AES-256-GCM |
| 15 | 1 | compression | `0x00` = none, `0x01` = gzip |
| 16 | 4 | chunk_size | plaintext bytes per record (uint32). Allowed: 65,536 to 16,777,216. Default 1,048,576 |
| 20 | 2 | enc_len | must be 32 |
| 22 | 32 | enc | HPKE encapsulated key |

All integers are big-endian.

- The HPKE `info` is the **22-byte prefix** (offsets 0–21). The writer builds it before calling `hpke.NewSender` (v1 knows `enc_len` is 32 in advance). `enc` is not in `info`; this is fine because DHKEM already binds `enc` into the key schedule
- A reader validates magic, version, the exact v1 suite, compression value, chunk_size range, and `enc_len == 32` **before** allocating buffers or starting HPKE. Anything else is rejected with a message naming the field

### Records (after the header)

Each record is:

| Length | Field |
| --- | --- |
| 1 | flag: `0x00` = more records follow, `0x01` = final record |
| 4 | plen: plaintext length of this record (uint32) |
| plen + 16 | `Sender.Seal(aad = flag ‖ plen, plaintext)` |

- One HPKE context per file. Records are sealed and opened strictly in order; HPKE's sequence number provides the nonce, so reordering, dropping, or duplicating records fails
- A non-final record has `plen == chunk_size` exactly. The final record has `0 ≤ plen ≤ chunk_size`
- There is **exactly one** final record, and it is the last thing in the file. A reader rejects: EOF before the final record (truncation), any byte after it (trailing data), and any length that breaks these rules
- Canonical writing: the writer holds back the current record until it knows whether more input follows. When input ends, the held record is written as final. So an input that is an exact multiple of chunk_size ends with a full-size final record, and an empty input is a single final record with `plen = 0`

### Plaintext

- A POSIX tar stream (`archive/tar`, PAX format), optionally gzip-compressed as a **single** gzip member (`compression = 0x01`). Compression is on by default; `--no-compress` writes `0x00`
- Readers consume every layer to the physical end: the tar end-of-archive marker, then only zero padding up to the end of the decompressed stream; gzip with multistream disabled and its trailer checked, then **zero further plaintext bytes** (a second gzip member or any garbage after the first member is rejected; keep bytes the gzip reader buffered ahead when checking this); then the final record. Stopping when the tar reader reports EOF is a bug, because the final record would never be authenticated

### Keys

- Private key file: one line `kurumi-private-key-v1:` + standard base64 (with padding) of the 32 bytes from `(*ecdh.PrivateKey).Bytes()` for X25519. Public key: `kurumi-public-key-v1:` + base64 of `(*ecdh.PublicKey).Bytes()`
- Parsers accept exactly one line, optionally ending in `\n` or `\r\n`, and require exactly 32 decoded bytes

## 4. Configuration file

Backup targets are declared in a configuration file, so the server that pushes and the machine that restores read the same file. **The file contains no secrets**: credentials and private keys are always given separately (section 6 and `--identity`), so the same file can be kept in version control. **The restore machine must take the file from a trusted source (e.g. the repository), never copy it back from the server**: an attacker who controls the server can change the bucket, prefix, or recipient in the server's copy and misdirect restore tests.

- Format: JSON (`encoding/json`; the standard library has no YAML or TOML parser). Strict parsing: exactly one JSON object followed by EOF; keys must match the documented spelling exactly (case-sensitive); unknown keys, duplicate keys, and `null` values are errors. `encoding/json` alone is case-insensitive and allows duplicates, so check the keys with a token-level pass first
- Path, first match wins: `--config <file>`; `$KURUMI_CONFIG`; the default location `$XDG_CONFIG_HOME/kurumi/config.json` (if `XDG_CONFIG_HOME` is unset: `~/.config/kurumi/config.json` on Linux and macOS, `%AppData%\kurumi\config.json` on Windows). If none exists, fail and name the paths that were tried. Relative paths inside the file are resolved from the file's directory
- Because the default location is per user, a person's PC can keep all their targets in one file and run `kurumi push <name>` / `kurumi restore <name>` with no flags, and on a server each service user (e.g. one user per application) has its own file containing only its own targets. A user never needs to read another user's configuration

```json
{
  "version": 1,
  "targets": {
    "app": {
      "bucket": "example-app-backup",
      "prefix": "app",
      "paths": ["/srv/app/dump"],
      "exclude": ["dump/tmp/*"],
      "recipient": "kurumi-public-key-v1:...",
      "compress": true
    },
    "notes": {
      "output_dir": "/mnt/usb/backups/notes",
      "paths": ["/home/alice/notes"],
      "recipient_file": "keys/notes.pub"
    }
  }
}
```

| Key | Required | Meaning |
| --- | --- | --- |
| `version` | yes | `1` |
| `targets` | yes | Map from target name (`[a-z0-9-]{1,63}`) to target |
| `bucket` | one of `bucket` / `output_dir` | Cloud Storage bucket |
| `prefix` | no | Object name prefix (default: the target name). 1–200 characters of `[A-Za-z0-9._/-]`, no leading or trailing `/`, no `//`, no `.` or `..` segment. Objects are `<prefix>/<name>` |
| `output_dir` | one of `bucket` / `output_dir` | Local directory for the encrypted files instead of a bucket |
| `paths` | yes | Directories to archive (absolute) |
| `exclude` | no | Glob patterns (see archiving rules) |
| `recipient` / `recipient_file` | exactly one | Public key, inline or as a file |
| `compress` | no | Default `true` |
| `chunk_size` | no | Default 1,048,576 (section 3 range) |

- `kurumi config check [--config <file>]` validates the file (types, required keys, exactly one of each pair, readable recipient, valid patterns, absolute paths) and touches nothing else. It exits `0` or `1` with every problem listed
- Command-line flags do not override configuration values. One source of truth per target

## 5. Commands

### Where the private key lives

The private key is expected to live in a **password manager**, not in a file on disk. kurumi never needs it as a stored file: every command that takes `--identity` accepts `-` (read the key from standard input) or any readable path, including the `/dev/fd/N` paths that shells create for process substitution. kurumi does not require the identity to be a regular file. Nothing in kurumi is specific to one password manager. README example ([pass](https://www.passwordstore.org/), the standard Unix password manager):

```sh
pass show kurumi/app | kurumi restore --identity - app | tar -x
kurumi restore --identity <(pass show kurumi/app) app | tar -x
```

- The key is read once, in full (at most 4 KiB), before any other work; then the buffer is overwritten with zeros as far as Go allows
- Keys are never taken from environment variables or command-line arguments (they leak into process listings and shell history)

### `kurumi keygen [-o <private-key-file>]`

- Without `-o`, write the private key to **standard output** so it can be piped into a password manager without touching disk. If standard output is a terminal, refuse (so the key is not shown on screen or kept in scrollback) and say how to pipe it
- With `-o <file>`: create the file exclusively (fail if it exists, do not follow a symlink at that path) with mode 0600 from creation, write, and check the close error. On Windows, file permissions are not set; print a warning saying so
- The public key is printed on standard error in both cases, and can be obtained again with `public-key`

### `kurumi public-key --identity <private-key-file | ->`

- Print the public key that belongs to the private key, on standard output (for writing it into a configuration file)

### `kurumi push [--config <file>] [--dry-run] <target>`

Pushes one target. Credentials for a bucket target come from section 6 (an upload-only credential).

Archiving rules:

- Each entry of `paths` becomes a top-level directory in the archive named by the base name of its cleaned path. Two paths with the same base name are an error. The filesystem root is rejected. A path that is itself a symlink is rejected (configure the real path)
- Symlinks are stored as symlinks (never followed). Hard links are stored as separate regular files. Regular files, directories, and symlinks are the only supported types; any other type (device, socket, FIFO) is an error unless excluded
- Stored metadata: path, type, mode bits, modification time, numeric uid/gid. Not stored: names of owners, xattrs, ACLs
- `exclude` patterns match the archive path (e.g. `data/tmp/*`) with `path.Match`. An excluded directory is skipped entirely. Malformed patterns are rejected before any file is read
- For an `output_dir` target, the output file and its temporary file are skipped by file identity (device and inode) if they fall inside a path being archived
- A file that cannot be read, disappears, or changes size while being read is an **error**, not a warning. Backups that quietly miss files are worse than failed ones
- kurumi reads a live filesystem; the result is not a snapshot. The README says to stop or dump the application first where consistency matters

Output:

- Name of the backup: `<UTC yyyymmddThhmmssZ>-<8 random hex>.kurumi`. In a bucket it is `<prefix>/<name>`; in `output_dir` it is `<output_dir>/<name>`
- Bucket targets upload following section 6
- `output_dir` targets never overwrite. Write to a temporary file created exclusively with mode 0600 in the same directory, check write, sync, and close errors, then publish with `os.Link(temp, final)` (fails if `final` exists, no race) and remove the temporary file. `os.Rename` is not used because it replaces an existing file
- `--dry-run`: produce the full encrypted stream into `io.Discard`, report the size, write and upload nothing
- On success, print **one line of JSON to standard output** and nothing else there: `{"target": "<name>", "object": "<name or path, empty for dry run>", "dry_run": <bool>, "bytes": <size of the encrypted file>, "files": <number of regular files archived>, "started_at": "<RFC 3339>", "finished_at": "<RFC 3339>"}`. Turning this into metrics, log alerts, or files is the caller's job
- Progress and errors go to standard error, one line per event (for journald)
- Exit codes: `0` success; `1` failure, nothing was finalized; `2` **outcome unknown** (the upload may or may not have been finalized; see section 6); `3` **the backup was finalized but the success line could not be written** (e.g. a broken stdout pipe). The object name is also logged to standard error. Callers must not retry automatically on `2` or `3`

### Backup names

- A backup name matches exactly `^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\.kurumi$` with a valid UTC date and time. Anywhere a user gives a name, only this form is accepted (not a path or full object key); kurumi builds the object key or local path itself
- `list` and `restore` consider only **immediate children** of the target's location whose names match this form; anything else (nested objects, other files) is ignored. Order: by the timestamp, then by the random part, both ascending. No matching backup is an error (exit `1`)

### `kurumi list [--config <file>] <target>`

- List the backups of a target, oldest first: name, size, creation time. For a bucket target this needs a **read credential** (section 6); for `output_dir` it reads the directory
- `--format json` prints one JSON object per line

### `kurumi restore [--config <file>] --identity <private-key-file | -> <target> [<name>]`

- Restore one backup of a target: the named one, or the **newest** (by the timestamp in the name) if omitted. The chosen name is printed to standard error first
- Steps: copy the backup into a temporary file created exclusively with mode 0600 (in `$TMPDIR`, removed afterwards, also on failure). For bucket targets this is the download, checked against the object's CRC32C (section 6); for `output_dir` targets it is a copy of the local file (which must be a regular file, not a symlink), so the bytes cannot change between verifying and decrypting. Then run the full `verify` on the temporary file; **only if that succeeds**, decrypt the same temporary file to standard output
- A failure while copying, checking, or verifying writes **nothing** to standard output. A failure after decrypting has started (e.g. a closed pipe) can leave partial output; the exit status is the only signal of success
- Extraction is left to `tar`, as with `decrypt`: `kurumi restore ... | tar -x` (see README for safe extraction)
- `--verify-only`: download and verify, print the `verify` report, write no archive. This is the building block for scheduled restore tests run from another machine
- For `output_dir` targets the file is read from the directory instead of downloaded

### `kurumi decrypt --identity <private-key-file | -> [<file>]`

- For a file obtained some other way. Decrypt `<file>` (standard input if omitted; with `--identity -`, `<file>` is required because standard input carries the key) and write the tar stream (decompressed) to standard output
- Output is written as records are authenticated, so **on failure, standard output may already contain a partial archive**. The exit status is the only signal of success. Prefer `restore`, or run `verify` first
- There is no option to extract files. Extraction is left to `tar`

### `kurumi verify --identity <private-key-file | -> [<file>]`

- `<file>` is required with `--identity -`, as for `decrypt`. Decrypt and read the whole file through every layer (section 3) without writing anything. Report file count, total bytes, and the newest modification time inside, as diagnostics
- `verify` proves the file is well-formed and was encrypted to this key. It does **not** prove who made it or that its contents are real (see section 1). Restore tests must check application-level contents against something trusted

### Common

- `--version` prints the version and commit
- Messages are in English. Key material, JWTs, access tokens, and upload session URIs never appear in output or logs

## 6. Talking to Google Cloud

### Authentication

- Credentials are never in the configuration file. A service account key JSON file from `--credentials`, otherwise `GOOGLE_APPLICATION_CREDENTIALS`. Use different service accounts for pushing (objectCreator only, on the server) and for `list` / `restore` (`roles/storage.objectViewer` only, on the restore machine). Require `type == "service_account"`, `client_email`, `private_key` (PEM, PKCS#8 RSA)
- Build a JWT signed with RS256 (unpadded base64url): `iss` = `client_email`, `scope` = `https://www.googleapis.com/auth/devstorage.read_write` for `push`, `https://www.googleapis.com/auth/devstorage.read_only` for `list` and `restore`, `aud` = `https://oauth2.googleapis.com/token`, `iat` = now, `exp` = now + at most 1 hour. No `sub`. Exchange it at `https://oauth2.googleapis.com/token` (fixed; the `token_uri` in the JSON must equal this or the run fails)
- Fetch a new token if the current one has less than 5 minutes left
- HTTPS only. Do not follow redirects on the token or upload endpoints

### Allowed operations (the complete list)

`push`:

1. Token exchange: `POST https://oauth2.googleapis.com/token`
2. Start a resumable upload: `POST https://storage.googleapis.com/upload/storage/v1/b/<bucket>/o?uploadType=resumable&name=<name>&ifGenerationMatch=0`
3. Send data to the session URI: `PUT` with `Content-Range`
4. Ask the session how much it has received: `PUT` with `Content-Range: bytes */*` (or `bytes */<total>` once known)

`list` and `restore` (bucket targets):

1. Token exchange, as above
2. List objects under the prefix: `GET https://storage.googleapis.com/storage/v1/b/<bucket>/o?prefix=<prefix>/` (following `pageToken`)
3. Download one object: `GET https://storage.googleapis.com/storage/v1/b/<bucket>/o/<object>?alt=media&generation=<generation>`, using the `generation` and `crc32c` from the listing. The CRC32C is the base64 of the big-endian 4-byte value; a missing or malformed value, or a mismatch, fails the restore

All URLs use the fixed scheme and host shown; bucket and object names are inserted with path escaping (`url.PathEscape`), query values with `url.QueryEscape`. No authenticated request in any command follows a redirect. Nothing else, in any command. Tests (section 8) fail if any other request is made.

### Upload protocol

- Upload buffer: 8 MiB by default, a multiple of 256 KiB (Cloud Storage requires non-final chunks to be multiples of 256 KiB). Unrelated to the record size in section 3
- Non-final chunks are sent with an unknown total (`bytes a-b/*`). **The last buffer is held back until every producer (file reading, tar close, gzip close, final record) has finished without error.** Only then is it sent with the exact total, which finalizes the object. If anything fails before that, kurumi stops sending and exits `1`; the object is never finalized
- An abandoned session is not visible as an object, but stays usable until it expires (up to a week). kurumi does not cancel it. Session URIs are bearer capabilities, so they are never logged
- Bytes are kept in memory until the server acknowledges them, so they can be resent. Every incomplete response (`308`) is checked: its `Range` header says how much the server actually has, which may be less than was sent (or absent, meaning nothing). Resend from there. On an error or timeout during a data PUT, ask the session for its status and resume from what it has. Retry with backoff a bounded number of times
- If the final chunk was sent and the response was lost, ask the session for its status. If it reports the object as finalized, that is success. If the status cannot be determined, exit `2` (outcome unknown). **Never restart under a new name once any data has been sent**
- A `412` on the start request (the name is already taken) leads to a new random name, up to 3 times. A collision reported only at finalization cannot be retried (the stream is consumed): exit `1` with a message saying so. Whether a name collision under a create-only credential returns `412` or `403`, and whether it is checked at the start or at finalization, is **not confirmed**; check it against real Cloud Storage and handle what is observed

## 7. Release and documentation

- Pushing a tag builds with GitHub Actions and publishes binaries (`CGO_ENABLED=0`, `-trimpath`) for `linux/amd64`, `linux/arm64`, `darwin/arm64`, `windows/amd64`, plus `SHA256SUMS` covering every binary. The README says that checksums downloaded from the same place detect corruption, not a compromised release
- `README.md`: section 1 in plain words, including what is not protected. Bucket setup: dedicated service account, bucket-level binding only, uniform bucket-level access, lifecycle rule, optional locked retention policy, soft delete, and checking that no other grant (project-level or inherited) gives the account more. A sample configuration file. Usage, including a systemd example that sends the success line to the journal and alerts when it has not appeared for a set time. Restore steps: `kurumi restore <target> | tar -x` **as an unprivileged user, into a new empty directory, without restoring ownership** (e.g. GNU tar `--no-same-owner --no-same-permissions`), and inspect the result before copying anything into place. `verify` does not make paths, links, or permissions in an attacker-made archive safe; how well `tar` resists such archives depends on the implementation and options. How to build (`go build` must be enough)
- `FORMAT.md`: section 3 on its own, with **step-by-step decryption using any RFC 9180 implementation**, and test vectors (section 8). Name at least one non-Go HPKE implementation that was actually used to decrypt the vectors
- `SECURITY.md`: how to report vulnerabilities

## 8. Tests

- Round trips: empty directory; one empty file; many small files; a file spanning several records; inputs whose compressed or uncompressed size is an exact multiple of chunk_size; with and without compression
- Format rejection: every byte of the header, flags, lengths, ciphertexts, and tags flipped one at a time; records dropped, duplicated, reordered; EOF at every record boundary and inside records; bytes after the final record; a final flag on a non-last record; `plen` out of range; unknown suite, compression, chunk_size, `enc_len`
- Late authentication: a file where the tar end comes before a damaged or missing final record must fail `verify` and `decrypt` (exit status), not succeed
- Gzip boundary: a second gzip member, and garbage after the first member, are both rejected
- Wrong private key fails
- Test vectors in `FORMAT.md` (empty input, short, exactly one full record, several records) decrypt to the expected plaintext with kurumi and with the named non-Go implementation
- Archiving: duplicate base names rejected; symlink stored, not followed; special file rejected; file that changes size while read rejected; exclude patterns
- Upload, against a fake server built with `net/http/httptest`: only the allowlisted requests are made; a `308` that acknowledges fewer bytes than sent, or has no `Range`, leads to resending the rest; total sizes that are exact multiples of the upload buffer; `ifGenerationMatch=0` is on the start request; non-final chunks are 256 KiB multiples; a failure at any producer stage (including tar close and gzip close) never sends the final chunk; a lost response on a data chunk resumes from the status; a lost response on the final chunk is resolved by status or exits `2`; a `412` on start leads to a new name; nothing secret is logged
- Configuration: unknown keys, both or neither of `bucket`/`output_dir` and of `recipient`/`recipient_file`, relative `paths`, bad target names, and malformed patterns are rejected by `config check` and by every command; relative `recipient_file` resolves from the file's directory
- Configuration lookup: `--config` beats `$KURUMI_CONFIG` beats the default location; `XDG_CONFIG_HOME` is honoured; a missing file names every path tried
- Configuration: case variants, duplicate keys, `null`, trailing data after the object, and invalid prefixes are rejected
- Names: `restore` refuses names that are not in the backup-name form (paths, `../`, full keys); a symlink or non-regular file in `output_dir` is refused; a local file changed after the copy does not change what is emitted
- `list` and `restore` against the fake server: only the read allowlist is used; newest selection by name; a CRC32C mismatch fails; a failed verify writes nothing to standard output and removes the temporary file
- Identity input: `--identity -` reads standard input; a `/dev/fd/N` path (process substitution) works; a key over 4 KiB is rejected; `decrypt` and `verify` without `<file>` are rejected with `--identity -`; `keygen` refuses to write the private key to a terminal; `public-key` matches the key `keygen` printed
- Keys: exclusive creation, symlink at the target path refused, parsing rules
- Local output: an existing destination (including one created concurrently) is never replaced; the output file inside an input directory is not archived
- Arguments: symlink directory argument and filesystem root rejected; malformed exclude pattern rejected before reading; dry-run JSON has `dry_run: true`; exit `3` when standard output is closed after finalizing
- CI runs `go vet` and `go test ./...` with Go 1.26 on Linux and Windows

## 9. Out of scope

- Any request outside section 6's allowlists
- Deleting or pruning backups
- Secrets in the configuration file (credentials and private keys are always separate)
- Pushing several targets in one run (call `push` once per target)
- Extracting files (use `tar`)
- Writing metrics or status files (the caller handles the standard-output line)
- Deduplication, incremental backups, snapshots that share data
- Backends other than Cloud Storage in v1
- Credential types other than a service account key file
- Encrypting the private key file (keep it in a password manager instead)
- Integration with a specific password manager
- Scheduling (systemd timers or cron)
- A bundle archive of all binaries and sources

## 10. Definition of done

- All commands and tests above are in place and CI passes
- Against a real bucket with a dedicated objectCreator-only service account: `push` succeeds; the same credential is refused when trying to read, list, delete, and overwrite (checked manually and written in the README); the name-collision behaviour in section 6 is observed and handled
- With the same configuration file and a separate objectViewer-only credential, `list` shows the object, `restore --verify-only` passes, and `restore | tar -x` restores the files
- The test vectors decrypt with a non-Go HPKE implementation

