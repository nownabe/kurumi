# kurumi

kurumi (胡桃, a walnut that a squirrel buries for later) packs directories into one archive, encrypts it to a public key, and uploads it to a Google Cloud Storage bucket as a **new object that never replaces or deletes anything**.

It is built for servers that may one day be broken into. The server only ever holds an upload-only credential and a public key, so an attacker who takes over the server **cannot read, list, overwrite, delete, or decrypt** the backups already in the bucket. Every backup is a full, self-contained archive in a [documented format](FORMAT.md) that any RFC 9180 (HPKE) implementation can open, years from now, without kurumi.

kurumi is a single static binary that uses only the Go standard library.

## What kurumi protects, and what it does not

**Protected.** Assume the server running kurumi is compromised and the attacker has everything on it: the upload credential, the public key, the binary. They still cannot:

- read, list, overwrite, or delete existing backups through that credential, because it can only create new objects;
- decrypt existing backups, because the private key never lives on the server.

**Not protected.** Plan for these yourself:

- **Stopping or poisoning future backups.** The attacker can stop kurumi from running, or upload well-formed backups full of junk; anyone with the public key can make a valid file. If nobody notices until the bucket's lifecycle rule has expired every good backup, nothing good is left. So: alert when no successful run has been seen for a while (see [systemd](#running-it-with-systemd)), run restore tests from another machine that check the _contents_ (`kurumi restore --verify-only` plus your own application-level checks), and keep backups longer than it takes you to notice. kurumi's success line is printed on the server the attacker controls, so an alert on it only catches ordinary failures; poisoning is caught only by restore tests run from elsewhere.
- **Data still on the server.** Encryption does not protect plaintext that is still on the compromised server, or future backups if the attacker swaps the public key in the configuration.
- **Cost.** The attacker can upload large amounts of data to your bucket.
- **Anyone with admin access to the bucket or project.** Retention, lifecycle rules, and restore credentials must be managed from somewhere other than the server.

kurumi reads a live filesystem; a backup is not a snapshot. Where consistency matters, stop the application or dump its data (e.g. `pg_dump`) into a directory first, and back up that directory.

## Install

Download from the [latest release](https://github.com/nownabe/kurumi/releases/latest):

- `kurumi_<version>_<os>_<arch>[.exe]` — a binary for `linux` (`amd64`, `arm64`), `darwin` (`arm64`), or `windows` (`amd64`)
- `SHA256SUMS` — SHA-256 checksums of every file in the release

### Verify the download

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

On macOS use `shasum -a 256 -c SHA256SUMS --ignore-missing`. On Windows, compare the output of `Get-FileHash <file>` in PowerShell with the line for that file in `SHA256SUMS`.

`SHA256SUMS` sits in the same Release as the files it covers, so it catches a corrupted download but not a replaced one. To check that a file was built by this repository's release workflow from the tag `<tag>` (e.g. `v1.2.3`), verify its build provenance attestation with the [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify <file> --repo nownabe/kurumi \
  --signer-workflow nownabe/kurumi/.github/workflows/publish.yaml \
  --source-ref refs/tags/<tag>
```

Do this when you download a release. The keys that sign attestations rotate over the years, so `sha256sum -c SHA256SUMS` against a `SHA256SUMS` you kept remains the check that works offline and long-term.

### Build from source

```sh
go build
```

Go 1.26 or newer.

## Set up the bucket

Do this from an administrator's machine, never from the backup server.

```sh
PROJECT=my-project
BUCKET=example-app-backup

# Bucket with uniform bucket-level access (no per-object ACLs).
gcloud storage buckets create gs://$BUCKET --project=$PROJECT --location=asia-northeast1 --uniform-bucket-level-access

# Delete backups after 90 days. Choose a retention longer than it takes you to notice a problem.
echo '{"rule":[{"action":{"type":"Delete"},"condition":{"age":90}}]}' > lifecycle.json
gcloud storage buckets update gs://$BUCKET --lifecycle-file=lifecycle.json

# Optional: a retention policy stops anyone, even admins, from deleting objects early.
# Locking it is irreversible; test without --lock first.
gcloud storage buckets update gs://$BUCKET --retention-period=30d
# gcloud storage buckets update gs://$BUCKET --lock-retention-period

# Soft delete keeps deleted objects recoverable for a while (on by default, 7 days).
gcloud storage buckets update gs://$BUCKET --soft-delete-duration=30d

# Upload-only service account for the server, bound ONLY on this bucket.
gcloud iam service-accounts create kurumi-push --project=$PROJECT
gcloud storage buckets add-iam-policy-binding gs://$BUCKET \
  --member=serviceAccount:kurumi-push@$PROJECT.iam.gserviceaccount.com --role=roles/storage.objectCreator
gcloud iam service-accounts keys create push-key.json --iam-account=kurumi-push@$PROJECT.iam.gserviceaccount.com

# Read-only service account for the restore machine.
gcloud iam service-accounts create kurumi-restore --project=$PROJECT
gcloud storage buckets add-iam-policy-binding gs://$BUCKET \
  --member=serviceAccount:kurumi-restore@$PROJECT.iam.gserviceaccount.com --role=roles/storage.objectViewer
gcloud iam service-accounts keys create restore-key.json --iam-account=kurumi-restore@$PROJECT.iam.gserviceaccount.com
```

`roles/storage.objectCreator` allows creating objects but not reading, listing, overwriting, or deleting them (overwriting needs `storage.objects.delete`). It also carries a few unrelated permissions, none of which touch existing objects; a custom role with only `storage.objects.create` is even tighter.

**Check that nothing else grants the push account more**: no project-level or folder/organization-level role, no inherited binding. For example:

```sh
gcloud projects get-iam-policy $PROJECT --flatten=bindings --filter="bindings.members:kurumi-push@" --format="value(bindings.role)"   # must print nothing
gcloud storage buckets get-iam-policy gs://$BUCKET
```

Copy only `push-key.json` to the server. Keep `restore-key.json` on the restore machine.

## Keys

Generate a key pair on a trusted machine. The private key belongs in a password manager, not in a file. With [pass](https://www.passwordstore.org/):

```sh
kurumi keygen | pass insert -m kurumi/app      # the public key is printed on standard error
pass show kurumi/app | kurumi public-key --identity -   # print the public key again later
```

`kurumi keygen` refuses to print the private key to a terminal. `kurumi keygen -o key.txt` writes it to a new file with mode 0600 instead (on Windows, permissions are not set; protect the file yourself).

Every command that needs the private key takes `--identity <file>`, `--identity -` (standard input), or a `/dev/fd/N` path from process substitution. Keys are never read from environment variables or command-line arguments.

## Configuration

Targets are declared in a JSON file that contains **no secrets**, so it can live in version control and be shared by the server and the restore machine. **The restore machine must take the file from a trusted source** (e.g. the repository), never copy it back from the server: an attacker could change the bucket, prefix, or recipient there to misdirect your restore tests.

kurumi looks for the file at `--config <file>`, then `$KURUMI_CONFIG`, then `$XDG_CONFIG_HOME/kurumi/config.json` (`~/.config/kurumi/config.json` on Linux and macOS, `%AppData%\kurumi\config.json` on Windows), and uses the first that exists. On a server, give each service user its own file with only its own targets.

```json
{
  "version": 1,
  "targets": {
    "app": {
      "bucket": "example-app-backup",
      "prefix": "app",
      "paths": ["/srv/app/dump"],
      "exclude": ["dump/tmp"],
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

| Key                            | Required                       | Meaning                                                                                                                                     |
| ------------------------------ | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `version`                      | yes                            | `1`                                                                                                                                         |
| `targets`                      | yes                            | Map from target name (`[a-z0-9-]{1,63}`) to target                                                                                          |
| `bucket`                       | one of `bucket` / `output_dir` | Cloud Storage bucket                                                                                                                        |
| `prefix`                       | no                             | Object name prefix (default: the target name). `[A-Za-z0-9._/-]`, 1–200 characters, no leading/trailing `/`, `//`, `.` or `..`              |
| `output_dir`                   | one of `bucket` / `output_dir` | Local directory for the encrypted files instead of a bucket                                                                                 |
| `paths`                        | yes                            | Absolute paths of directories to archive. Each becomes a top-level directory named after its base name                                      |
| `exclude`                      | no                             | [`path.Match`](https://pkg.go.dev/path#Match) patterns matched against archive paths such as `dump/tmp/x`. An excluded directory is skipped |
| `recipient` / `recipient_file` | exactly one                    | Public key, inline or as a file                                                                                                             |
| `compress`                     | no                             | gzip the archive; default `true`                                                                                                            |
| `chunk_size`                   | no                             | Record size, 65,536 to 16,777,216; default 1,048,576                                                                                        |

Parsing is strict: unknown or misspelled keys, duplicate keys, `null`, and anything after the object are errors. Relative `output_dir` and `recipient_file` are resolved from the configuration file's directory. `kurumi config check` lists every problem and exits 0 or 1.

## Usage

```sh
kurumi push app                    # credentials: --credentials push-key.json or GOOGLE_APPLICATION_CREDENTIALS
kurumi push --dry-run app          # encrypt into nowhere and report the size
kurumi list app                    # needs the read-only credential; --format json for one object per line
kurumi restore --identity <(pass show kurumi/app) app | tar -x     # newest backup
kurumi restore --identity - app 20261101T030000Z-1a2b3c4d.kurumi < key.txt > backup.tar
kurumi restore --identity <(pass show kurumi/app) --verify-only app   # for scheduled restore tests
kurumi verify --identity key.txt backup.kurumi
kurumi decrypt --identity key.txt backup.kurumi | tar -t
```

Backups are named `<UTC yyyymmddThhmmssZ>-<8 random hex>.kurumi` and stored as `<prefix>/<name>` in the bucket or `<output_dir>/<name>` locally. `restore` and `list` accept only names in that form and consider only immediate children of the target location.

What gets archived: regular files, directories, and symlinks (stored as links, never followed), with path, mode, modification time, and numeric uid/gid. Hard links become separate files. Owner names, xattrs, and ACLs are not stored. Any other file type (socket, FIFO, device) is an error unless excluded. A file that cannot be read, disappears, or changes size while being read fails the backup; a backup that quietly misses files is worse than a failed one.

`push` prints exactly one line of JSON on standard output when it succeeds, and progress and errors on standard error, one line per event:

```json
{
  "target": "app",
  "object": "app/20261101T030000Z-1a2b3c4d.kurumi",
  "dry_run": false,
  "bytes": 1048576,
  "files": 12,
  "started_at": "2026-11-01T03:00:00Z",
  "finished_at": "2026-11-01T03:00:04Z"
}
```

| Exit code | Meaning                                                                                                    |
| --------- | ---------------------------------------------------------------------------------------------------------- |
| 0         | Success                                                                                                    |
| 1         | Failure; nothing was finalized                                                                             |
| 2         | Outcome unknown: the final upload chunk was sent but kurumi could not learn whether it was accepted        |
| 3         | The backup was finalized, but the success line could not be written (its name is logged on standard error) |

Do not retry automatically on 2 or 3; check the bucket from the restore machine instead.

`decrypt` writes the archive as it is authenticated, so on failure its output may already contain part of an archive; only the exit status says whether it succeeded. `restore` copies the backup to a private temporary file, verifies all of it, and only then decrypts, so a failed restore writes nothing. `verify` proves a file is well-formed and was encrypted to your key; it does **not** prove who made it or that the contents are real.

## Running it with systemd

```ini
# /etc/systemd/system/kurumi-app.service
[Unit]
Description=kurumi backup of app

[Service]
Type=oneshot
User=app
Environment=GOOGLE_APPLICATION_CREDENTIALS=/etc/kurumi/app-push-key.json
ExecStartPre=/usr/local/bin/app-dump /srv/app/dump
ExecStart=/usr/local/bin/kurumi push app
# Standard output (the success line) and standard error both go to the journal.
```

```ini
# /etc/systemd/system/kurumi-app.timer
[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
```

Alert when no success line has appeared for a set time, for example from a monitoring check:

```sh
journalctl -u kurumi-app --since -26h -o cat | grep -q '"target":"app"' || alert "kurumi app: no successful backup in 26h"
```

Remember that this check runs on the server; schedule real restore tests (`kurumi restore --verify-only` plus a check of the restored data) from another machine.

## Restoring safely

A backup may have been made by an attacker. Extract **as an unprivileged user, into a new empty directory, without restoring ownership**, and inspect the result before copying anything into place:

```sh
mkdir restore && cd restore
kurumi restore --identity <(pass show kurumi/app) app | tar -x --no-same-owner --no-same-permissions
```

`verify` does not make paths, links, or permissions in a hostile archive safe; how well `tar` resists such archives depends on the implementation and its options.

## Talking to Google Cloud

kurumi speaks to two hosts only, over HTTPS, without following redirects:

- `push`: token exchange at `https://oauth2.googleapis.com/token`, start a resumable upload with `ifGenerationMatch=0`, upload chunks, and ask the session how much it has. Nothing else, not even a check whether a name exists.
- `list` and `restore`: token exchange, list objects under the prefix, download one object (checked against its CRC32C).

The last upload chunk is held back until the whole archive has been produced without error, so a failure never finalizes a partial backup. Session URIs, tokens, and keys never appear in logs.

## Verification against real Cloud Storage

The definition of done includes checks that need a real bucket. Run them with a dedicated objectCreator-only account and record the results here.

| Check                                                                     | Result      |
| ------------------------------------------------------------------------- | ----------- |
| `push` succeeds                                                           | not yet run |
| The push credential is refused for read (`gcloud storage cat`)            | not yet run |
| The push credential is refused for list (`gcloud storage ls`)             | not yet run |
| The push credential is refused for delete (`gcloud storage rm`)           | not yet run |
| The push credential cannot overwrite (`gcloud storage cp` onto an object) | not yet run |
| Name collision: status code and whether it appears at start or finalize   | not yet run |
| `list`, `restore --verify-only`, `restore \| tar -x` with objectViewer    | not yet run |

kurumi currently treats a `412` on the start request as a collision (new name, up to 3 times), and a `412` or `403` on the final chunk as a collision it cannot recover from (exit 1).

## Development

```sh
mise run setup   # linters and the pre-commit secret scan
go vet ./... && go test ./...
go test -run TestVectors -update   # regenerate the test vectors (then update FORMAT.md)
```

Releases are automated: release-please maintains a release PR from [Conventional Commits](https://www.conventionalcommits.org/), and merging it tags the release and runs GoReleaser to publish the artifacts.

## License

MIT. See [SECURITY.md](SECURITY.md) to report a vulnerability.
