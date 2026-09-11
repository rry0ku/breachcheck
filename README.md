# breachcheck

A single-file bash CLI that checks whether a password has appeared in a known
data breach, using [Have I Been Pwned](https://haveibeenpwned.com)'s free
Pwned Passwords API, without ever sending your password, or even your full
password hash, over the network.

## How it works

Your password is hashed locally (SHA1 by default, or NTLM with `-n`). Only
the first 5 characters of that hash are sent to the API. The server responds
with every hash in its dataset that shares that same 5-character prefix,
typically hundreds of them, and the script checks locally whether your exact
hash is among them.

This is the [k-anonymity model](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/)
HIBP and Cloudflare designed specifically so tools like this one don't have
to be trusted with your actual credentials. The server learns "someone
queried this bucket," never which specific password you checked.

## Requirements

- `bash`
- `curl`
- `sha1sum` (part of coreutils, present by default on virtually all Linux systems)
- `openssl` and `iconv` — only needed for `-n`/`--ntlm` mode

## Usage

```bash
chmod +x checkpwned.sh

./breachcheck.sh                        # interactive check, visible input
./breachcheck.sh -h                     # interactive check, hidden input
./breachcheck.sh -n                     # check against NTLM hashes instead of SHA1
./breachcheck.sh -f wordlist.txt        # batch-check every line in a file
./breachcheck.sh --stdin --json         # read one password from stdin, output JSON
echo "hunter2" | ./breachcheck.sh --stdin
```

### Flags

| Flag | Description |
|---|---|
| `-h, --hidden` | mask password input while typing |
| `-n, --ntlm` | check NTLM hashes instead of SHA1 |
| `-f, --file PATH` | batch-check one password per line from a file |
| `--stdin` | read a single password from stdin (for piping/scripting) |
| `-j, --json` | machine-readable JSON output |
| `-q, --quiet` | suppress decorative output, print result only |
| `--no-color` | disable ANSI colors |
| `--help` | show usage and exit |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | password(s) clear |
| `1` | at least one password matched a known breach |
| `2` | error (network failure, bad input, missing dependency, etc.) |

Meaningful exit codes make this easy to drop into a script or CI pipeline:

```bash
if ! ./checkpwned.sh --stdin -q <<< "$PASSWORD"; then
    echo "weak password, choose another"
fi
```

## Batch mode

Point `-f` at a wordlist and it checks every line, with a short delay between
requests, and prints a summary at the end:

```
┌─────────────────────────────────────┐
│ SUMMARY                             │
│ checked: 3   matched: 2   errors: 0 │
└─────────────────────────────────────┘
```

## Privacy notes

- The full password and full hash never leave your machine, only a 5-character
  hash prefix is sent per lookup.
- Requests include the `Add-Padding` header, which pads API responses so
  response size alone can't leak whether your bucket had a rare or common
  match count.
- This tool does query a third-party service (`api.pwnedpasswords.com`) over
  the network. If you need a fully offline/air-gapped check, download the
  full Pwned Passwords dataset separately and query it locally instead.

## License

MIT
