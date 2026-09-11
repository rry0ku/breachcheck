#!/usr/bin/env bash
set -euo pipefail

API_BASE="https://api.pwnedpasswords.com/range"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${FORCE_NO_COLOR:-0}" != "1" ]; then
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  RED=$'\033[38;5;203m'
  GREEN=$'\033[38;5;114m'
  YELLOW=$'\033[38;5;221m'
  CYAN=$'\033[38;5;80m'
  MAGENTA=$'\033[38;5;176m'
  GRAY=$'\033[38;5;244m'
  RESET=$'\033[0m'
else
  BOLD="" DIM="" RED="" GREEN="" YELLOW="" CYAN="" MAGENTA="" GRAY="" RESET=""
fi

QUIET=false
JSON=false
HIDDEN=false
NTLM=false
FROM_STDIN=false
BATCH_FILE=""
RATE_DELAY="0.5"

log() {
  [ "$QUIET" = true ] && return 0
  printf '%s\n' "$1" >&2
}
logf() {
  [ "$QUIET" = true ] && return 0
  printf "$@" >&2
}

visible_len() {
  local s=$1
  s=$(printf '%s' "$s" | sed -E 's/\x1b\[[0-9;]*m//g')
  (
    export LC_ALL=C.UTF-8 2>/dev/null
    printf '%s' "${#s}"
  )
}

box() {
  [ "$QUIET" = true ] && return 0
  local color=$1 width=0 line
  shift
  for line in "$@"; do
    local len
    len=$(visible_len "$line")
    [ "$len" -gt "$width" ] && width=$len
  done
  local border
  border=$(printf '─%.0s' $(seq 1 $((width + 2))))
  printf '%s┌%s┐%s\n' "$color" "$border" "$RESET"
  for line in "$@"; do
    local len
    len=$(visible_len "$line")
    local pad=$((width - len))
    printf '%s│ %s%*s %s│%s\n' "$color" "$line" "$pad" "" "$color" "$RESET"
  done
  printf '%s└%s┘%s\n' "$color" "$border" "$RESET"
}

die() {
  if [ "$JSON" = true ]; then
    printf '{"error":"%s"}\n' "$(printf '%s' "$1" | sed 's/"/\\"/g')"
  else
    printf '\n%s✖ %s%s\n\n' "$RED$BOLD" "$1" "$RESET" >&2
  fi
  exit 2
}

usage() {
  cat >&2 <<EOF

Usage: $(basename "$0") [OPTIONS]

  -h, --hidden        mask password input
  -n, --ntlm          check against NTLM hashes instead of SHA1
  -f, --file PATH     batch-check one password per line from a file
      --stdin         read a single password from stdin (for piping/scripts)
  -j, --json          machine-readable JSON output
  -q, --quiet         suppress all decorative output, print result only
      --no-color      disable ANSI colors
      --help          show this help and exit

Exit codes:
  0  password(s) clear
  1  at least one password matched a known breach
  2  error (network failure, bad input, etc.)

Examples:
  $(basename "$0")                    interactive check, visible input
  $(basename "$0") -h                 interactive check, hidden input
  $(basename "$0") -f passwords.txt   batch-check a wordlist
  echo "hunter2" | $(basename "$0") --stdin --json

EOF
  exit 2
}

command -v sha1sum >/dev/null 2>&1 || die "sha1sum not found"
command -v curl >/dev/null 2>&1 || die "curl not found"
command -v grep >/dev/null 2>&1 || die "grep not found"

while [ $# -gt 0 ]; do
  case "$1" in
  -h | --hidden)
    HIDDEN=true
    shift
    ;;
  -n | --ntlm)
    NTLM=true
    shift
    ;;
  -f | --file)
    [ -n "${2:-}" ] || die "--file requires a path"
    BATCH_FILE="$2"
    shift 2
    ;;
  --stdin)
    FROM_STDIN=true
    shift
    ;;
  -j | --json)
    JSON=true
    shift
    ;;
  -q | --quiet)
    QUIET=true
    shift
    ;;
  --no-color)
    BOLD="" DIM="" RED="" GREEN="" YELLOW="" CYAN="" MAGENTA="" GRAY="" RESET=""
    shift
    ;;
  --help) usage ;;
  -*) die "unknown option: $1 (see --help)" ;;
  *) die "unexpected argument: $1 (see --help)" ;;
  esac
done

if [ "$NTLM" = true ]; then
  command -v openssl >/dev/null 2>&1 || die "NTLM mode requires openssl"
  command -v iconv >/dev/null 2>&1 || die "NTLM mode requires iconv"
  if printf 'x' | openssl dgst -md4 -provider legacy -provider default >/dev/null 2>&1; then
    MD4_ARGS=(-md4 -provider legacy -provider default)
  elif printf 'x' | openssl dgst -md4 >/dev/null 2>&1; then
    MD4_ARGS=(-md4)
  else
    die "NTLM mode needs MD4 support in openssl, unavailable on this system"
  fi
fi

compute_hash() {
  local pw=$1
  if [ "$NTLM" = true ]; then
    printf '%s' "$pw" | iconv -f UTF-8 -t UTF-16LE 2>/dev/null |
      openssl dgst "${MD4_ARGS[@]}" 2>/dev/null | awk '{print toupper($NF)}'
  else
    printf '%s' "$pw" | sha1sum | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]'
  fi
}

query_range() {
  local prefix=$1 mode_flag="" response rc
  [ "$NTLM" = true ] && mode_flag="?mode=ntlm"
  response=$(curl -sS --fail --max-time 10 --retry 2 --retry-delay 1 \
    -H "User-Agent: checkpwned-script" \
    -H "Add-Padding: true" \
    "${API_BASE}/${prefix}${mode_flag}" 2>/dev/null) && rc=0 || rc=$?
  if [ "${rc:-0}" -ne 0 ]; then
    return 1
  fi
  printf '%s' "$response" | tr -d '\r'
}

check_one() {
  local pw=$1
  local label=${2:-}
  [ -n "$pw" ] || {
    echo "SKIP::empty password"
    return
  }

  local hash prefix suffix
  hash=$(compute_hash "$pw")
  local expected_len=40
  [ "$NTLM" = true ] && expected_len=32
  if [ -z "$hash" ] || [ ${#hash} -ne "$expected_len" ]; then
    echo "ERROR::hash computation failed"
    return
  fi
  prefix="${hash:0:5}"
  suffix="${hash:5}"

  logf '%s→%s hash computed %s(%s…, rest hidden)%s\n' "$GRAY" "$RESET" "$GRAY" "$prefix" "$RESET"
  logf '%s→%s querying %sapi.pwnedpasswords.com%s with prefix %s%s%s only (full hash never leaves this machine)\n' \
    "$GRAY" "$RESET" "$BOLD" "$RESET" "$BOLD" "$prefix" "$RESET"

  local resp
  if ! resp=$(query_range "$prefix"); then
    echo "ERROR::API request failed for prefix $prefix"
    return
  fi

  local match
  match=$(printf '%s' "$resp" | grep -i -F "${suffix}:" | head -n 1 || true)

  if [ -n "$match" ]; then
    local count="${match##*:}"
    count="${count//[^0-9]/}"
    [ -n "$count" ] || count="0"
    echo "MATCH::$count"
  else
    echo "CLEAR::0"
  fi
}

print_result() {
  local result=$1 label=$2 reveal=${3:-}
  local status="${result%%::*}"
  local value="${result#*::}"

  case "$status" in
  MATCH)
    if [ "$JSON" = true ]; then
      printf '{"label":"%s","status":"matched","count":%s}\n' "$label" "$value"
    elif [ "$QUIET" = true ]; then
      printf 'MATCH\t%s\t%s\n' "$value" "$label"
    else
      local msg
      if [ -n "$reveal" ]; then
        msg="${GREEN}${reveal}${RESET}${RED} is seen ${YELLOW}${BOLD}${value}${RESET}${RED} time(s) in known breaches"
      else
        msg="seen ${YELLOW}${BOLD}${value}${RESET}${RED} time(s) in known breaches"
      fi
      printf '\n'
      box "$RED" "${BOLD}⚠ MATCHED${RESET}${RED}" "$msg"
      printf '\n%sChange this password if it is still in use.%s\n\n' "$DIM" "$RESET"
    fi
    return 1
    ;;
  CLEAR)
    if [ "$JSON" = true ]; then
      printf '{"label":"%s","status":"clear"}\n' "$label"
    elif [ "$QUIET" = true ]; then
      printf 'CLEAR\t0\t%s\n' "$label"
    else
      printf '\n'
      box "$GREEN" "${BOLD}✓ CLEAR${RESET}${GREEN}" "not found in known breaches"
      printf '\n'
    fi
    return 0
    ;;
  SKIP)
    [ "$JSON" = true ] && printf '{"label":"%s","status":"skipped","reason":"%s"}\n' "$label" "$value"
    return 0
    ;;
  ERROR | *)
    if [ "$JSON" = true ]; then
      printf '{"label":"%s","status":"error","message":"%s"}\n' "$label" "$value"
    else
      printf '%s✖ %s: %s%s\n' "$RED" "$label" "$value" "$RESET" >&2
    fi
    return 2
    ;;
  esac
}

if [ -n "$BATCH_FILE" ]; then
  [ -f "$BATCH_FILE" ] || die "'$BATCH_FILE' not found"
  [ -r "$BATCH_FILE" ] || die "'$BATCH_FILE' is not readable"

  if [ "$QUIET" = false ] && [ "$JSON" = false ]; then
    printf '\n'
    box "$MAGENTA" "${BOLD}${CYAN}COMPROMISED PASSWORD SCANNER${RESET}${MAGENTA}" "${DIM}batch mode — $(basename "$BATCH_FILE")${RESET}${MAGENTA}"
    printf '\n'
  fi

  TOTAL=0
  MATCHED=0
  ERRORS=0
  EXIT_CODE=0

  [ "$JSON" = true ] && printf '['
  FIRST=true

  while IFS= read -r pw || [ -n "$pw" ]; do
    [ -z "$pw" ] && continue
    TOTAL=$((TOTAL + 1))
    result=$(check_one "$pw" "line $TOTAL")
    unset pw

    if [ "$JSON" = true ]; then
      [ "$FIRST" = true ] || printf ','
      FIRST=false
    fi

    rc=0
    print_result "$result" "line $TOTAL" || rc=$?
    if [ "$rc" -eq 1 ]; then
      MATCHED=$((MATCHED + 1))
      EXIT_CODE=1
    fi
    if [ "$rc" -eq 2 ]; then ERRORS=$((ERRORS + 1)); fi

    sleep "$RATE_DELAY"
  done <"$BATCH_FILE"

  [ "$JSON" = true ] && printf ']\n'

  if [ "$QUIET" = false ] && [ "$JSON" = false ]; then
    printf '\n'
    box "$CYAN" "${BOLD}SUMMARY${RESET}${CYAN}" \
      "checked: ${BOLD}${TOTAL}${RESET}${CYAN}   matched: ${RED}${BOLD}${MATCHED}${RESET}${CYAN}   errors: ${YELLOW}${ERRORS}${RESET}${CYAN}"
    printf '\n'
  fi

  exit "$EXIT_CODE"
fi

if [ "$FROM_STDIN" = true ]; then
  IFS= read -r PASSWORD
else
  if [ "$QUIET" = false ] && [ "$JSON" = false ]; then
    printf '\n'
    box "$MAGENTA" "${BOLD}${CYAN}COMPROMISED PASSWORD SCANNER${RESET}${MAGENTA}" "${DIM}live HIBP k-anonymity API${RESET}${MAGENTA}"
    printf '\n'
  fi

  if [ "$HIDDEN" = true ]; then
    [ "$QUIET" = false ] && printf '%s?%s Enter password %s(hidden)%s: ' "$CYAN$BOLD" "$RESET" "$DIM" "$RESET"
    read -rs PASSWORD
  else
    [ "$QUIET" = false ] && printf '%s?%s Enter password: ' "$CYAN$BOLD" "$RESET"
    read -r PASSWORD
  fi
  [ "$QUIET" = false ] && printf '\n\n'
fi

[ -n "$PASSWORD" ] || die "no password entered."

REVEAL=""
[ "$HIDDEN" = false ] && REVEAL="$PASSWORD"

result=$(check_one "$PASSWORD" "password")
unset PASSWORD

rc=0
print_result "$result" "password" "$REVEAL" || rc=$?
unset REVEAL
exit "$rc"
