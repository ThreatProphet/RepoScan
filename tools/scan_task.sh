#!/usr/bin/env bash
set -u

usage() {
  printf 'Usage: %s [--rules DIR] [--ignore-config FILE] [--max-size BYTES] TARGET\n' "$0" >&2
}

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
RULE_DIR="$ROOT_DIR/rules"
IGNORE_CONFIG="$ROOT_DIR/config/scan_ignore.txt"
MAX_SIZE=2097152

while [ "$#" -gt 0 ]; do
  case "$1" in
    --rules)
      [ "$#" -ge 2 ] || { usage; exit 64; }
      RULE_DIR="$2"
      shift 2
      ;;
    --ignore-config)
      [ "$#" -ge 2 ] || { usage; exit 64; }
      IGNORE_CONFIG="$2"
      shift 2
      ;;
    --max-size)
      [ "$#" -ge 2 ] || { usage; exit 64; }
      MAX_SIZE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      printf 'Unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
    *)
      break
      ;;
  esac
done

[ "$#" -eq 1 ] || { usage; exit 64; }
TARGET="$1"

if ! command -v yara >/dev/null 2>&1; then
  printf 'error: yara CLI is required for %s\n' "$0" >&2
  printf 'hint: use python3 tools/scan_task.py for the built-in fallback scanner\n' >&2
  exit 69
fi

if [ ! -d "$TARGET" ] && [ ! -f "$TARGET" ]; then
  printf 'error: target does not exist: %s\n' "$TARGET" >&2
  exit 64
fi

if [ ! -d "$RULE_DIR" ]; then
  printf 'error: rules directory does not exist: %s\n' "$RULE_DIR" >&2
  exit 64
fi

if [ ! -f "$IGNORE_CONFIG" ]; then
  printf 'error: ignore config does not exist: %s\n' "$IGNORE_CONFIG" >&2
  exit 64
fi

TMP_FILE="$(mktemp "${TMPDIR:-/tmp}/tp-yara-files.XXXXXX")" || exit 70
cleanup() {
  rm -f "$TMP_FILE"
}
trap cleanup EXIT INT TERM

if [ -f "$TARGET" ]; then
  printf '%s\n' "$TARGET" > "$TMP_FILE"
else
  FIND_ARGS=("$TARGET" -type f -size "-${MAX_SIZE}c")
  while IFS= read -r pattern; do
    case "$pattern" in
      ''|'#'*) continue ;;
    esac
    FIND_ARGS+=(! -path "$TARGET/${pattern%/}")
  done < "$IGNORE_CONFIG"
  find "${FIND_ARGS[@]}" -print > "$TMP_FILE"
fi

MATCHES=0
while IFS= read -r file_path; do
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    MATCHES=$((MATCHES + 1))
    printf '%s\n' "$line"
  done <<EOF
$(yara -w "$RULE_DIR"/*.yar "$file_path" 2>/dev/null)
EOF
done < "$TMP_FILE"

if [ "$MATCHES" -gt 0 ]; then
  printf 'Findings: %s\n' "$MATCHES"
  exit 1
fi

printf 'No YARA findings.\n'
exit 0
