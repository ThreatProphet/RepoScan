#!/usr/bin/env bash
set -u

usage() {
  printf 'Usage: %s [--rules DIR] [--ignore-config FILE] [--max-size BYTES] [--color auto|always|never] TARGET\n' "$0" >&2
}

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
RULE_DIR="$ROOT_DIR/rules"
IGNORE_CONFIG="$ROOT_DIR/config/scan_ignore.txt"
MAX_SIZE=2097152
COLOR_MODE=auto

color_enabled() {
  case "$COLOR_MODE" in
    always) return 0 ;;
    never) return 1 ;;
    auto) [ -t 1 ] && [ -z "${NO_COLOR:-}" ] ;;
    *) return 1 ;;
  esac
}

if color_enabled; then
  RESET="$(printf '\033[0m')"
  BOLD="$(printf '\033[1m')"
  DIM="$(printf '\033[2m')"
  RED="$(printf '\033[31m')"
  YELLOW="$(printf '\033[33m')"
  GREEN="$(printf '\033[32m')"
  BLUE="$(printf '\033[34m')"
  GRAY="$(printf '\033[90m')"
else
  RESET=''
  BOLD=''
  DIM=''
  RED=''
  YELLOW=''
  GREEN=''
  BLUE=''
  GRAY=''
fi

rule_severity() {
  awk -v wanted="$1" '
    $0 ~ "^[ \t]*rule[ \t]+" wanted "([ \t\n\r{]|$)" { in_rule = 1 }
    in_rule && /severity[ \t]*=/ {
      value = $0
      sub(/^.*severity[ \t]*=[ \t]*"/, "", value)
      sub(/".*$/, "", value)
      print value
      exit
    }
    in_rule && /^[ \t]*}/ { in_rule = 0 }
  ' "$RULE_DIR"/*.yar 2>/dev/null
}

severity_color() {
  case "$1" in
    critical) printf '%s' "$RED" ;;
    high) printf '%s' "$YELLOW" ;;
    medium) printf '%s' "$BLUE" ;;
    low) printf '%s' "$GRAY" ;;
    *) printf '%s' "$GRAY" ;;
  esac
}

severity_label() {
  case "$1" in
    critical) printf 'CRITICAL' ;;
    high) printf 'HIGH' ;;
    medium) printf 'MEDIUM' ;;
    low) printf 'LOW' ;;
    *) printf '%s' "$1" | tr '[:lower:]' '[:upper:]' ;;
  esac
}

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
    --color)
      [ "$#" -ge 2 ] || { usage; exit 64; }
      case "$2" in
        auto|always|never) COLOR_MODE="$2" ;;
        *) printf 'Invalid color mode: %s\n' "$2" >&2; exit 64 ;;
      esac
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

if color_enabled; then
  RESET="$(printf '\033[0m')"
  BOLD="$(printf '\033[1m')"
  DIM="$(printf '\033[2m')"
  RED="$(printf '\033[31m')"
  YELLOW="$(printf '\033[33m')"
  GREEN="$(printf '\033[32m')"
  BLUE="$(printf '\033[34m')"
  GRAY="$(printf '\033[90m')"
else
  RESET=''
  BOLD=''
  DIM=''
  RED=''
  YELLOW=''
  GREEN=''
  BLUE=''
  GRAY=''
fi

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
CRITICALS=0
printf '%sRepoScan%s\n' "$BOLD" "$RESET"
printf 'Target:   %s\n' "$TARGET"
printf 'Engine:   yara-cli\n'
printf '\n'
while IFS= read -r file_path; do
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    MATCHES=$((MATCHES + 1))
    rule="${line%% *}"
    path="${line#* }"
    rel_path="$path"
    case "$rel_path" in
      "$TARGET"/*) rel_path="${rel_path#"$TARGET"/}" ;;
    esac
    severity="$(rule_severity "$rule")"
    [ -n "$severity" ] || severity='medium'
    [ "$severity" = "critical" ] && CRITICALS=$((CRITICALS + 1))
    label="$(severity_label "$severity")"
    color="$(severity_color "$severity")"
    printf '%s%s%s\n' "$color$BOLD" "$label" "$RESET"
    printf '  - %s%s%s\n' "$BOLD" "$rule" "$RESET"
    printf '    path:   %s%s%s\n' "$BLUE" "$rel_path" "$RESET"
    printf '    source: %syara-cli%s\n' "$GRAY" "$RESET"
  done <<EOF
$(yara -w "$RULE_DIR"/*.yar "$file_path" 2>/dev/null)
EOF
done < "$TMP_FILE"

printf '\n'
if [ "$MATCHES" -gt 0 ]; then
  if [ "$CRITICALS" -gt 0 ]; then
    VERDICT='malicious-likely'
    EXIT_CODE=2
    VERDICT_COLOR="$RED"
  else
    VERDICT='suspicious'
    EXIT_CODE=1
    VERDICT_COLOR="$YELLOW"
  fi
  printf 'Verdict:  %s%s%s\n' "$VERDICT_COLOR$BOLD" "$VERDICT" "$RESET"
  printf 'Findings: %s\n' "$MATCHES"
  printf '%sExit code: %s%s\n' "$DIM" "$EXIT_CODE" "$RESET"
  exit "$EXIT_CODE"
fi

printf 'Verdict:  %sno-findings%s\n' "$GREEN$BOLD" "$RESET"
printf 'Findings: 0\n'
printf '%sNo YARA findings.%s\n' "$GREEN" "$RESET"
exit 0
