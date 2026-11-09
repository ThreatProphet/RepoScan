#!/bin/sh
# Quick-run launcher. Keep this file outside the repository being inspected.
# Artifact pins are reviewed inputs, never values supplied by the scan target.
REPOSCAN_VERSION='0.3.1'
REPOSCAN_WHEEL_SHA256='c93319502a508e40a370caab0703b7888d211559c6f1cceca30a76d4efa70730'
UV_VERSION='0.13.7'
PYTHON_VERSION='3.12.16'
PYTHON_BUILD='20261026'
YARA_VERSION='4.5.4'

# Do not resolve commands, shell startup files, or project configuration in target.
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
unset ENV BASH_ENV CDPATH
IFS=$(printf ' \t\n_')
IFS=${IFS%_}
umask 077

fail() {
    printf 'RepoScan launcher: %s\n' "$*" >&2
    exit 70
}

usage() {
    cat <<'EOF'
Usage: sh reposcan-run.sh [--offline] TARGET [RepoScan options...]
       sh reposcan-run.sh --help
       sh reposcan-run.sh --version

Run the pinned RepoScan release with canonical YARA in a private environment.
TARGET may be a relative or absolute path. Run this trusted launcher outside
the unfamiliar repository; it never installs or executes the target project.
Explicit --rules and --ignore-config paths must be absolute.

The first run downloads verified uv/RepoScan artifacts, managed CPython, and
the pinned YARA wheel. Later runs reuse the private runtime. --offline forbids
downloads and requires a completed first run. No sudo or shell-profile edits.

State: $REPOSCAN_RUN_HOME, or $HOME/.local/share/threatprophet-reposcan-run
The state directory must be private, outside TARGET, and have no symlink
components. The launcher targets Linux x86_64/glibc. macOS 15+ arm64/x86_64
remains a qualification candidate until the native CI and release checks pass.

Scanner exit codes are preserved. Launcher usage errors return 64; bootstrap
failures return 70. --version describes the pins, not runtime readiness.
EOF
}

offline=no
if [ "${1-}" = '--offline' ]; then
    offline=yes
    shift
fi
case "${1-}" in
    --help|-h) usage; exit 0 ;;
    --version)
        printf 'RepoScan quick-run launcher: pinned RepoScan %s; uv %s; CPython %s; yara-python %s (readiness not checked)\n' \
            "$REPOSCAN_VERSION" "$UV_VERSION" "$PYTHON_VERSION" "$YARA_VERSION"
        exit 0 ;;
    ''|-*) usage >&2; exit 64 ;;
esac

caller_directory=$(pwd -P) || fail 'cannot determine the calling directory'

# Lexical normalization, like os.path.abspath: do not follow target symlinks.
absolute_path() (
    case "$1" in /*) remaining=$1 ;; *) remaining=$caller_directory/$1 ;; esac
    absolute=
    while [ -n "$remaining" ]; do
        component=${remaining%%/*}
        case "$remaining" in */*) remaining=${remaining#*/} ;; *) remaining= ;; esac
        case "$component" in
            ''|.) ;;
            ..) absolute=${absolute%/*} ;;
            *) absolute=$absolute/$component ;;
        esac
    done
    printf '%s\n' "${absolute:-/}"
)

target=$(absolute_path "$1") || fail 'cannot make target absolute'
shift
expect_path=no
for argument do
    if [ "$expect_path" = yes ]; then
        case "$argument" in /*) ;; *) printf 'RepoScan launcher: --rules and --ignore-config require absolute paths\n' >&2; exit 64 ;; esac
        expect_path=no
    else
        # argparse accepts long-option abbreviations. Do not let an abbreviated
        # path option escape this check and acquire a different working base.
        case "$argument" in
            --?*)
                option=${argument%%=*}
                for path_option in --rules --ignore-config; do
                    case "$path_option" in
                        "$option"*)
                            [ "$option" = "$path_option" ] || {
                                printf 'RepoScan launcher: spell path options as --rules or --ignore-config\n' >&2
                                exit 64
                            } ;;
                    esac
                done ;;
        esac
        case "$argument" in
            --rules|--ignore-config) expect_path=yes ;;
            --rules=*|--ignore-config=*)
                case "${argument#*=}" in /*) ;; *) printf 'RepoScan launcher: --rules and --ignore-config require absolute paths\n' >&2; exit 64 ;; esac ;;
        esac
    fi
done
if [ "$expect_path" = yes ]; then
    printf 'RepoScan launcher: missing path after --rules or --ignore-config\n' >&2
    exit 64
fi

case "${HOME-}" in /*) launcher_home=$HOME ;; *) fail 'HOME must be an absolute user directory' ;; esac
case "${REPOSCAN_RUN_HOME-$launcher_home/.local/share/threatprophet-reposcan-run}" in
    /*) state=${REPOSCAN_RUN_HOME-$launcher_home/.local/share/threatprophet-reposcan-run} ;;
    *) fail 'REPOSCAN_RUN_HOME must be an absolute directory' ;;
esac
state=$(absolute_path "$state") || fail 'cannot make state path absolute'
[ "$state" != / ] || fail 'state cannot be the filesystem root'
[ "$target" != / ] || fail 'state cannot be outside a scan of the filesystem root'
case "$state/" in "$target/"*) fail 'state must be outside the scan target; choose REPOSCAN_RUN_HOME elsewhere' ;; esac
case "$target/" in "$state/"*) fail 'scan target must be outside the launcher state directory' ;; esac

os=$(uname -s) || fail 'cannot identify the operating system'
architecture=$(uname -m) || fail 'cannot identify the architecture'
case "$os:$architecture" in
    Linux:x86_64)
        case "$(getconf GNU_LIBC_VERSION 2>/dev/null)" in glibc\ *) ;; *) fail 'quick-run requires glibc on Linux; musl is not qualified' ;; esac
        uv_target=x86_64-unknown-linux-gnu
        uv_sha256=c5221ff41b7892bfc223543883600125f6a47fe845093e0f5bdff4f359196d83 ;;
    Darwin:arm64|Darwin:x86_64)
        macos_version=$(sw_vers -productVersion) || fail 'cannot identify the macOS version'
        macos_major=${macos_version%%.*}
        case "$macos_major" in ''|*[!0-9]*) fail 'unrecognized macOS version' ;; esac
        [ "$macos_major" -ge 15 ] || fail 'quick-run requires macOS 15 or newer'
        if [ "$architecture" = arm64 ]; then
            uv_target=aarch64-apple-darwin
            uv_sha256=81b811b57e4624df7ed3aac148e0359100d9962f3d9dce00aec533dc2e086731
        else
            uv_target=x86_64-apple-darwin
            uv_sha256=20c47e4c1f630b8abaff8c291fa9b9aa300fef92c4fbff95adf198b55287cda7
        fi ;;
    *) fail "unsupported platform: $os $architecture" ;;
esac
user_id=$(id -u) || fail 'cannot identify the current user'

file_info() {
    case "$os" in Linux) stat -c '%u %a' "$1" ;; Darwin) stat -f '%u %Lp' "$1" ;; esac
}

# Check each component before creating children. Root-owned sticky ancestors
# (e.g. /tmp) are permitted; the state directory itself must be user-owned.
ensure_directory() (
    remaining=${1#/}
    checked=
    while [ -n "$remaining" ]; do
        component=${remaining%%/*}
        case "$remaining" in */*) remaining=${remaining#*/} ;; *) remaining= ;; esac
        checked=$checked/$component
        [ ! -L "$checked" ] || fail "symlink in state path: $checked"
        if [ ! -e "$checked" ]; then
            mkdir "$checked" || fail "cannot create private directory: $checked"
        fi
        [ -d "$checked" ] || fail "state component is not a directory: $checked"
        metadata=$(file_info "$checked") || fail "cannot inspect directory: $checked"
        owner=${metadata% *}
        mode=${metadata#* }
        case "$mode" in ''|*[!0-7]*) fail "cannot inspect directory permissions: $checked" ;; esac
        if [ -z "$remaining" ]; then
            [ "$owner" = "$user_id" ] || fail "state directory is not owned by the current user: $checked"
        else
            [ "$owner" = "$user_id" ] || [ "$owner" = 0 ] || fail "untrusted state ancestor: $checked"
        fi
        case "$mode" in
            *[2367][0-7]|*[0-7][2367])
                case "$owner:$mode:$remaining" in
                    0:1???:?*) ;; # Sticky root-owned parent, not the requested directory.
                    *) fail "state path is writable by other users: $checked" ;;
                esac ;;
        esac
    done
)

safe_file() (
    if [ -L "$1" ] || [ ! -f "$1" ]; then
        fail "cached artifact is not a regular non-symlink file: $1"
    fi
    metadata=$(file_info "$1") || fail "cannot inspect cached artifact: $1"
    [ "${metadata% *}" = "$user_id" ] || fail "cached artifact has an unexpected owner: $1"
    case "${metadata#* }" in *[2367][0-7]|*[0-7][2367]) fail "cached artifact is writable by other users: $1" ;; esac
)

ensure_directory "$state" || exit 70
lock=$state/.bootstrap.lock
mkdir "$lock" 2>/dev/null || fail "setup lock exists at $lock; another launcher may be preparing the runtime (remove a stale lock only after it has stopped)"
work=
cleanup() {
    if [ -n "$work" ]; then rm -rf "$work"; fi
    rmdir "$lock" 2>/dev/null || :
}
trap cleanup 0
trap 'exit 70' HUP INT TERM
work=$(mktemp -d "$state/.bootstrap.XXXXXX") || fail 'cannot create private bootstrap workspace'
downloads=$state/downloads
runtime=$state/runtimes/$REPOSCAN_VERSION-$REPOSCAN_WHEEL_SHA256
for directory in "$downloads" "$state/bin" "$state/python" "$state/python-bin" "$runtime/cache"; do
    ensure_directory "$directory" || exit 70
done

# An allowlist prevents inherited UV_*, PYTHON*, pip, and project settings from
# selecting code. Retain terminal preferences, explicit HTTPS proxies, and
# caller-supplied CA locations for managed networks. TLS verification stays on.
clean_environment() {
    environment_action=$1
    shift
    if [ "${NO_COLOR+x}" = x ]; then set -- "NO_COLOR=$NO_COLOR" "$@"; fi
    if [ -n "${HTTPS_PROXY-}" ]; then set -- "HTTPS_PROXY=$HTTPS_PROXY" "$@"; fi
    if [ -n "${https_proxy-}" ]; then set -- "https_proxy=$https_proxy" "$@"; fi
    if [ -n "${NO_PROXY-}" ]; then set -- "NO_PROXY=$NO_PROXY" "$@"; fi
    if [ -n "${no_proxy-}" ]; then set -- "no_proxy=$no_proxy" "$@"; fi
    if [ -n "${SSL_CERT_FILE-}" ]; then
        case "$SSL_CERT_FILE" in /*) ;; *) fail 'SSL_CERT_FILE must be an absolute path' ;; esac
        set -- "SSL_CERT_FILE=$SSL_CERT_FILE" "$@"
    fi
    if [ -n "${SSL_CERT_DIR-}" ]; then
        case "$SSL_CERT_DIR" in /*) ;; *) fail 'SSL_CERT_DIR must be an absolute path' ;; esac
        case "$SSL_CERT_DIR" in *:|*:[!/]*) fail 'every SSL_CERT_DIR entry must be an absolute path' ;; esac
        set -- "SSL_CERT_DIR=$SSL_CERT_DIR" "$@"
    fi
    if [ -n "${CURL_CA_BUNDLE-}" ]; then
        case "$CURL_CA_BUNDLE" in /*) ;; *) fail 'CURL_CA_BUNDLE must be an absolute path' ;; esac
        set -- "CURL_CA_BUNDLE=$CURL_CA_BUNDLE" "$@"
    fi
    "$environment_action" /usr/bin/env -i "PATH=$PATH" "HOME=$launcher_home" \
        'LANG=C.UTF-8' "TERM=${TERM-dumb}" "$@"
}

verify_sha256() {
    case "$os" in
        Linux) observed=$(sha256sum < "$1") || fail 'SHA-256 calculation failed' ;;
        Darwin) observed=$(shasum -a 256 < "$1") || fail 'SHA-256 calculation failed' ;;
    esac
    [ "${observed%% *}" = "$2" ] || fail "SHA-256 mismatch for $1; remove that cached file and retry"
}

download_verified() {
    if [ -e "$3" ] || [ -L "$3" ]; then
        safe_file "$3" || exit 70
        verify_sha256 "$3" "$2"
        return
    fi
    [ "$offline" = no ] || fail "offline cache is missing $3; complete an online run first"
    printf 'RepoScan launcher: downloading %s\n' "${3##*/}" >&2
    clean_environment command curl -q --fail --location --silent --show-error \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 180 --retry 2 --retry-max-time 240 \
        --output "$work/download" "$1" || fail "download failed: $1"
    verify_sha256 "$work/download" "$2"
    mv "$work/download" "$3" || fail 'cannot publish verified download'
}

uv_archive=$downloads/uv-$UV_VERSION-$uv_target.tar.gz
wheel=$downloads/threatprophet_reposcan-$REPOSCAN_VERSION-py3-none-any.whl
# Upstream checksum sources: the corresponding .tar.gz.sha256 release assets.
download_verified "https://github.com/astral-sh/uv/releases/download/$UV_VERSION/uv-$uv_target.tar.gz" "$uv_sha256" "$uv_archive"
download_verified "https://github.com/ThreatProphet/RepoScan/releases/download/v$REPOSCAN_VERSION/threatprophet_reposcan-$REPOSCAN_VERSION-py3-none-any.whl" "$REPOSCAN_WHEEL_SHA256" "$wheel"

# Re-extract just the verified executable on each invocation, so a stale or
# modified executable in the cache is never executed. No secondary installer.
extracted_uv=$work/uv
# Streaming a single member creates our own file, without restoring archive
# ownership, permissions, or directory metadata (also works in user namespaces).
clean_environment command tar -xOzf "$uv_archive" "uv-$uv_target/uv" > "$extracted_uv" || fail 'cannot extract verified uv archive'
if [ ! -s "$extracted_uv" ] || [ -L "$extracted_uv" ]; then
    fail 'uv archive did not contain a regular executable'
fi
chmod 700 "$extracted_uv" || fail 'cannot set uv executable permissions'
uv_binary=$state/bin/uv-$UV_VERSION-$uv_target
if [ -e "$uv_binary" ] || [ -L "$uv_binary" ]; then safe_file "$uv_binary" || exit 70; fi
mv "$extracted_uv" "$uv_binary" || fail 'cannot publish verified uv executable'
cd "$state" || fail 'cannot enter trusted launcher directory'

run_tool() {
    tool_action=$1
    tool_network=$2
    shift 2
    if [ "$tool_network" = offline ]; then set -- --offline "$@"; fi
    clean_environment "$tool_action" \
        "UV_CACHE_DIR=$runtime/cache" "UV_PYTHON_INSTALL_DIR=$state/python" \
        "UV_PYTHON_BIN_DIR=$state/python-bin" 'UV_PYTHON_INSTALL_BIN=false' \
        "UV_PYTHON_CPYTHON_BUILD=$PYTHON_BUILD" 'UV_HTTP_TIMEOUT=120' 'UV_HTTP_RETRIES=2' \
        "$uv_binary" --no-config tool run --no-env-file --isolated --managed-python \
        --python "$PYTHON_VERSION" --no-build --default-index https://pypi.org/simple \
        --from "$wheel" --with "yara-python==$YARA_VERSION" "$@"
}

printf 'RepoScan launcher: checking private RepoScan %s / YARA %s runtime\n' "$REPOSCAN_VERSION" "$YARA_VERSION" >&2
network=online
if [ "$offline" = yes ]; then network=offline; fi
installed_python=$(run_tool command "$network" python -I -c '
import importlib.metadata as metadata
import os
import pathlib
import sys
import reposcan
import yara
from reposcan import settings
assert metadata.version("threatprophet-reposcan") == sys.argv[1], "unexpected RepoScan version"
assert metadata.version("yara-python") == sys.argv[2], "unexpected YARA version"
cache = pathlib.Path(sys.argv[3]).resolve()
assert pathlib.Path(sys.prefix).resolve().is_relative_to(cache), "unexpected tool environment"
assert pathlib.Path(reposcan.__file__).resolve().is_relative_to(cache), "unexpected package origin"
assert pathlib.Path(yara.__file__).resolve().is_relative_to(cache), "unexpected YARA origin"
assert settings.DEFAULT_RULES.is_dir() and any(settings.DEFAULT_RULES.glob("*.yar")), "missing packaged rules"
assert settings.DEFAULT_IGNORE_CONFIG.is_file(), "missing packaged configuration"
assert yara.compile(source="rule launcher_probe { condition: true }").match(data=b""), "YARA probe failed"
print(os.path.abspath(sys.executable))
' "$REPOSCAN_VERSION" "$YARA_VERSION" "$runtime/cache") || fail 'runtime preparation failed; no scan was performed'
case "$installed_python" in "$runtime/cache/"*) ;; *) fail 'health check returned an interpreter outside the private runtime' ;; esac
[ -x "$installed_python" ] || fail 'prepared Python interpreter is unavailable'

cleanup
trap - 0 HUP INT TERM
# No resolver runs during scanning. The already verified interpreter runs in
# Python isolated mode; exec preserves scanner exit codes and signals.
clean_environment exec "$installed_python" -I -m reposcan "$target" "$@"
