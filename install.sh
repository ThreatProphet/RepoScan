#!/usr/bin/env bash
set -eu

# Select the interpreter without interpreting path arguments as shell code.
PYTHON=python3
EXPECT_VALUE=
for ARGUMENT in "$@"; do
    if [ -n "$EXPECT_VALUE" ]; then
        if [ "$EXPECT_VALUE" = python ]; then
            PYTHON=$ARGUMENT
        fi
        EXPECT_VALUE=
        continue
    fi
    case "$ARGUMENT" in
        --python) EXPECT_VALUE=python ;;
        --python=*) PYTHON=${ARGUMENT#--python=} ;;
        --prefix|--bin-dir) EXPECT_VALUE=path ;;
    esac
done

if [ "$EXPECT_VALUE" = python ] || [ -z "$PYTHON" ]; then
    printf '%s\n' 'install.sh: --python requires an interpreter path or command.' >&2
    exit 2
fi

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
exec -- "$PYTHON" -I "$SCRIPT_DIR/tools/install.py" "$@"
