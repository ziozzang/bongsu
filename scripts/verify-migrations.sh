#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MIGRATIONS_DIR="${BONGSU_MIGRATIONS_DIR:-${ROOT}/migrations}"

if [ ! -d "$MIGRATIONS_DIR" ]; then
    echo "ERROR: migrations directory not found: $MIGRATIONS_DIR" >&2
    exit 1
fi

mapfile -t files < <(find "$MIGRATIONS_DIR" -maxdepth 1 -type f -name '*.sql' -printf '%f\n' | sort)
if [ "${#files[@]}" -eq 0 ]; then
    echo "ERROR: no migration files found in $MIGRATIONS_DIR" >&2
    exit 1
fi

expected=1
declare -A seen_numbers=()

for file in "${files[@]}"; do
    if [[ ! "$file" =~ ^([0-9]{3})_[a-z0-9_]+\.sql$ ]]; then
        echo "ERROR: invalid migration filename: $file" >&2
        echo "Expected format: NNN_lower_snake_case.sql" >&2
        exit 1
    fi

    number="${BASH_REMATCH[1]}"
    number10=$((10#$number))
    if [ "${seen_numbers[$number]+set}" = "set" ]; then
        echo "ERROR: duplicate migration number: $number" >&2
        exit 1
    fi
    seen_numbers[$number]=1

    if [ "$number10" -ne "$expected" ]; then
        printf 'ERROR: migration sequence gap: got %03d, want %03d (%s)\n' "$number10" "$expected" "$file" >&2
        exit 1
    fi

    path="${MIGRATIONS_DIR}/${file}"
    if [ ! -s "$path" ]; then
        echo "ERROR: empty migration file: $file" >&2
        exit 1
    fi
    if grep -nE '^(<<<<<<<|=======|>>>>>>>)' "$path"; then
        echo "ERROR: conflict marker found in migration: $file" >&2
        exit 1
    fi
    if grep -n $'\r' "$path"; then
        echo "ERROR: CRLF line ending found in migration: $file" >&2
        exit 1
    fi

    expected=$((expected + 1))
done

echo "Verified ${#files[@]} migration files through $(printf '%03d' $((expected - 1)))"
