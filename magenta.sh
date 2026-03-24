#!/bin/sh
set -eu

IMAGE="magenta:latest"
CACHE_DIR="${HOME}/.magenta-cache"

usage() {
    cat <<'EOF'
Usage: magenta.sh INPUT_DIR OUTPUT

Run Magenta in a Docker container to generate a security report.

Arguments:
  INPUT_DIR   Directory containing tool output files (nmap, nessus, etc.)
  OUTPUT      Output file or directory. Format is determined by the path:
                .md, .txt  → Markdown
                .json, .js → JSON
                path/      → Obsidian vault (trailing slash)

Environment:
  LANG        Report language is derived from this (default: en)

If a magenta.json5 or magenta.json file exists at the root of
INPUT_DIR, it is automatically passed as report metadata.

Examples:
  magenta.sh ./scans report.md
  magenta.sh ./scans ./output/report.json
  magenta.sh ./scans ./vault/
  LANG=es magenta.sh ./scans informe.md
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    usage
    exit 0
fi

if [ $# -ne 2 ]; then
    usage >&2
    exit 1
fi

input_dir="$(cd "$1" && pwd)"
output="$2"

lang="${LANG:-en}"
lang="${lang%%_*}"
lang="${lang%%.*}"
case "$lang" in C|POSIX|"") lang="en" ;; esac

output_parent="$(cd "$(dirname "$output")" && pwd)"
output_name="$(basename "$output")"

mkdir -p "$CACHE_DIR"

metadata_args=""
if [ -f "${input_dir}/magenta.json5" ]; then
    metadata_args="-m /data/input/magenta.json5"
elif [ -f "${input_dir}/magenta.json" ]; then
    metadata_args="-m /data/input/magenta.json"
fi

docker run --rm --read-only \
    --tmpfs /tmp \
    -v "${input_dir}:/data/input:ro" \
    -v "${output_parent}:/data/output" \
    -v "${CACHE_DIR}:/app/cache" \
    "$IMAGE" \
    report /data/input \
    -o "/data/output/${output_name}" \
    -l "$lang" \
    $metadata_args
