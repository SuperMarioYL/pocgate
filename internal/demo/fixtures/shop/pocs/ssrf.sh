#!/bin/sh
# ssrf: /fetch calls any caller-supplied URL, so it can reach the fixture's own
# internal-only endpoint that clients are never meant to read directly.
#
# Exit codes are a tri-state contract with pocgate (see authbypass.sh): 0 fired,
# 1 a definite silent response, 2 unobserved (transport failure or an
# unexpected status such as a 500 from a broken build).
set -eu

base=${POCGATE_TARGET_URL:-http://127.0.0.1:18081}

if ! command -v curl >/dev/null 2>&1; then
	echo "ssrf: curl is required to probe the fixture" >&2
	exit 2
fi

body=$(mktemp "${TMPDIR:-/tmp}/pocgate-ssrf.XXXXXX")
trap 'rm -f "$body"' EXIT

status=$(curl -sS -o "$body" -w '%{http_code}' --max-time 5 "$base/fetch?url=$base/internal") || {
	echo "ssrf: UNOBSERVED: the fixture is not answering at $base" >&2
	exit 2
}

case "$status" in
200)
	if grep -q 'INTERNAL-ONLY' "$body"; then
		echo "ssrf: FIRED: /fetch relayed the internal-only endpoint"
		exit 0
	fi
	echo "ssrf: UNOBSERVED: /fetch returned 200 without the internal body" >&2
	exit 2
	;;
400|403)
	echo "ssrf: SILENT: /fetch refused the internal URL (HTTP $status)"
	exit 1
	;;
*)
	echo "ssrf: UNOBSERVED: /fetch answered HTTP $status, which is not a definite fix" >&2
	exit 2
	;;
esac
