#!/bin/sh
# authbypass: /admin performs a privileged action without any credential check.
#
# Exit codes are a tri-state contract with pocgate:
#   0  FIRED       the vulnerable behaviour was observed
#   1  SILENT      the target answered with a definite, non-vulnerable response
#   2  UNOBSERVED  no definite answer (transport failure or unexpected status)
#
# The HTTP status is read without curl -f on purpose: -f turns a 401/403 into a
# non-zero exit, which would make a fixed target indistinguishable from a
# broken or unreachable one.
set -eu

base=${POCGATE_TARGET_URL:-http://127.0.0.1:18081}

if ! command -v curl >/dev/null 2>&1; then
	echo "authbypass: curl is required to probe the fixture" >&2
	exit 2
fi

body=$(mktemp "${TMPDIR:-/tmp}/pocgate-authbypass.XXXXXX")
trap 'rm -f "$body"' EXIT

status=$(curl -sS -o "$body" -w '%{http_code}' --max-time 5 "$base/admin") || {
	echo "authbypass: UNOBSERVED: the fixture is not answering at $base" >&2
	exit 2
}

case "$status" in
200)
	if grep -q 'ADMIN-ACTION-ALLOWED' "$body"; then
		echo "authbypass: FIRED: /admin granted a privileged action without a credential"
		exit 0
	fi
	echo "authbypass: UNOBSERVED: /admin returned 200 without the privileged-action body" >&2
	exit 2
	;;
401|403)
	echo "authbypass: SILENT: /admin denied the unauthenticated request (HTTP $status)"
	exit 1
	;;
*)
	echo "authbypass: UNOBSERVED: /admin answered HTTP $status, which is not a definite fix" >&2
	exit 2
	;;
esac
