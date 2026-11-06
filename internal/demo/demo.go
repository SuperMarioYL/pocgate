// Package demo runs the bundled shop fixture from red to green: it captures the
// vulnerable baseline, verifies the bundled patch, and then replays two
// deliberately bad patches so the STILL_VULNERABLE and REGRESSION_BROKEN
// verdicts are shown next to CLOSED.
//
// The fixture is embedded in the binary, so the demo needs nothing on disk and
// no network. Everything is expanded into a temporary directory; the only file
// the demo leaves behind is the signed evidence under .pocgate/evidence/ in the
// working directory, which is what `pocgate attest verify` then checks.
package demo

import (
	"context"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SuperMarioYL/pocgate/internal/evidence"
	"github.com/SuperMarioYL/pocgate/internal/oracle"
	"github.com/SuperMarioYL/pocgate/internal/spec"
	"github.com/SuperMarioYL/pocgate/internal/verdict"
)

//go:embed fixtures/shop/main.go fixtures/shop/regression_test.go fixtures/shop/pocgate.yaml fixtures/shop/pocs/*.sh
var fixture embed.FS

//go:embed fixtures/shop/patch.diff
var goodPatch []byte

// partialPatch fixes the traversal and SSRF flaws but leaves /admin open, so the
// authbypass PoC keeps firing after the patch: STILL_VULNERABLE.
const partialPatch = `--- a/main.go
+++ b/main.go
@@ -9,10 +9,13 @@
 	"fmt"
 	"io"
 	"log"
+	"net"
 	"net/http"
+	"net/url"
 	"os"
 	"os/signal"
 	"path/filepath"
+	"strings"
 	"syscall"
 	"time"
 )
@@ -89,8 +92,8 @@
 	fmt.Fprint(w, adminBody)
 }
 
-// files serves a file under root. filepath.Join cleans "..", so a caller can
-// walk out of root: the flaw the traversal PoC reproduces.
+// files serves a file under root. A joined path is checked against root before
+// it is read, so "../" can no longer walk out of the public directory.
 func files(root string) http.HandlerFunc {
 	return func(w http.ResponseWriter, r *http.Request) {
 		name := r.URL.Query().Get("path")
@@ -98,7 +101,13 @@
 			http.Error(w, "missing path", http.StatusBadRequest)
 			return
 		}
-		data, err := os.ReadFile(filepath.Join(root, name))
+		full := filepath.Join(root, name)
+		rel, err := filepath.Rel(root, full)
+		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
+			http.Error(w, "path escapes the public root", http.StatusBadRequest)
+			return
+		}
+		data, err := os.ReadFile(full)
 		if err != nil {
 			http.Error(w, err.Error(), http.StatusNotFound)
 			return
@@ -113,15 +122,24 @@
 	fmt.Fprint(w, internalBody)
 }
 
-// fetch retrieves any caller-supplied URL: the SSRF flaw. A real service would
-// allowlist outbound hosts.
+// fetch retrieves a caller-supplied URL after refusing addresses a client must
+// not reach, so /fetch cannot be aimed at the service's own network.
 func fetch(w http.ResponseWriter, r *http.Request) {
 	target := r.URL.Query().Get("url")
 	if target == "" {
 		http.Error(w, "missing url", http.StatusBadRequest)
 		return
 	}
-	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
+	u, err := url.Parse(target)
+	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
+		http.Error(w, "unsupported url", http.StatusBadRequest)
+		return
+	}
+	if isBlockedHost(u.Hostname()) {
+		http.Error(w, "outbound host is not allowed", http.StatusForbidden)
+		return
+	}
+	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u.String(), nil)
 	if err != nil {
 		http.Error(w, err.Error(), http.StatusBadRequest)
 		return
@@ -135,4 +153,22 @@
 	defer resp.Body.Close()
 	w.WriteHeader(resp.StatusCode)
 	_, _ = io.Copy(w, io.LimitReader(resp.Body, 64<<10))
+}
+
+// isBlockedHost rejects loopback, link-local, and private addresses so /fetch
+// cannot be turned into a probe of the target's own network.
+func isBlockedHost(host string) bool {
+	if host == "" || host == "localhost" {
+		return true
+	}
+	ips, err := net.LookupIP(host)
+	if err != nil {
+		return true
+	}
+	for _, ip := range ips {
+		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
+			return true
+		}
+	}
+	return false
 }
`

// regressionPatch fixes every flaw but also adds a test that asserts the old,
// vulnerable /admin behaviour, so the regression command gains a failure:
// REGRESSION_BROKEN.
const regressionPatch = `--- /dev/null
+++ b/fix_test.go
@@ -0,0 +1,17 @@
+package main
+
+import (
+	"net/http"
+	"net/http/httptest"
+	"testing"
+)
+
+// TestAdminStaysPublic guards the legacy behaviour: /admin used to be reachable
+// without a credential.
+func TestAdminStaysPublic(t *testing.T) {
+	rec := httptest.NewRecorder()
+	admin(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
+	if rec.Code != http.StatusOK {
+		t.Fatalf("/admin status = %d, want %d (legacy behaviour)", rec.Code, http.StatusOK)
+	}
+}
--- a/main.go
+++ b/main.go
@@ -9,10 +9,13 @@
 	"fmt"
 	"io"
 	"log"
+	"net"
 	"net/http"
+	"net/url"
 	"os"
 	"os/signal"
 	"path/filepath"
+	"strings"
 	"syscall"
 	"time"
 )
@@ -27,6 +30,10 @@
 	secretBody   = "SHOP-INTERNAL-SECRET: do not serve this outside the root\n"
 )
 
+// adminToken is the credential /admin now requires. A real service would load
+// it from a secret store instead of the source.
+const adminToken = "operator-token"
+
 func main() {
 	root, err := prepareData()
 	if err != nil {
@@ -83,14 +90,17 @@
 	fmt.Fprint(w, "shop fixture\n\nGET /admin\nGET /file?path=hello.txt\nGET /fetch?url=<url>\n")
 }
 
-// admin performs a privileged action without checking any credential. The
-// authbypass PoC fires when this unauthenticated request succeeds.
+// admin performs a privileged action for an authenticated operator only.
 func admin(w http.ResponseWriter, r *http.Request) {
+	if r.Header.Get("X-Admin-Token") != adminToken {
+		http.Error(w, "admin token required", http.StatusUnauthorized)
+		return
+	}
 	fmt.Fprint(w, adminBody)
 }
 
-// files serves a file under root. filepath.Join cleans "..", so a caller can
-// walk out of root: the flaw the traversal PoC reproduces.
+// files serves a file under root. A joined path is checked against root before
+// it is read, so "../" can no longer walk out of the public directory.
 func files(root string) http.HandlerFunc {
 	return func(w http.ResponseWriter, r *http.Request) {
 		name := r.URL.Query().Get("path")
@@ -98,7 +108,13 @@
 			http.Error(w, "missing path", http.StatusBadRequest)
 			return
 		}
-		data, err := os.ReadFile(filepath.Join(root, name))
+		full := filepath.Join(root, name)
+		rel, err := filepath.Rel(root, full)
+		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
+			http.Error(w, "path escapes the public root", http.StatusBadRequest)
+			return
+		}
+		data, err := os.ReadFile(full)
 		if err != nil {
 			http.Error(w, err.Error(), http.StatusNotFound)
 			return
@@ -113,15 +129,24 @@
 	fmt.Fprint(w, internalBody)
 }
 
-// fetch retrieves any caller-supplied URL: the SSRF flaw. A real service would
-// allowlist outbound hosts.
+// fetch retrieves a caller-supplied URL after refusing addresses a client must
+// not reach, so /fetch cannot be aimed at the service's own network.
 func fetch(w http.ResponseWriter, r *http.Request) {
 	target := r.URL.Query().Get("url")
 	if target == "" {
 		http.Error(w, "missing url", http.StatusBadRequest)
 		return
 	}
-	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
+	u, err := url.Parse(target)
+	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
+		http.Error(w, "unsupported url", http.StatusBadRequest)
+		return
+	}
+	if isBlockedHost(u.Hostname()) {
+		http.Error(w, "outbound host is not allowed", http.StatusForbidden)
+		return
+	}
+	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u.String(), nil)
 	if err != nil {
 		http.Error(w, err.Error(), http.StatusBadRequest)
 		return
@@ -135,4 +160,22 @@
 	defer resp.Body.Close()
 	w.WriteHeader(resp.StatusCode)
 	_, _ = io.Copy(w, io.LimitReader(resp.Body, 64<<10))
+}
+
+// isBlockedHost rejects loopback, link-local, and private addresses so /fetch
+// cannot be turned into a probe of the target's own network.
+func isBlockedHost(host string) bool {
+	if host == "" || host == "localhost" {
+		return true
+	}
+	ips, err := net.LookupIP(host)
+	if err != nil {
+		return true
+	}
+	for _, ip := range ips {
+		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
+			return true
+		}
+	}
+	return false
 }
`

// Options are the inputs to a demo run.
type Options struct {
	Out     io.Writer
	Version string
	// EvidencePath is where the signed evidence lands. It defaults to
	// .pocgate/evidence/latest.json in the working directory.
	EvidencePath string
}

// Run drives the fixture through the baseline, the good patch, and the two bad
// patches. It returns an error when a case does not produce the verdict the
// fixture is built to demonstrate.
func Run(ctx context.Context, opts Options) error {
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	started := time.Now()

	work, err := os.MkdirTemp("", "pocgate-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	target := filepath.Join(work, "shop")
	if err := expand(target); err != nil {
		return fmt.Errorf("expand the bundled fixture: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(work, "patches"), 0o755); err != nil {
		return err
	}
	specPath := filepath.Join(target, "pocgate.yaml")
	sp, err := spec.Load(specPath)
	if err != nil {
		return fmt.Errorf("load the bundled spec: %w", err)
	}

	fmt.Fprintln(out, "pocgate demo: shop fixture with three synthetic flaws")
	fmt.Fprintf(out, "  target: %s\n", target)

	fmt.Fprintln(out, "\n== vulnerable build (baseline) ==")
	baseline, err := oracle.Capture(ctx, specPath, oracle.Options{Version: opts.Version})
	if baseline != nil {
		baseline.Report(out)
	}
	if err != nil {
		return fmt.Errorf("baseline: %w", err)
	}

	cases := []struct {
		name  string
		patch []byte
		want  verdict.Verdict
	}{
		{"good patch", goodPatch, verdict.Closed},
		{"partial patch", []byte(partialPatch), verdict.StillVulnerable},
		{"regression patch", []byte(regressionPatch), verdict.RegressionBroken},
	}

	var closed *evidence.Document
	for _, c := range cases {
		fmt.Fprintf(out, "\n== %s ==\n", c.name)
		patchPath := filepath.Join(work, "patches", strings.ReplaceAll(c.name, " ", "-")+".diff")
		if err := os.WriteFile(patchPath, c.patch, 0o644); err != nil {
			return err
		}
		doc, err := verdict.Run(ctx, verdict.Request{Spec: sp, PatchPath: patchPath, Version: opts.Version})
		if err != nil {
			return fmt.Errorf("%s: %w", c.name, err)
		}
		report(out, doc)
		if got := verdict.Verdict(doc.Verdict); got != c.want {
			return fmt.Errorf("%s produced %s, want %s", c.name, got, c.want)
		}
		if c.want == verdict.Closed {
			closed = doc
		}
	}

	path := opts.EvidencePath
	if path == "" {
		path = filepath.Join(".pocgate", "evidence", "latest.json")
	}
	if err := evidence.Write(path, closed); err != nil {
		return fmt.Errorf("write evidence: %w", err)
	}
	fmt.Fprintf(out, "\n== evidence ==\n")
	// The path is printed as given, so the next command can be copied from the
	// screen and the run does not depend on the absolute location it ran in.
	fmt.Fprintf(out, "  file:    %s\n", path)
	fmt.Fprintf(out, "  digest:  %s\n", closed.Digest)
	fmt.Fprintf(out, "  verify:  pocgate attest verify --pubkey %s.pub %s\n", path, path)

	elapsed := time.Since(started).Round(100 * time.Millisecond)
	fmt.Fprintf(out, "\ndemo: CLOSED in %s", elapsed)
	if elapsed > 90*time.Second {
		fmt.Fprintf(out, " (OVER the 90s budget)")
	}
	fmt.Fprintln(out)
	return nil
}

// report prints one line per oracle and the verdict.
func report(w io.Writer, d *evidence.Document) {
	for _, o := range d.Oracles {
		fmt.Fprintf(w, "  %-12s pre FIRED %d/%d  →  post FIRED %d/%d\n",
			o.ID, o.Pre.Fired, o.Repeats, o.Post.Fired, o.Repeats)
	}
	fmt.Fprintf(w, "  regression: %s, new failures: %d\n",
		d.Regression.Parser, len(d.Regression.NewFailures))
	for _, id := range d.Regression.NewFailures {
		fmt.Fprintf(w, "    new: %s\n", id)
	}
	fmt.Fprintf(w, "  verdict: %s (exit %d)\n", d.Verdict, verdict.Verdict(d.Verdict).ExitCode())
}

// expand writes the embedded fixture under dst.
func expand(dst string) error {
	const prefix = "fixtures/shop/"
	return fs.WalkDir(fixture, "fixtures/shop", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(path, prefix)
		if rel == "" {
			return os.MkdirAll(dst, 0o755)
		}
		out := filepath.Join(dst, filepath.FromSlash(rel))
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		data, err := fs.ReadFile(fixture, path)
		if err != nil {
			return err
		}
		mode := fs.FileMode(0o644)
		if strings.HasSuffix(rel, ".sh") {
			mode = 0o755
		}
		return os.WriteFile(out, data, mode)
	})
}
