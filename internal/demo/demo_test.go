package demo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/SuperMarioYL/pocgate/internal/oracle"
	"github.com/SuperMarioYL/pocgate/internal/spec"
	"github.com/SuperMarioYL/pocgate/internal/verdict"
)

// allFiveHundredPatch replaces the fixture's routes with a handler that returns
// 500 for everything. The service is up, but nothing it says is a definite
// answer about any flaw, so the PoCs must classify every run as unobserved.
const allFiveHundredPatch = `--- a/main.go
+++ b/main.go
@@ -33,12 +33,12 @@
 		log.Fatalf("prepare fixture data: %v", err)
 	}
 
+	// Every route is broken on purpose: a 500 says nothing about the flaws.
+	_ = root
 	mux := http.NewServeMux()
-	mux.HandleFunc("/", index)
-	mux.HandleFunc("/admin", admin)
-	mux.HandleFunc("/file", files(root))
-	mux.HandleFunc("/internal", internal)
-	mux.HandleFunc("/fetch", fetch)
+	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
+		http.Error(w, "broken", http.StatusInternalServerError)
+	})
 
 	srv := &http.Server{Addr: addr, Handler: mux}
 	go func() {
`

// TestAllFiveHundredPatchIsInconclusive is the end-to-end regression for the
// critical defect: a patch that leaves the service answering 500 everywhere was
// once read as CLOSED, because any non-fire exit counted as silence. The build
// is broken, so the gate must report INCONCLUSIVE and exit non-zero.
func TestAllFiveHundredPatchIsInconclusive(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl is required to probe the fixture")
	}

	ctx := context.Background()
	work := t.TempDir()
	target := filepath.Join(work, "shop")
	if err := expand(target); err != nil {
		t.Fatalf("expand fixture: %v", err)
	}
	specPath := filepath.Join(target, "pocgate.yaml")
	if _, err := oracle.Capture(ctx, specPath, oracle.Options{Version: "test"}); err != nil {
		t.Fatalf("capture baseline: %v", err)
	}
	sp, err := spec.Load(specPath)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}

	patchPath := filepath.Join(work, "all-500.diff")
	if err := os.WriteFile(patchPath, []byte(allFiveHundredPatch), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := verdict.Run(ctx, verdict.Request{Spec: sp, PatchPath: patchPath, Version: "test"})
	if err != nil {
		t.Fatalf("verify all-500 patch: %v", err)
	}
	if got := verdict.Verdict(doc.Verdict); got != verdict.Inconclusive {
		t.Fatalf("verdict = %s, want INCONCLUSIVE: a build that answers 500 everywhere proves nothing", got)
	}
	if got := verdict.Verdict(doc.Verdict); got.ExitCode() == 0 {
		t.Fatalf("verdict %s exits 0; a broken build must never be a green gate", got)
	}
}
