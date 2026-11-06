// Command shop is a deliberately vulnerable fixture for pocgate. It is not a
// product: every flaw below is synthetic, exists only so the bundled PoCs have
// a target, and must never be copied into real code.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// The fixture listens on the port its pocgate.yaml declares.
const addr = "127.0.0.1:18081"

// Responses the PoCs look for. Each one is the proof that its flaw reproduced.
const (
	adminBody    = "ADMIN-ACTION-ALLOWED: deleted every order\n"
	internalBody = "INTERNAL-ONLY: db=sqlite://shop env=prod\n"
	secretBody   = "SHOP-INTERNAL-SECRET: do not serve this outside the root\n"
)

func main() {
	root, err := prepareData()
	if err != nil {
		log.Fatalf("prepare fixture data: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", index)
	mux.HandleFunc("/admin", admin)
	mux.HandleFunc("/file", files(root))
	mux.HandleFunc("/internal", internal)
	mux.HandleFunc("/fetch", fetch)

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	log.Printf("shop fixture listening on http://%s", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// prepareData lays out one public root and one secret file just outside it, so
// a traversal PoC has a known file to reach with "../secret.txt".
func prepareData() (root string, err error) {
	base := filepath.Join(os.TempDir(), "pocgate-shop-fixture")
	root = filepath.Join(base, "public")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello from the public root\n"), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(base, "secret.txt"), []byte(secretBody), 0o600); err != nil {
		return "", err
	}
	return root, nil
}

// index is the only page a browser needs. It deliberately does not link the
// internal endpoint.
func index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	fmt.Fprint(w, "shop fixture\n\nGET /admin\nGET /file?path=hello.txt\nGET /fetch?url=<url>\n")
}

// admin performs a privileged action without checking any credential. The
// authbypass PoC fires when this unauthenticated request succeeds.
func admin(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, adminBody)
}

// files serves a file under root. filepath.Join cleans "..", so a caller can
// walk out of root: the flaw the traversal PoC reproduces.
func files(root string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("path")
		if name == "" {
			http.Error(w, "missing path", http.StatusBadRequest)
			return
		}
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Write(data)
	}
}

// internal answers only in-process callers in a real service. Here it is
// reachable because nothing enforces that, which is what the SSRF PoC proves.
func internal(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, internalBody)
}

// fetch retrieves any caller-supplied URL: the SSRF flaw. A real service would
// allowlist outbound hosts.
func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		http.Error(w, "missing url", http.StatusBadRequest)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 64<<10))
}
