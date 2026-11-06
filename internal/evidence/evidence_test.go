package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sample() Document {
	return Document{
		Verdict: "CLOSED",
		Target: Target{
			Name:           "shop",
			PatchSHA256:    "14594f1e1c4fd7a4e72f8b6f401720528119e67827641ac08d4ea40f40e052c9",
			PreTreeSHA256:  "9ea280896cf2d3ec64ab6fd688f324bd8bd1e6c83e1b5c2889d0881760a74a35",
			PostTreeSHA256: "116de6848afecdb67a440d8a8f261aef8adaa923383d09bc70842482ba96f637",
			BuildCmd:       "go build -o shop main.go",
		},
		Oracles: []Oracle{{
			ID:        "authbypass",
			PoCSHA256: "3eee7fec298f2d367c20bbbb71808e70c5aec422b8eab24cb71226271e2d6be1",
			Repeats:   3,
			Pre:       Side{Fired: 3, Exit: 0, StdoutSHA: "c32a82fdc952778637c6641b6d3208e17144f3ac037fadf877825c9d2ff31582", DurationMS: 90},
			Post:      Side{Fired: 0, Exit: 2, StdoutSHA: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", DurationMS: 336},
		}},
		Regression: Regression{
			Cmd:         "go test main.go *_test.go",
			Parser:      "exit_code",
			Pre:         TestSet{Total: 1, FailedIDs: []string{}},
			Post:        TestSet{Total: 1, FailedIDs: []string{}},
			NewFailures: []string{},
		},
		Labels: Labels{CVE: "CVE-2026-00000"},
		Env: Env{
			POCGateVersion: "0.1.0",
			OS:             "darwin",
			RuntimeProbe:   map[string]string{"go": "go1.24.1"},
			StartedAt:      "2026-11-07T04:00:00Z",
			EndedAt:        "2026-11-07T04:00:12Z",
		},
	}
}

// writeEvidence signs a sample document under a private HOME and returns its
// path and bytes.
func writeEvidence(t *testing.T) (string, []byte) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "evidence", "latest.json")
	doc := sample()
	if err := Write(path, &doc); err != nil {
		t.Fatalf("Write: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, raw
}

func TestWriteProducesACanonicalSignedDocument(t *testing.T) {
	path, raw := writeEvidence(t)

	if !json.Valid(bytes.TrimSuffix(raw, []byte("\n"))) {
		t.Fatal("evidence is not valid JSON")
	}
	if bytes.Count(raw, []byte("\n")) != 1 || raw[len(raw)-1] != '\n' {
		t.Fatalf("evidence must be one line plus a trailing newline, got %q", raw)
	}

	doc, err := Verify(path, path+".pub")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if doc.Verdict != "CLOSED" {
		t.Fatalf("verdict = %q, want CLOSED", doc.Verdict)
	}
	if len(doc.Digest) != 64 {
		t.Fatalf("digest = %q, want 64 hex characters", doc.Digest)
	}
	if doc.Signature == "" {
		t.Fatal("signature is empty")
	}
	if _, err := os.Stat(path + ".pub"); err != nil {
		t.Fatalf("the public key must be published next to the evidence: %v", err)
	}
}

func TestCountersAreIntegers(t *testing.T) {
	_, raw := writeEvidence(t)

	if strings.Contains(string(raw), "3/3") {
		t.Fatal("a hit rate must be derived from fired/repeats, never stored as \"3/3\"")
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	oracles, ok := doc["oracles"].([]any)
	if !ok || len(oracles) == 0 {
		t.Fatal("oracles is not a JSON array")
	}
	pre, ok := oracles[0].(map[string]any)["pre"].(map[string]any)
	if !ok {
		t.Fatal("pre is not a JSON object")
	}
	if n, ok := pre["fired"].(float64); !ok || n != 3 {
		t.Fatalf("pre.fired = %v (%T), want the integer 3", pre["fired"], pre["fired"])
	}
	for _, field := range []string{"exit", "duration_ms"} {
		if _, ok := pre[field].(float64); !ok {
			t.Errorf("pre.%s is not a JSON number", field)
		}
	}
	if _, ok := oracles[0].(map[string]any)["repeats"].(float64); !ok {
		t.Error("oracle.repeats is not a JSON number")
	}
}

// TestVerifyRejectsAnyByteChange flips bytes in signed fields and in the
// canonical form itself: every one must fail.
func TestVerifyRejectsAnyByteChange(t *testing.T) {
	path, raw := writeEvidence(t)

	mutations := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "verdict value",
			mutate: func(b []byte) []byte {
				return bytes.Replace(b, []byte(`"CLOSED"`), []byte(`"CLOSEQ"`), 1)
			},
		},
		{
			name: "digest byte",
			mutate: func(b []byte) []byte {
				i := bytes.Index(b, []byte(`"digest":"`)) + len(`"digest":"`)
				b[i] = 'x'
				return b
			},
		},
		{
			name: "target name",
			mutate: func(b []byte) []byte {
				return bytes.Replace(b, []byte(`"shop"`), []byte(`"shoq"`), 1)
			},
		},
		{
			name: "extra whitespace",
			mutate: func(b []byte) []byte {
				return bytes.Replace(b, []byte(`"verdict"`), []byte(`"verdict" `), 1)
			},
		},
		{
			name: "trailing newline removed",
			mutate: func(b []byte) []byte {
				return bytes.TrimSuffix(b, []byte("\n"))
			},
		},
		{
			name: "appended newline",
			mutate: func(b []byte) []byte {
				return append(b, '\n')
			},
		},
		{
			name: "truncated",
			mutate: func(b []byte) []byte {
				return b[:len(b)/2]
			},
		},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			tampered := filepath.Join(t.TempDir(), "latest.json")
			if err := os.WriteFile(tampered, m.mutate(append([]byte(nil), raw...)), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(tampered, path+".pub"); err == nil {
				t.Fatal("Verify accepted a tampered document")
			} else if !errors.Is(err, ErrVerification) {
				t.Fatalf("error %v does not wrap ErrVerification", err)
			}
		})
	}
}

// TestVerifyOnAnotherMachine uses only the published public key: no local key
// exists, which is the cross-machine, offline case. The key must still be named
// explicitly; a sibling .pub is never discovered on its own.
func TestVerifyOnAnotherMachine(t *testing.T) {
	path, raw := writeEvidence(t)
	pub, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}

	elsewhere := t.TempDir()
	t.Setenv("HOME", t.TempDir()) // no ~/.pocgate/key here
	copied := filepath.Join(elsewhere, "latest.json")
	if err := os.WriteFile(copied, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	// Neither the local key nor a missing --pubkey can stand in for the
	// expected signer key.
	if _, err := Verify(copied, ""); !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify without --pubkey = %v, want ErrVerification", err)
	}

	if err := os.WriteFile(copied+".pub", pub, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(copied, ""); !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify discovered the sibling key; error = %v, want ErrVerification", err)
	}

	// The caller names the key it expects, wherever it was obtained.
	explicit := filepath.Join(elsewhere, "signer.pub")
	if err := os.WriteFile(explicit, pub, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(copied, explicit); err != nil {
		t.Fatalf("Verify with an explicit --pubkey: %v", err)
	}
}

// TestVerifyRejectsFreshlyResignedWithFreshSiblingKey is the trust-anchor
// regression: rewriting the document and re-signing it with a fresh key, while
// publishing that fresh key next to the file, must still fail against the key
// the verifier expects.
func TestVerifyRejectsFreshlyResignedWithFreshSiblingKey(t *testing.T) {
	path, _ := writeEvidence(t)
	expectedKey := path + ".pub"

	// Forge a closure claim and sign it with a key whose public half lands in
	// the attacker-controlled sibling file.
	t.Setenv("HOME", t.TempDir())
	forgedPath := filepath.Join(t.TempDir(), "latest.json")
	forged := sample()
	forged.Oracles[0].Pre.Fired = 99
	forged.Oracles[0].Post.Fired = 0
	if err := Write(forgedPath, &forged); err != nil {
		t.Fatalf("re-sign forged evidence: %v", err)
	}
	if _, err := os.Stat(forgedPath + ".pub"); err != nil {
		t.Fatalf("the forged evidence must carry its sibling key: %v", err)
	}

	if _, err := Verify(forgedPath, expectedKey); !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify with the expected key = %v, want ErrVerification", err)
	}
}

// TestVerifyRejectsWrongKey uses a different key than the signer's.
func TestVerifyRejectsWrongKey(t *testing.T) {
	path, _ := writeEvidence(t)

	// Sign a second document under a fresh HOME, so it carries another key.
	t.Setenv("HOME", t.TempDir())
	other := filepath.Join(t.TempDir(), "other.json")
	doc := sample()
	if err := Write(other, &doc); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path, other+".pub"); err == nil {
		t.Fatal("Verify accepted a signature from a different key")
	}
}
