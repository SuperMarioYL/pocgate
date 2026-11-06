// Package evidence owns the closure attestation document: its schema, the
// canonical byte form that is hashed and signed, and the ed25519 signing and
// verification of that form.
//
// The document is the plan's ClosureEvidence record. Counters are JSON integers
// so the file can be read by jq and by another tool without a parser of its
// own: a hit rate is derived as fired/repeats, never stored as "3/3".
//
// Signing covers the canonical bytes, so verification needs no network, no
// clock, and no state beyond the file and a public key. The canonical form is
// one compact JSON object with fields in struct order, no trailing newline, and
// digest/signature blanked; the file additionally ends with a single newline.
// Verification recomputes the canonical form and rejects a file that differs by
// even one byte.
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Document is one closure attestation. Field order is part of the canonical
// form: reordering these fields would change every digest and signature.
type Document struct {
	Verdict    string     `json:"verdict"`
	Target     Target     `json:"target"`
	Oracles    []Oracle   `json:"oracles"`
	Regression Regression `json:"regression"`
	Labels     Labels     `json:"labels"`
	Env        Env        `json:"env"`
	Digest     string     `json:"digest"`
	Signature  string     `json:"signature"`
}

// Target records the object under test and the exact tree the patch was
// verified against.
type Target struct {
	Name           string `json:"name"`
	PatchSHA256    string `json:"patch_sha256"`
	PreTreeSHA256  string `json:"pre_tree_sha256"`
	PostTreeSHA256 string `json:"post_tree_sha256"`
	BuildCmd       string `json:"build_cmd"`
}

// Oracle is one PoC's before/after observation. Repeats is the number of runs
// per side and Fired is how many of them reproduced the flaw, so the hit rate is
// fired/repeats.
type Oracle struct {
	ID        string `json:"id"`
	PoCSHA256 string `json:"poc_sha256"`
	Repeats   int    `json:"repeats"`
	Pre       Side   `json:"pre"`
	Post      Side   `json:"post"`
}

// Side is the aggregate of one side's repeats. Exit and StdoutSHA are the final
// repeat's values, which for a deterministic PoC speaks for every run; Fired
// counts all repeats and DurationMS is their total cost.
type Side struct {
	Fired      int    `json:"fired"`
	Exit       int    `json:"exit"`
	StdoutSHA  string `json:"stdout_sha"`
	DurationMS int64  `json:"duration_ms"`
}

// Regression is the third leg: the failure set before and after the patch.
type Regression struct {
	Cmd         string   `json:"cmd"`
	Parser      string   `json:"parser"`
	Pre         TestSet  `json:"pre"`
	Post        TestSet  `json:"post"`
	NewFailures []string `json:"new_failures"`
}

// TestSet is one regression run's totals.
type TestSet struct {
	Total     int      `json:"total"`
	FailedIDs []string `json:"failed_ids"`
}

// Labels are operator-supplied metadata. pocgate records them and never infers
// a mapping; technique is absent until the operator sets it.
type Labels struct {
	CVE       string `json:"cve"`
	Technique string `json:"technique,omitempty"`
}

// Env records who produced the evidence and on what runtime.
type Env struct {
	POCGateVersion string            `json:"pocgate_version"`
	OS             string            `json:"os"`
	RuntimeProbe   map[string]string `json:"runtime_probe"`
	StartedAt      string            `json:"started_at"`
	EndedAt        string            `json:"ended_at"`
}

// ErrVerification marks any failure to authenticate an evidence file: a byte
// changed, a digest that no longer matches, or a signature that does not hold.
var ErrVerification = errors.New("evidence verification failed")

// Sign fills Digest and Signature. It signs the canonical bytes with the local
// ed25519 key, creating ~/.pocgate/key on first use, and returns the public key
// in base64 so the caller can publish it next to the document.
func Sign(d *Document) (publicKey string, err error) {
	canonicalBytes, err := canonical(*d)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonicalBytes)
	d.Digest = hex.EncodeToString(sum[:])

	priv, err := localKey()
	if err != nil {
		return "", err
	}
	d.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonicalBytes))
	pub := priv.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(pub), nil
}

// Bytes returns the canonical document including digest and signature, with no
// trailing newline. It is exactly what Write puts in the file.
func Bytes(d *Document) ([]byte, error) {
	return marshal(*d)
}

// Write signs d, writes it in canonical form with one trailing newline, and
// writes the public key to <path>.pub so another machine can verify offline.
func Write(path string, d *Document) error {
	pub, err := Sign(d)
	if err != nil {
		return err
	}
	doc, err := Bytes(d)
	if err != nil {
		return err
	}
	if err := writeFile(path, append(doc, '\n')); err != nil {
		return err
	}
	return writeFile(path+".pub", []byte(pub+"\n"))
}

// Verify authenticates the evidence file at path against an explicit public
// key. A key shipped next to the evidence is not a trust anchor: whoever can
// rewrite the document can rewrite the sibling .pub too, so the caller must
// name the key it expects. The file must also be byte-for-byte the canonical
// form, so a single altered byte fails.
func Verify(path, pubkeyPath string) (*Document, error) {
	if pubkeyPath == "" {
		return nil, fmt.Errorf("%w: an explicit public key is required (--pubkey); a key next to the evidence proves only that the files agree with each other", ErrVerification)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	body := bytes.TrimSuffix(raw, []byte("\n"))

	var d Document
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%w: parse %s: %v", ErrVerification, path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: %s carries data after the evidence object", ErrVerification, path)
	}
	if d.Digest == "" || d.Signature == "" {
		return nil, fmt.Errorf("%w: %s has no digest or signature", ErrVerification, path)
	}

	canonicalBytes, err := canonical(d)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonicalBytes)
	if hex.EncodeToString(sum[:]) != d.Digest {
		return nil, fmt.Errorf("%w: digest does not match the content of %s", ErrVerification, path)
	}

	sig, err := base64.StdEncoding.DecodeString(d.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: %s has a malformed signature", ErrVerification, path)
	}
	pub, err := readPublicKey(pubkeyPath)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, canonicalBytes, sig) {
		return nil, fmt.Errorf("%w: signature does not verify for %s", ErrVerification, path)
	}

	expected, err := Bytes(&d)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(append(expected, '\n'), raw) {
		return nil, fmt.Errorf("%w: %s is not in canonical form, so at least one byte differs", ErrVerification, path)
	}
	return &d, nil
}

// canonical encodes the signed part of d: compact JSON, field order preserved,
// no trailing newline, digest and signature blanked.
func canonical(d Document) ([]byte, error) {
	d.Digest = ""
	d.Signature = ""
	return marshal(d)
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// localKey loads ~/.pocgate/key, generating a key pair on first use.
func localKey() (ed25519.PrivateKey, error) {
	path, err := keyPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err == nil {
		return parsePrivateKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read signing key %s: %w", path, err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(priv) + "\n"
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return nil, fmt.Errorf("write signing key %s: %w", path, err)
	}
	return priv, nil
}

// readPublicKey reads an ed25519 public key from a base64 file.
func readPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("%w: public key is not valid base64", ErrVerification)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key is %d bytes, want %d", ErrVerification, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func keyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory for the signing key: %w", err)
	}
	return filepath.Join(home, ".pocgate", "key"), nil
}

// LocalKeyStatus reports where the signing key lives and whether it is present
// and usable. It never creates a key: a diagnostic must not change what it
// inspects. A non-nil error means a key file exists but cannot be used, which
// signing would fail on too.
func LocalKeyStatus() (path string, present bool, err error) {
	path, err = keyPath()
	if err != nil {
		return path, false, err
	}
	data, readErr := os.ReadFile(path)
	switch {
	case errors.Is(readErr, os.ErrNotExist):
		return path, false, nil
	case readErr != nil:
		return path, false, readErr
	}
	if _, err := parsePrivateKey(data); err != nil {
		return path, true, err
	}
	return path, true, nil
}

func parsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("signing key is not valid base64: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing key is %d bytes, want %d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".evidence-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
