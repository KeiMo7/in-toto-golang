package in_toto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----------------------------- test helpers -----------------------------

// newTestKey generates a fresh ed25519 in-toto key.
func newTestKey(t *testing.T) Key {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key := Key{}
	pemBlock, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	err = key.LoadKeyReader(
		bytes.NewReader(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pemBlock})),
		ed25519Scheme, []string{"sha256", "sha512"})
	require.NoError(t, err)
	// stash the private key for signing through a temporary key object
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	privKey := Key{}
	require.NoError(t, privKey.LoadKeyReader(
		bytes.NewReader(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})),
		ed25519Scheme, []string{"sha256", "sha512"}))
	require.Equal(t, key.KeyID, privKey.KeyID)
	testPrivateKeys.Store(key.KeyID, privKey)
	return key
}

// testPrivateKeys keeps the signing counterpart of generated public keys.
var testPrivateKeys sync.Map

func signerKey(t *testing.T, keyID string) Key {
	t.Helper()
	v, ok := testPrivateKeys.Load(keyID)
	require.True(t, ok, "no private key registered for %s", keyID)
	return v.(Key)
}

// newSignedLink builds a Metablock containing a link for stepName and signs
// it with the given private key.
func newSignedLink(t *testing.T, stepName string, signer Key) *Metablock {
	t.Helper()
	mb := &Metablock{Signed: Link{
		Type:        "link",
		Name:        stepName,
		Materials:   map[string]HashObj{},
		Products:    map[string]HashObj{},
		ByProducts:  map[string]interface{}{},
		Command:     []string{"echo", stepName},
		Environment: map[string]interface{}{},
	}}
	require.NoError(t, mb.Sign(signer))
	return mb
}

// writeLink writes metadata using the canonical short link file name.
func writeLink(t *testing.T, dir, stepName string, keyID string, md Metadata) string {
	t.Helper()
	path := filepath.Join(dir, fmt.Sprintf(LinkNameFormat, stepName, keyID))
	require.NoError(t, md.Dump(path))
	return path
}

// newCertChain creates an ed25519 root CA, intermediate CA and a leaf
// certificate. It returns the leaf as an in-toto Key (with certificate),
// the leaf private signing key, and the two cert pools.
func newCertChain(t *testing.T, commonName string) (Key, Key, *x509.CertPool, *x509.CertPool) {
	t.Helper()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootPub, rootPriv)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	intPub, intPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, intPub, rootPriv)
	require.NoError(t, err)
	intCert, err := x509.ParseCertificate(intDER)
	require.NoError(t, err)

	leafPub, leafPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"example"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intCert, leafPub, intPriv)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	// Build the in-toto leaf key from the public key and attach the
	// certificate.
	leafPubDER, err := x509.MarshalPKIXPublicKey(leafPub)
	require.NoError(t, err)
	certKey := Key{}
	require.NoError(t, certKey.LoadKeyReader(
		strings.NewReader(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: leafPubDER}))),
		ed25519Scheme, []string{"sha256", "sha512"}))
	certKey.KeyVal.Certificate = string(leafPEM)

	privDER, err := x509.MarshalPKCS8PrivateKey(leafPriv)
	require.NoError(t, err)
	leafSigner := Key{}
	require.NoError(t, leafSigner.LoadKeyReader(
		strings.NewReader(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))),
		ed25519Scheme, []string{"sha256", "sha512"}))
	leafSigner.KeyVal.Certificate = string(leafPEM)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	intPool := x509.NewCertPool()
	intPool.AddCert(intCert)

	_ = leafCert
	return certKey, leafSigner, rootPool, intPool
}

// certSignedLink returns a Metablink signed by the leaf, embedding the leaf
// certificate in the signature.
func certSignedLink(t *testing.T, stepName string, signer Key) *Metablock {
	t.Helper()
	mb := newSignedLink(t, stepName, signer)
	return mb
}

// countByReason tallies candidate reasons within a step report.
func countByReason(report StepLinkReport) map[LinkRejectReason]int {
	out := map[LinkRejectReason]int{}
	for _, c := range report.Candidates {
		out[c.Reason]++
	}
	return out
}

func findCandidate(report StepLinkReport, path string) (LinkCandidate, bool) {
	for _, c := range report.Candidates {
		if c.Path == path {
			return c, true
		}
	}
	return LinkCandidate{}, false
}

// ----------------------------- unit tests -----------------------------

func TestResolveLinkWorkers(t *testing.T) {
	// n <= 0: bounded by GOMAXPROCS and the default, at least 1.
	prev := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(prev)

	runtime.GOMAXPROCS(2)
	assert.Equal(t, 2, ResolveLinkWorkers(0))
	assert.Equal(t, 2, ResolveLinkWorkers(-5))

	runtime.GOMAXPROCS(100)
	assert.Equal(t, DefaultAggregationWorkers, ResolveLinkWorkers(0))
	assert.Equal(t, 8, DefaultAggregationWorkers)

	runtime.GOMAXPROCS(prev)

	// In-range values pass through.
	assert.Equal(t, 1, ResolveLinkWorkers(1))
	assert.Equal(t, 4, ResolveLinkWorkers(4))
	assert.Equal(t, MaxAggregationWorkers, ResolveLinkWorkers(MaxAggregationWorkers))
	assert.Equal(t, 64, MaxAggregationWorkers)

	// Above the cap.
	assert.Equal(t, MaxAggregationWorkers, ResolveLinkWorkers(65))
	assert.Equal(t, MaxAggregationWorkers, ResolveLinkWorkers(100000))
}

func TestAggregateHappyPath(t *testing.T) {
	dir := t.TempDir()
	key1 := newTestKey(t)
	key2 := newTestKey(t)

	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key1.KeyID: key1, key2.KeyID: key2},
		Steps: []Step{
			{
				Type:            "step",
				Threshold:       2,
				PubKeys:         []string{key1.KeyID, key2.KeyID},
				SupplyChainItem: SupplyChainItem{Name: "build"},
			},
		},
	}

	writeLink(t, dir, "build", key1.KeyID, newSignedLink(t, "build", signerKey(t, key1.KeyID)))
	writeLink(t, dir, "build", key2.KeyID, newSignedLink(t, "build", signerKey(t, key2.KeyID)))

	agg := LinkAggregator{LinkDir: dir}
	report, err := agg.Aggregate(context.Background(), layout)
	require.NoError(t, err)
	require.Len(t, report.Steps, 1)

	step := report.Steps[0]
	assert.Equal(t, "build", step.StepName)
	assert.Len(t, step.Candidates, 2)
	assert.Len(t, step.Verified, 2)
	require.NotNil(t, step.Verified)

	// Candidates sorted by path.
	assert.True(t, sort.SliceIsSorted(step.Candidates, func(i, j int) bool {
		return step.Candidates[i].Path < step.Candidates[j].Path
	}))
	for _, c := range step.Candidates {
		assert.Equal(t, LinkStateVerified, c.State)
		assert.Nil(t, c.Err)
	}

	got, ok := report.Step("build")
	assert.True(t, ok)
	assert.Equal(t, step, got)

	_, ok = report.Step("does-not-exist")
	assert.False(t, ok)
}

func TestAggregateThresholdFailure(t *testing.T) {
	dir := t.TempDir()
	key1 := newTestKey(t)
	key2 := newTestKey(t)

	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key1.KeyID: key1, key2.KeyID: key2},
		Steps: []Step{{
			Type:            "step",
			Threshold:       2,
			PubKeys:         []string{key1.KeyID, key2.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}

	// Only one valid link.
	writeLink(t, dir, "build", key1.KeyID, newSignedLink(t, "build", signerKey(t, key1.KeyID)))

	agg := LinkAggregator{LinkDir: dir}
	report, err := agg.Aggregate(context.Background(), layout)
	require.Error(t, err)
	require.NotNil(t, report, "a threshold failure must still return a report")

	var aggErr *LinkAggregationError
	require.True(t, errors.As(err, &aggErr))
	require.Len(t, aggErr.Failures, 1)
	failure := aggErr.Failures[0]
	assert.Equal(t, "build", failure.StepName)
	assert.Equal(t, 2, failure.Threshold)
	assert.Equal(t, 1, failure.Verified)
	assert.Equal(t, 0, failure.Rejected)
	assert.Contains(t, err.Error(), `step "build"`)
	assert.Contains(t, err.Error(), "threshold 2")
	assert.Contains(t, err.Error(), "verified 1")
	assert.Contains(t, err.Error(), "rejected 0")

	// Failed step still exposes a non-nil, empty verified map.
	assert.NotNil(t, report.Steps[0].Verified)
}

func TestAggregateNameMismatch(t *testing.T) {
	dir := t.TempDir()
	key := newTestKey(t)
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key.KeyID: key},
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			PubKeys:         []string{key.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}

	// File name claims "build" but the payload name is "other".
	mb := newSignedLink(t, "other", signerKey(t, key.KeyID))
	writeLink(t, dir, "build", key.KeyID, mb)

	report, err := LinkAggregator{LinkDir: dir}.Aggregate(context.Background(), layout)
	require.Error(t, err)
	c, ok := findCandidate(report.Steps[0], filepath.Join(dir, fmt.Sprintf(LinkNameFormat, "build", key.KeyID)))
	require.True(t, ok)
	assert.Equal(t, LinkStateRejected, c.State)
	assert.Equal(t, RejectNameMismatch, c.Reason)
	require.NotNil(t, c.Err)
}

func TestAggregateUnauthorizedSigner(t *testing.T) {
	dir := t.TempDir()
	authorized := newTestKey(t)
	unknown := newTestKey(t)

	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{authorized.KeyID: authorized},
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			PubKeys:         []string{authorized.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}

	writeLink(t, dir, "build", unknown.KeyID, newSignedLink(t, "build", signerKey(t, unknown.KeyID)))

	report, err := LinkAggregator{LinkDir: dir}.Aggregate(context.Background(), layout)
	require.Error(t, err)
	c := report.Steps[0].Candidates[0]
	assert.Equal(t, RejectUnauthorized, c.Reason)
	assert.Equal(t, LinkStateRejected, c.State)
	require.NotNil(t, c.Err)
}

func TestAggregateTamperedSignature(t *testing.T) {
	dir := t.TempDir()
	key := newTestKey(t)
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key.KeyID: key},
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			PubKeys:         []string{key.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}

	mb := newSignedLink(t, "build", signerKey(t, key.KeyID))
	mb.Signatures[0].Sig = "abcd"
	writeLink(t, dir, "build", key.KeyID, mb)

	report, err := LinkAggregator{LinkDir: dir}.Aggregate(context.Background(), layout)
	require.Error(t, err)
	c := report.Steps[0].Candidates[0]
	assert.Equal(t, RejectBadSignature, c.Reason)
	require.NotNil(t, c.Err)
}

func TestAggregateCertificatePath(t *testing.T) {
	dir := t.TempDir()
	certKey, leafSigner, rootPool, intPool := newCertChain(t, "functionary.example.com")

	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{},
		Steps: []Step{{
			Type:      "step",
			Threshold: 1,
			PubKeys:   []string{},
			CertificateConstraints: []CertificateConstraint{{
				CommonName:    "functionary.example.com",
				Organizations: []string{"example"},
				URIs:          []string{},
				Roots:         []string{"*"},
			}},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}

	writeLink(t, dir, "build", certKey.KeyID, certSignedLink(t, "build", leafSigner))

	agg := LinkAggregator{LinkDir: dir, RootCertPool: rootPool, IntermediateCertPool: intPool}
	report, err := agg.Aggregate(context.Background(), layout)
	require.NoError(t, err)
	c := report.Steps[0].Candidates[0]
	assert.Equal(t, LinkStateVerified, c.State, "unexpected: %v", c.Err)
	assert.Len(t, report.Steps[0].Verified, 1)

	// Constraint mismatch must reject with the certificate reason.
	badLayout := layout
	badLayout.Steps[0].CertificateConstraints[0].CommonName = "wrong.example.com"
	report2, err := LinkAggregator{LinkDir: dir, RootCertPool: rootPool, IntermediateCertPool: intPool}.
		Aggregate(context.Background(), badLayout)
	require.Error(t, err)
	c2 := report2.Steps[0].Candidates[0]
	assert.Equal(t, RejectCertificate, c2.Reason)
	require.NotNil(t, c2.Err)
}

func TestAggregateDuplicateSamePayload(t *testing.T) {
	dir := t.TempDir()
	id1, id2 := collidingKeyIDs(t)
	key1 := newKeyWithForcedID(t, id1)
	key2 := newKeyWithForcedID(t, id2)
	require.Equal(t, id1[:8], id2[:8])

	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key1.KeyID: key1, key2.KeyID: key2},
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			PubKeys:         []string{key1.KeyID, key2.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}

	// A single file whose two signatures share the 8-char prefix is a
	// signer mismatch and must be rejected without panicking.
	mb := newSignedLink(t, "build", signerKey(t, key1.KeyID))
	require.NoError(t, mb.Sign(signerKey(t, key2.KeyID)))
	path := writeLink(t, dir, "build", id1, mb)

	report, err := LinkAggregator{LinkDir: dir}.Aggregate(context.Background(), layout)
	require.Error(t, err)
	c, ok := findCandidate(report.Steps[0], path)
	require.True(t, ok)
	assert.Equal(t, LinkStateRejected, c.State)
	assert.Equal(t, RejectSignerMismatch, c.Reason)
	require.NotNil(t, c.Err)

	// A single valid candidate with the colliding short id verifies through
	// its own full key id and is retained unchanged.
	require.NoError(t, os.Remove(path))
	single := newSignedLink(t, "build", signerKey(t, key1.KeyID))
	path = writeLink(t, dir, "build", id1, single)
	report2, err2 := LinkAggregator{LinkDir: dir}.Aggregate(context.Background(), layout)
	require.NoError(t, err2)
	c2, ok := findCandidate(report2.Steps[0], path)
	require.True(t, ok)
	assert.Equal(t, LinkStateVerified, c2.State)
	assert.Equal(t, id1, c2.SignerKeyID)
}

// TestBuildReportDedup covers the equal-payload dedup branch directly: two
// verified candidates sharing one group key (step + full signer id) with
// identical canonical bytes keep the lexicographically smallest path and
// reject the other as a duplicate. Such a group cannot arise from two
// directory entries on disk because strict link file names encode the key
// id's 8-character prefix, so the branch is defensive logic.
func TestBuildReportDedup(t *testing.T) {
	dir := t.TempDir()
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}
	md := &Metablock{Signed: Link{Type: "link", Name: "build"}}
	p1 := filepath.Join(dir, "build.11111111.link")
	p2 := filepath.Join(dir, "build.22222222.link")
	results := []processedCandidate{
		{
			candidate:   LinkCandidate{Path: p1, StepName: "build", SignerKeyID: "k1", State: LinkStateVerified},
			metadata:    md,
			canonical:   []byte("identical-payload"),
			canonicalOK: true,
		},
		{
			candidate:   LinkCandidate{Path: p2, StepName: "build", SignerKeyID: "k1", State: LinkStateVerified},
			metadata:    md,
			canonical:   []byte("identical-payload"),
			canonicalOK: true,
		},
	}

	report, err := LinkAggregator{}.buildReport(layout, results)
	require.NoError(t, err)
	step := report.Steps[0]
	require.Len(t, step.Candidates, 2)
	assert.Len(t, step.Verified, 1)
	assert.Contains(t, step.Verified, "k1")
	assert.Equal(t, 1, countByReason(step)[RejectDuplicateFile])
	for _, c := range step.Candidates {
		switch c.Path {
		case p1:
			assert.Equal(t, LinkStateVerified, c.State)
		case p2:
			assert.Equal(t, LinkStateRejected, c.State)
			assert.Equal(t, RejectDuplicateFile, c.Reason)
			require.NotNil(t, c.Err)
		}
	}
}

// TestBuildReportConflict covers the different-payload conflict branch: the
// whole group becomes conflicting, nothing enters Verified and the step
// fails its threshold with a *LinkAggregationError.
func TestBuildReportConflict(t *testing.T) {
	dir := t.TempDir()
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}
	md := &Metablock{Signed: Link{Type: "link", Name: "build"}}
	p1 := filepath.Join(dir, "build.11111111.link")
	p2 := filepath.Join(dir, "build.22222222.link")
	results := []processedCandidate{
		{
			candidate:   LinkCandidate{Path: p1, StepName: "build", SignerKeyID: "k1", State: LinkStateVerified},
			metadata:    md,
			canonical:   []byte("payload-one"),
			canonicalOK: true,
		},
		{
			candidate:   LinkCandidate{Path: p2, StepName: "build", SignerKeyID: "k1", State: LinkStateVerified},
			metadata:    md,
			canonical:   []byte("payload-two"),
			canonicalOK: true,
		},
	}

	report, err := LinkAggregator{}.buildReport(layout, results)
	require.Error(t, err)
	var aggErr *LinkAggregationError
	require.True(t, errors.As(err, &aggErr))
	require.Len(t, aggErr.Failures, 1)
	assert.Equal(t, 0, aggErr.Failures[0].Verified)
	assert.Equal(t, 2, aggErr.Failures[0].Rejected)

	step := report.Steps[0]
	assert.Empty(t, step.Verified)
	require.Len(t, step.Candidates, 2)
	for _, c := range step.Candidates {
		assert.Equal(t, LinkStateConflicting, c.State)
		assert.Equal(t, RejectConflictingSigner, c.Reason)
		require.NotNil(t, c.Err)
	}
	_, ok1 := findCandidate(step, p1)
	_, ok2 := findCandidate(step, p2)
	assert.True(t, ok1 && ok2, "conflicting candidates stay auditable")
}

func TestAggregateSymlinkAndOversizeAndGarbage(t *testing.T) {
	dir := t.TempDir()
	key := newTestKey(t)
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key.KeyID: key},
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			PubKeys:         []string{key.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}

	good := writeLink(t, dir, "build", key.KeyID, newSignedLink(t, "build", signerKey(t, key.KeyID)))

	// Symlink pointing at the good link must not be followed.
	symPath := filepath.Join(dir, fmt.Sprintf("build.%s.link", "aaaaaaaa"))
	require.NoError(t, os.Symlink(good, symPath))

	// Oversize regular file with a valid-looking name.
	bigPath := filepath.Join(dir, "build.bbbbbbbb.link")
	require.NoError(t, os.WriteFile(bigPath, make([]byte, MaxLinkFileSize+1), 0644))

	// Unparseable garbage file with a valid-looking name.
	badPath := filepath.Join(dir, "build.cccccccc.link")
	require.NoError(t, os.WriteFile(badPath, []byte("{not json"), 0644))

	// File with an unrelated name must not enter the report at all.
	ignorePath := filepath.Join(dir, "README.txt")
	require.NoError(t, os.WriteFile(ignorePath, []byte("hi"), 0644))

	report, err := LinkAggregator{LinkDir: dir}.Aggregate(context.Background(), layout)
	// The valid link still satisfies the threshold; the malformed entries
	// only affect themselves.
	require.NoError(t, err)
	step := report.Steps[0]
	// Exactly the four pattern-matching names, the stray file excluded.
	assert.Len(t, step.Candidates, 4)

	byPath := map[string]LinkCandidate{}
	for _, c := range step.Candidates {
		byPath[c.Path] = c
	}
	assert.Equal(t, RejectNotRegularFile, byPath[symPath].Reason)
	assert.Equal(t, RejectFileTooLarge, byPath[bigPath].Reason)
	assert.Equal(t, RejectLoadFailed, byPath[badPath].Reason)
	assert.Equal(t, LinkStateVerified, byPath[good].State)
	for p, c := range byPath {
		if p != good {
			require.NotNil(t, c.Err, "path %s should carry an error", p)
		}
	}
}

func TestAggregateEmptyDirAndNoSteps(t *testing.T) {
	// Empty directory with a step: threshold failure, but the directory itself
	// is readable.
	dir := t.TempDir()
	key := newTestKey(t)
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key.KeyID: key},
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			PubKeys:         []string{key.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}
	report, err := LinkAggregator{LinkDir: dir}.Aggregate(context.Background(), layout)
	require.Error(t, err)
	require.NotNil(t, report)
	assert.Len(t, report.Steps[0].Candidates, 0)
	assert.NotNil(t, report.Steps[0].Verified)

	// Layout without steps: non-nil empty report and nil error.
	emptyLayout := Layout{Type: "layout", Expires: "3000-01-01T00:00:00Z"}
	report2, err2 := LinkAggregator{LinkDir: dir}.Aggregate(context.Background(), emptyLayout)
	require.NoError(t, err2)
	require.NotNil(t, report2)
	assert.Len(t, report2.Steps, 0)
}

func TestAggregateThresholdLessThanOne(t *testing.T) {
	dir := t.TempDir()
	key := newTestKey(t)
	writeLink(t, dir, "build", key.KeyID, newSignedLink(t, "build", signerKey(t, key.KeyID)))

	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key.KeyID: key},
		Steps: []Step{{
			Type:            "step",
			Threshold:       0,
			PubKeys:         []string{key.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}
	report, err := LinkAggregator{LinkDir: dir}.Aggregate(context.Background(), layout)
	require.Error(t, err)
	var aggErr *LinkAggregationError
	require.True(t, errors.As(err, &aggErr))
	assert.Equal(t, 0, aggErr.Failures[0].Threshold)
	require.NotNil(t, report)
}

func TestAggregateBadDirectory(t *testing.T) {
	key := newTestKey(t)
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key.KeyID: key},
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			PubKeys:         []string{key.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}

	missing := filepath.Join(t.TempDir(), "does-not-exist")
	report, err := LinkAggregator{LinkDir: missing}.Aggregate(context.Background(), layout)
	require.Error(t, err)
	assert.Nil(t, report)
	assert.Contains(t, err.Error(), missing)

	// A regular file in place of the directory.
	file := filepath.Join(t.TempDir(), "afile")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0644))
	report2, err2 := LinkAggregator{LinkDir: file}.Aggregate(context.Background(), layout)
	require.Error(t, err2)
	assert.Nil(t, report2)
	assert.Contains(t, err2.Error(), file)
}

func TestAggregateLongestStepNameMatch(t *testing.T) {
	dir := t.TempDir()
	shortKey := newTestKey(t)
	longKey := newTestKey(t)

	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{shortKey.KeyID: shortKey, longKey.KeyID: longKey},
		Steps: []Step{
			{Type: "step", Threshold: 1, PubKeys: []string{shortKey.KeyID},
				SupplyChainItem: SupplyChainItem{Name: "build"}},
			{Type: "step", Threshold: 1, PubKeys: []string{longKey.KeyID},
				SupplyChainItem: SupplyChainItem{Name: "build-extra"}},
		},
	}

	// "build-extra.<hex>.link" must belong to the longest matching step.
	writeLink(t, dir, "build-extra", longKey.KeyID,
		newSignedLink(t, "build-extra", signerKey(t, longKey.KeyID)))
	writeLink(t, dir, "build", shortKey.KeyID,
		newSignedLink(t, "build", signerKey(t, shortKey.KeyID)))

	report, err := LinkAggregator{LinkDir: dir}.Aggregate(context.Background(), layout)
	require.NoError(t, err)
	names := []string{report.Steps[0].StepName, report.Steps[1].StepName}
	assert.Equal(t, []string{"build", "build-extra"}, names)
	assert.Len(t, report.Steps[1].Candidates, 1)
	assert.Len(t, report.Steps[0].Candidates, 1)
}

func TestAggregateVerifiedLinksIsolation(t *testing.T) {
	dir := t.TempDir()
	key := newTestKey(t)
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key.KeyID: key},
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			PubKeys:         []string{key.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}
	writeLink(t, dir, "build", key.KeyID, newSignedLink(t, "build", signerKey(t, key.KeyID)))

	agg := LinkAggregator{LinkDir: dir}
	report, err := agg.Aggregate(context.Background(), layout)
	require.NoError(t, err)

	first := report.VerifiedLinks()
	require.Len(t, first["build"], 1)
	first["build"]["injected"] = nil
	first["new-step"] = map[string]Metadata{}

	second := report.VerifiedLinks()
	_, polluted := second["build"]["injected"]
	assert.False(t, polluted)
	_, ok := second["new-step"]
	assert.False(t, ok)
}

func TestAggregateDeterministic(t *testing.T) {
	dir := t.TempDir()
	key1 := newTestKey(t)
	key2 := newTestKey(t)
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key1.KeyID: key1, key2.KeyID: key2},
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			PubKeys:         []string{key1.KeyID, key2.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}
	writeLink(t, dir, "build", key1.KeyID, newSignedLink(t, "build", signerKey(t, key1.KeyID)))
	writeLink(t, dir, "build", key2.KeyID, newSignedLink(t, "build", signerKey(t, key2.KeyID)))

	snapshot := func(r *LinkReport, err error) string {
		require.NoError(t, err)
		var b strings.Builder
		for _, s := range r.Steps {
			b.WriteString(s.StepName + "|")
			verified := make([]string, 0, len(s.Verified))
			for k := range s.Verified {
				verified = append(verified, k)
			}
			sort.Strings(verified)
			b.WriteString(strings.Join(verified, ",") + "|")
			for _, c := range s.Candidates {
				b.WriteString(c.Path + ":" + string(c.State) + ":" + string(c.Reason) + ";")
			}
			b.WriteString("\n")
		}
		return b.String()
	}

	// 50 repeated calls must be identical, across worker counts 1, 4 and 64.
	var baseline string
	run := 0
	for _, workers := range []int{1, 4, 64} {
		for i := 0; i < 50; i++ {
			r, err := LinkAggregator{LinkDir: dir, Workers: workers}.
				Aggregate(context.Background(), layout)
			snap := snapshot(r, err)
			if run == 0 {
				baseline = snap
			} else {
				assert.Equal(t, baseline, snap)
			}
			run++
		}
	}
}

func TestAggregateConcurrentSameValue(t *testing.T) {
	dir := t.TempDir()
	key1 := newTestKey(t)
	key2 := newTestKey(t)
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key1.KeyID: key1, key2.KeyID: key2},
		Steps: []Step{{
			Type:            "step",
			Threshold:       2,
			PubKeys:         []string{key1.KeyID, key2.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}
	writeLink(t, dir, "build", key1.KeyID, newSignedLink(t, "build", signerKey(t, key1.KeyID)))
	writeLink(t, dir, "build", key2.KeyID, newSignedLink(t, "build", signerKey(t, key2.KeyID)))

	agg := LinkAggregator{LinkDir: dir, Workers: 4}
	results := make([]string, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r, err := agg.Aggregate(context.Background(), layout)
			require.NoError(t, err)
			parts := []string{}
			for _, s := range r.Steps {
				ids := make([]string, 0, len(s.Verified))
				for k := range s.Verified {
					ids = append(ids, k)
				}
				sort.Strings(ids)
				parts = append(parts, s.StepName+":"+strings.Join(ids, ","))
			}
			results[idx] = strings.Join(parts, "|")
		}(i)
	}
	wg.Wait()
	for i := 1; i < len(results); i++ {
		assert.Equal(t, results[0], results[i])
	}
}

func TestAggregateCancellation(t *testing.T) {
	dir := t.TempDir()
	key := newTestKey(t)
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key.KeyID: key},
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			PubKeys:         []string{key.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}
	writeLink(t, dir, "build", key.KeyID, newSignedLink(t, "build", signerKey(t, key.KeyID)))

	// Pre-cancelled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := LinkAggregator{LinkDir: dir}.Aggregate(ctx, layout)
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, report)

	// Cancellation during execution: a deadline that is already exceeded.
	dlCtx, dlCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer dlCancel()
	report2, err2 := LinkAggregator{LinkDir: dir}.Aggregate(dlCtx, layout)
	require.ErrorIs(t, err2, context.DeadlineExceeded)
	assert.Nil(t, report2)
}

func TestAggregateNoGoroutineLeak(t *testing.T) {
	dir := t.TempDir()
	key := newTestKey(t)
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key.KeyID: key},
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			PubKeys:         []string{key.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}
	for i := 0; i < 5; i++ {
		writeLink(t, dir, fmt.Sprintf("build-%d", i), key.KeyID, newSignedLink(t, "build", signerKey(t, key.KeyID)))
	}
	// The above files intentionally don't match the step name; add a valid one.
	writeLink(t, dir, "build", key.KeyID, newSignedLink(t, "build", signerKey(t, key.KeyID)))

	before := runtime.NumGoroutine()
	for i := 0; i < 10; i++ {
		_, err := LinkAggregator{LinkDir: dir, Workers: 8}.Aggregate(context.Background(), layout)
		if err != nil {
			// Threshold failures are expected for the unmatched files; only
			// context/directory errors would indicate a leak.
			var aggErr *LinkAggregationError
			require.True(t, errors.As(err, &aggErr))
		}
	}
	// Give the scheduler a chance to reap finished goroutines.
	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()
	assert.LessOrEqual(t, after, before+2, "goroutine count grew from %d to %d", before, after)
}

func TestVerifyLinkSignatureThresholdsRegression(t *testing.T) {
	// First link validates through the public key path.
	pubKey := newTestKey(t)

	// Second link validates only through the certificate path.
	certKey, leafSigner, rootPool, intPool := newCertChain(t, "functionary.example.com")

	step := Step{
		Type:      "step",
		Threshold: 2,
		PubKeys:   []string{pubKey.KeyID},
		CertificateConstraints: []CertificateConstraint{{
			CommonName:    "functionary.example.com",
			Organizations: []string{"example"},
			URIs:          []string{},
			Roots:         []string{"*"},
		}},
		SupplyChainItem: SupplyChainItem{Name: "build"},
	}
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{pubKey.KeyID: pubKey},
		Steps:   []Step{step},
	}

	pubLink := newSignedLink(t, "build", signerKey(t, pubKey.KeyID))
	certLink := certSignedLink(t, "build", leafSigner)
	// Sanity: the cert key is not in the layout's public keys, so only the
	// certificate path can authorize it.
	_, certInLayout := layout.Keys[certKey.KeyID]
	require.False(t, certInLayout)

	stepsMetadata := map[string]map[string]Metadata{
		"build": {
			pubKey.KeyID:  pubLink,
			certKey.KeyID: certLink,
		},
	}

	// The old implementation carried isAuthorizedSignature across candidates
	// and skipped the certificate path after a pubkey success. The fixed
	// implementation must return both links.
	verified, err := VerifyLinkSignatureThesholds(layout, stepsMetadata, rootPool, intPool)
	require.NoError(t, err)
	require.Len(t, verified["build"], 2)
	assert.Contains(t, verified["build"], pubKey.KeyID)
	assert.Contains(t, verified["build"], certKey.KeyID)

	// A link whose payload name differs from the step must be rejected.
	renamed := newSignedLink(t, "other-step", signerKey(t, pubKey.KeyID))
	badMetadata := map[string]map[string]Metadata{
		"build": {
			pubKey.KeyID:  renamed,
			certKey.KeyID: certLink,
		},
	}
	_, err = VerifyLinkSignatureThesholds(layout, badMetadata, rootPool, intPool)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build")
}

func TestInTotoVerifyIntegration(t *testing.T) {
	// Baseline: the shipped demo layout still verifies end to end.
	layoutMb, err := LoadMetadata("demo.layout")
	require.NoError(t, err)
	var layoutKey Key
	require.NoError(t, layoutKey.LoadKey("alice.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"}))
	summary, err := InTotoVerify(layoutMb, map[string]Key{layoutKey.KeyID: layoutKey},
		".", "", map[string]string{}, [][]byte{}, testOSisWindows())
	require.NoError(t, err)
	_, ok := summary.GetPayload().(Link)
	assert.True(t, ok)

	// DSSE layout path.
	dsseMb, err := LoadMetadata("demo.dsse.layout")
	require.NoError(t, err)
	_, err = InTotoVerify(dsseMb, map[string]Key{layoutKey.KeyID: layoutKey},
		".", "", map[string]string{}, [][]byte{}, testOSisWindows())
	require.NoError(t, err)
}

func TestInTotoVerifyAggregationFailures(t *testing.T) {
	dir := t.TempDir()
	key := newTestKey(t)

	buildLayout := func(threshold int) (Metadata, map[string]Key) {
		layout := Layout{
			Type:    "layout",
			Expires: "3000-01-01T00:00:00Z",
			Keys:    map[string]Key{key.KeyID: key},
			Steps: []Step{{
				Type:      "step",
				Threshold: threshold,
				PubKeys:   []string{key.KeyID},
				SupplyChainItem: SupplyChainItem{
					Name:              "build",
					ExpectedMaterials: [][]string{{"DISALLOW", "*"}},
					ExpectedProducts:  [][]string{{"DISALLOW", "*"}},
				},
			}},
			Inspect: []Inspection{},
		}
		mb := &Metablock{Signed: layout}
		require.NoError(t, mb.Sign(signerKey(t, key.KeyID)))
		return mb, map[string]Key{key.KeyID: key}
	}

	// Rename the link file so no candidate matches the step.
	layoutEnv, layoutKeys := buildLayout(1)
	mb := newSignedLink(t, "build", signerKey(t, key.KeyID))
	wrongName := filepath.Join(dir, fmt.Sprintf("package.%s.link", key.KeyID[:8]))
	require.NoError(t, mb.Dump(wrongName))
	_, err := InTotoVerify(layoutEnv, layoutKeys, dir, "", map[string]string{}, [][]byte{}, false)
	require.Error(t, err)
	var aggErr *LinkAggregationError
	require.True(t, errors.As(err, &aggErr), "got %T: %v", err, err)

	// Link.Name mismatch causes the same aggregation error type.
	require.NoError(t, os.Remove(wrongName))
	layoutEnv2, layoutKeys2 := buildLayout(1)
	mismatched := newSignedLink(t, "other", signerKey(t, key.KeyID))
	writeLink(t, dir, "build", key.KeyID, mismatched)
	_, err = InTotoVerify(layoutEnv2, layoutKeys2, dir, "", map[string]string{}, [][]byte{}, false)
	require.Error(t, err)
	require.True(t, errors.As(err, &aggErr))
}

func TestInTotoVerifySublayoutStillWorks(t *testing.T) {
	superMb, err := LoadMetadata("super.layout")
	require.NoError(t, err)
	layout, ok := superMb.GetPayload().(Layout)
	require.True(t, ok)

	// The shipped super.layout is an unsigned fixture, so the sublayout
	// expansion is exercised through the same flow as the upstream tests:
	// load, verify thresholds (the hardened path) and expand sublayouts.
	sublayoutDir := fmt.Sprintf(SublayoutLinkDirFormat, "sub_layout",
		"70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680")
	require.NoError(t, os.Mkdir(sublayoutDir, 0700))
	defer func() { assert.NoError(t, os.RemoveAll(sublayoutDir)) }()
	require.NoError(t, os.WriteFile(filepath.Join(sublayoutDir, "write-code.b7d643de.link"),
		mustReadFile(t, "write-code.b7d643de.link"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sublayoutDir, "package.d3ffd108.link"),
		mustReadFile(t, "package.d3ffd108.link"), 0644))

	stepsMetadata, err := LoadLinksForLayout(layout, ".")
	require.NoError(t, err)
	rootPool, intPool, err := LoadLayoutCertificates(layout, [][]byte{})
	require.NoError(t, err)
	verified, err := VerifyLinkSignatureThesholds(layout, stepsMetadata, rootPool, intPool)
	require.NoError(t, err)

	result, err := VerifySublayouts(layout, verified, ".", [][]byte{}, testOSisWindows())
	require.NoError(t, err)
	for _, stepData := range result {
		for _, metadata := range stepData {
			_, ok := metadata.GetPayload().(Link)
			assert.True(t, ok, "sublayout expansion must produce summary links")
		}
	}
}

func TestInTotoVerifyWithDirectoryEmptyStillFails(t *testing.T) {
	layoutMb, err := LoadMetadata("demo.layout")
	require.NoError(t, err)
	var layoutKey Key
	require.NoError(t, layoutKey.LoadKey("alice.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"}))

	empty := t.TempDir()
	_, err = InTotoVerifyWithDirectory(layoutMb, map[string]Key{layoutKey.KeyID: layoutKey},
		".", empty, "", map[string]string{}, [][]byte{}, false)
	require.Error(t, err)
}

// mustReadFile reads a file or fails the test.
func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return b
}

func TestAggregateMalformedMetadata(t *testing.T) {
	dir := t.TempDir()
	key := newTestKey(t)
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key.KeyID: key},
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			PubKeys:         []string{key.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}
	name := func(short string) string {
		return filepath.Join(dir, "build."+short+".link")
	}

	// Empty signature list.
	require.NoError(t, os.WriteFile(name("11111111"),
		[]byte(`{"signed":{"_type":"link","name":"build","materials":{},`+
			`"products":{},"byproducts":{},"command":[],"environment":{}},`+
			`"signatures":[]}`), 0644))

	// Unknown payload type.
	require.NoError(t, os.WriteFile(name("22222222"),
		[]byte(`{"signed":{"_type":"mystery"},"signatures":[{"keyid":"22222222","sig":"aa"}]}`), 0644))

	// Missing signed part.
	require.NoError(t, os.WriteFile(name("33333333"),
		[]byte(`{"signatures":[]}`), 0644))

	report, err := LinkAggregator{LinkDir: dir}.Aggregate(context.Background(), layout)
	require.Error(t, err)
	step := report.Steps[0]
	require.Len(t, step.Candidates, 3)
	for _, c := range step.Candidates {
		assert.Equal(t, LinkStateRejected, c.State)
		assert.Equal(t, RejectLoadFailed, c.Reason)
		require.NotNil(t, c.Err)
	}
}

func TestAggregateSublayoutPayloadSkipsNameCheck(t *testing.T) {
	dir := t.TempDir()
	key := newTestKey(t)
	signer := signerKey(t, key.KeyID)

	// A layout payload (sublayout) signed like a link file. Its embedded
	// name is irrelevant; the name check must be skipped for layouts.
	sublayout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Steps:   []Step{},
		Inspect: []Inspection{},
	}
	mb := &Metablock{Signed: sublayout}
	require.NoError(t, mb.Sign(signer))
	writeLink(t, dir, "build", key.KeyID, mb)

	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key.KeyID: key},
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			PubKeys:         []string{key.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}
	report, err := LinkAggregator{LinkDir: dir}.Aggregate(context.Background(), layout)
	require.NoError(t, err)
	c := report.Steps[0].Candidates[0]
	assert.Equal(t, LinkStateVerified, c.State)
	_, ok := report.Steps[0].Verified[key.KeyID]
	assert.True(t, ok)
}

func TestAggregateEmptyLinkDirDefaultsToCurrentDir(t *testing.T) {
	key := newTestKey(t)
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key.KeyID: key},
		Steps: []Step{{
			Type:            "step",
			Threshold:       1,
			PubKeys:         []string{key.KeyID},
			SupplyChainItem: SupplyChainItem{Name: "build"},
		}},
	}
	// No matching files in the current working directory: the aggregator
	// must read "." without error and report a threshold failure instead.
	report, err := LinkAggregator{}.Aggregate(context.Background(), layout)
	require.Error(t, err)
	require.NotNil(t, report)
	assert.Equal(t, "build", report.Steps[0].StepName)
}

func TestAggregateStepsFollowLayoutOrder(t *testing.T) {
	dir := t.TempDir()
	key := newTestKey(t)
	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{key.KeyID: key},
		Steps: []Step{
			{Type: "step", Threshold: 1, PubKeys: []string{key.KeyID},
				SupplyChainItem: SupplyChainItem{Name: "zzz"}},
			{Type: "step", Threshold: 1, PubKeys: []string{key.KeyID},
				SupplyChainItem: SupplyChainItem{Name: "aaa"}},
		},
	}
	writeLink(t, dir, "aaa", key.KeyID, newSignedLink(t, "aaa", signerKey(t, key.KeyID)))
	writeLink(t, dir, "zzz", key.KeyID, newSignedLink(t, "zzz", signerKey(t, key.KeyID)))

	report, err := LinkAggregator{LinkDir: dir}.Aggregate(context.Background(), layout)
	require.NoError(t, err)
	require.Len(t, report.Steps, 2)
	// Layout order, not alphabetical: zzz was declared first.
	assert.Equal(t, "zzz", report.Steps[0].StepName)
	assert.Equal(t, "aaa", report.Steps[1].StepName)
}

// newKeyWithForcedID generates an ed25519 key and overrides both the public
// and the private signing key's KeyID with keyID. Signature verification
// looks up the layout key by key id and uses its key material, so forcing
// the id lets tests construct full key ids that share an 8-character prefix
// (the only way two strict "<step>.<8hex>.link" file names can collide).
func newKeyWithForcedID(t *testing.T, keyID string) Key {
	t.Helper()
	key := newTestKey(t)
	signer, ok := testPrivateKeys.Load(key.KeyID)
	require.True(t, ok)
	signingKey := signer.(Key)
	key.KeyID = keyID
	signingKey.KeyID = keyID
	testPrivateKeys.Store(keyID, signingKey)
	return key
}

// collidingKeyIDs returns two distinct full key IDs sharing the same first
// eight lowercase hex characters.
func collidingKeyIDs(t *testing.T) (string, string) {
	t.Helper()
	prefix := "0123abcd"
	return prefix + "11111111111111111111111111111111111111111111111111111111",
		prefix + "22222222222222222222222222222222222222222222222222222222"
}
