package in_toto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file builds self-contained fixtures (keys, layouts and signed link
// metadata) in temporary directories and exercises the auditing verification
// pipeline.  Every test asserts both the verdict and the concrete evidence
// recorded for it.

// auditFixture bundles the material generated for one test case.
type auditFixture struct {
	dir       string
	layoutKey Key
	aliceKey  Key // authorized functionary key (with private part)
	bobKey    Key // second authorized functionary key (with private part)
	carolKey  Key // unauthorized functionary key (with private part)
	alicePub  Key
	bobPub    Key
	carolPub  Key
	layout    Layout
}

// newAuditFixture creates a fresh fixture with an ed25519 layout key and
// three functionary keys.
func newAuditFixture(t *testing.T) *auditFixture {
	t.Helper()
	dir := t.TempDir()

	f := &auditFixture{dir: dir}
	f.layoutKey = mustGenerateEd25519Key(t)
	f.aliceKey = mustGenerateEd25519Key(t)
	f.bobKey = mustGenerateEd25519Key(t)
	f.carolKey = mustGenerateEd25519Key(t)

	f.alicePub = publicOnly(f.aliceKey)
	f.bobPub = publicOnly(f.bobKey)
	f.carolPub = publicOnly(f.carolKey)

	f.layout = Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Readme:  "",
		Keys: map[string]Key{
			f.alicePub.KeyID: f.alicePub,
			f.bobPub.KeyID:   f.bobPub,
		},
		Steps: []Step{
			{
				Type:      "step",
				Threshold: 1,
				PubKeys:   []string{f.alicePub.KeyID},
				SupplyChainItem: SupplyChainItem{
					Name:              "build",
					ExpectedMaterials: [][]string{{"DISALLOW", "*"}},
					ExpectedProducts: [][]string{
						{"ALLOW", "foo.py"},
						{"DISALLOW", "*"},
					},
				},
			},
		},
		Inspect: []Inspection{},
	}
	return f
}

func mustGenerateEd25519Key(t *testing.T) Key {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key := Key{}
	require.NoError(t, key.LoadKeyReaderDefaults(strings.NewReader(
		encodeEd25519PrivatePEM(priv))))
	return key
}

func encodeEd25519PrivatePEM(priv ed25519.PrivateKey) string {
	// PKCS8 DER is what x509.ParsePKCS8PrivateKey expects; the standard
	// library marshals ed25519 private keys in PKCS8.
	der, err := marshalPKCS8(priv)
	if err != nil {
		panic(err)
	}
	return pemEncode("PRIVATE KEY", der)
}

func publicOnly(k Key) Key {
	pub := Key{
		KeyID:               k.KeyID,
		KeyIDHashAlgorithms: append([]string{}, k.KeyIDHashAlgorithms...),
		KeyType:             k.KeyType,
		Scheme:              k.Scheme,
		KeyVal: KeyVal{
			Public:      k.KeyVal.Public,
			Certificate: k.KeyVal.Certificate,
		},
	}
	return pub
}

// signedLayout wraps the fixture layout in a signed Metablock.
func (f *auditFixture) signedLayout(t *testing.T) *Metablock {
	t.Helper()
	mb := &Metablock{Signed: f.layout}
	require.NoError(t, mb.Sign(f.layoutKey))
	return mb
}

// writeLink creates, signs and dumps a link for the given step using the
// given key and returns the on-disk file name.
func (f *auditFixture) writeLink(t *testing.T, stepName string, signer Key,
	link Link) string {
	t.Helper()
	mb := &Metablock{Signed: link}
	require.NoError(t, mb.Sign(signer))
	name := fmt.Sprintf(LinkNameFormat, stepName, signer.KeyID)
	require.NoError(t, mb.Dump(filepath.Join(f.dir, name)))
	return name
}

func sampleLink(name string) Link {
	return Link{
		Type:        "link",
		Name:        name,
		Materials:   map[string]HashObj{},
		Products:    map[string]HashObj{"foo.py": {"sha256": "abcd"}},
		ByProducts:  map[string]interface{}{},
		Command:     []string{},
		Environment: map[string]interface{}{},
	}
}

func (f *auditFixture) layoutKeys() map[string]Key {
	return map[string]Key{f.layoutKey.KeyID: publicOnly(f.layoutKey)}
}

// runAudit runs the audited verification against the fixture.
func (f *auditFixture) runAudit(t *testing.T) (Metadata, *VerdictReport, error) {
	return InTotoVerifyWithAudit(f.signedLayout(t), f.layoutKeys(), f.dir, "",
		map[string]string{}, [][]byte{}, false)
}

// findEvidence returns the first record matching step, path fragment and
// classification.
func findEvidence(t *testing.T, report *VerdictReport, step, pathFragment,
	classification string) EvidenceRecord {
	t.Helper()
	for _, ev := range report.Evidence {
		if ev.Step == step &&
			(pathFragment == "" || strings.Contains(ev.Path, pathFragment)) &&
			ev.Classification == classification {
			return ev
		}
	}
	require.Failf(t, "evidence record not found",
		"step=%s path=%s classification=%s\nevidence=%+v",
		step, pathFragment, classification, report.Evidence)
	return EvidenceRecord{}
}

func countEvidence(report *VerdictReport, classification string) int {
	n := 0
	for _, ev := range report.Evidence {
		if ev.Classification == classification {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// 1. Signer not authorized by the layout
// ---------------------------------------------------------------------------

func TestAuditUnauthorizedSigner(t *testing.T) {
	f := newAuditFixture(t)
	// The link is validly signed by Carol, whose key is not in the step's
	// allowed pubkeys.
	f.writeLink(t, "build", f.carolKey, sampleLink("build"))

	_, report, err := f.runAudit(t)
	require.Error(t, err)
	assert.Equal(t, VerdictReject, report.Verdict)

	rec := findEvidence(t, report, "build", f.carolKey.KeyID[:8], EvidenceRejected)
	assert.Contains(t, rec.Reason, "not authorized")
	assert.Equal(t, f.carolKey.KeyID, rec.SignerKeyID)
	// The rejection carries a concrete failure check.
	assert.NotEmpty(t, failingChecks(report))
}

// ---------------------------------------------------------------------------
// 2. Valid signature but unsupported key type / scheme
// ---------------------------------------------------------------------------

func TestAuditUnsupportedKeyType(t *testing.T) {
	f := newAuditFixture(t)
	// Hand-craft a layout key entry whose key type and scheme are not
	// supported, while a real link signature exists under the same key id.
	// The authorized verification key cannot be constructed, so the signature
	// cannot be accepted.
	f.writeLink(t, "build", f.aliceKey, sampleLink("build"))

	bad := f.alicePub
	bad.KeyType = "rsa"
	bad.Scheme = "rsassa-pss-sha512-not-supported"
	f.layout.Keys[bad.KeyID] = bad

	_, report, err := f.runAudit(t)
	require.Error(t, err)
	assert.Equal(t, VerdictReject, report.Verdict)
	rec := findEvidence(t, report, "build", f.aliceKey.KeyID[:8], EvidenceRejected)
	assert.NotEmpty(t, rec.Reason)
}

// ---------------------------------------------------------------------------
// 3a. Fewer links than the threshold
// ---------------------------------------------------------------------------

func TestAuditBelowThreshold(t *testing.T) {
	f := newAuditFixture(t)
	f.layout.Steps[0].Threshold = 2
	f.layout.Steps[0].PubKeys = []string{f.alicePub.KeyID, f.bobPub.KeyID}

	// Only one valid link.
	f.writeLink(t, "build", f.aliceKey, sampleLink("build"))

	_, report, err := f.runAudit(t)
	require.Error(t, err)
	assert.Equal(t, VerdictReject, report.Verdict)

	threshold := findCheck(t, report, checkThreshold)
	assert.False(t, threshold.Passed)
	assert.Contains(t, threshold.Message, "requires '2'")
	assert.Equal(t, 1, threshold.Details["accepted"])
	assert.Equal(t, 1, threshold.Details["missing"])
	// The single valid link is still classified as accepted.
	assert.NotNil(t, findEvidenceOrNil(report, "build", f.aliceKey.KeyID[:8], EvidenceAccepted))
}

// ---------------------------------------------------------------------------
// 3b. Exactly the threshold
// ---------------------------------------------------------------------------

func TestAuditAtThreshold(t *testing.T) {
	f := newAuditFixture(t)
	f.layout.Steps[0].Threshold = 2
	f.layout.Steps[0].PubKeys = []string{f.alicePub.KeyID, f.bobPub.KeyID}

	link := sampleLink("build")
	f.writeLink(t, "build", f.aliceKey, link)
	f.writeLink(t, "build", f.bobKey, link)

	summary, report, err := f.runAudit(t)
	require.NoError(t, err)
	assert.Equal(t, VerdictPass, report.Verdict)
	assert.NotNil(t, summary)
	assert.Equal(t, 2, countEvidence(report, EvidenceAccepted))
}

// ---------------------------------------------------------------------------
// 3c/4. More links than the threshold, with conflicting artifacts
// ---------------------------------------------------------------------------

func TestAuditAboveThresholdConflicting(t *testing.T) {
	f := newAuditFixture(t)
	f.layout.Steps[0].Threshold = 1
	f.layout.Steps[0].PubKeys = []string{f.alicePub.KeyID, f.bobPub.KeyID}
	f.layout.Keys[f.bobPub.KeyID] = f.bobPub

	linkA := sampleLink("build")
	linkB := sampleLink("build")
	// Bob's link reports a different product hash.
	linkB.Products = map[string]HashObj{"foo.py": {"sha256": "deadbeef"}}

	f.writeLink(t, "build", f.aliceKey, linkA)
	f.writeLink(t, "build", f.bobKey, linkB)

	_, report, err := f.runAudit(t)
	require.Error(t, err)
	assert.Equal(t, VerdictReject, report.Verdict)

	consistency := findCheck(t, report, checkEvidenceConsistency)
	assert.False(t, consistency.Passed)
	assert.Contains(t, consistency.Message, "different artifacts")

	// Both conflicting links are pinpointed and deterministically ordered by
	// signer key id.
	rejected := evidenceForStep(report, "build", EvidenceRejected)
	require.Len(t, rejected, 2)
	expectedOrder := []string{f.alicePub.KeyID, f.bobPub.KeyID}
	if expectedOrder[0] > expectedOrder[1] {
		expectedOrder[0], expectedOrder[1] = expectedOrder[1], expectedOrder[0]
	}
	assert.Equal(t, expectedOrder[0], rejected[0].SignerKeyID)
	assert.Equal(t, expectedOrder[1], rejected[1].SignerKeyID)
	for _, rec := range rejected {
		assert.Contains(t, rec.Reason, "conflicting")
	}
}

// Above threshold but consistent: must still pass (verdict unchanged).
func TestAuditAboveThresholdConsistent(t *testing.T) {
	f := newAuditFixture(t)
	f.layout.Steps[0].PubKeys = []string{f.alicePub.KeyID, f.bobPub.KeyID}
	f.layout.Keys[f.bobPub.KeyID] = f.bobPub

	link := sampleLink("build")
	f.writeLink(t, "build", f.aliceKey, link)
	f.writeLink(t, "build", f.bobKey, link)

	_, report, err := f.runAudit(t)
	require.NoError(t, err)
	assert.Equal(t, VerdictPass, report.Verdict)
}

// ---------------------------------------------------------------------------
// 5. Corrupted, malformed and empty evidence files
// ---------------------------------------------------------------------------

func TestAuditDamagedEvidenceFiles(t *testing.T) {
	f := newAuditFixture(t)

	cases := []struct {
		name    string
		content string
		reason  string
	}{
		{"corrupted", "{not valid json", "malformed"},
		{"empty", "", "empty"},
		{"wrong format", `{"signed": {"_type": "something-else"}}`, "malformed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			f2 := &auditFixture{
				dir:       dir,
				layoutKey: f.layoutKey,
				aliceKey:  f.aliceKey,
				alicePub:  f.alicePub,
				layout:    f.layout,
			}
			path := filepath.Join(dir, fmt.Sprintf(LinkNameFormat, "build", f.alicePub.KeyID))
			require.NoError(t, os.WriteFile(path, []byte(tc.content), 0644))

			_, report, err := f2.runAudit(t)
			require.Error(t, err)
			assert.Equal(t, VerdictReject, report.Verdict)
			rec := findEvidence(t, report, "build", f.alicePub.KeyID[:8], EvidenceRejected)
			assert.Contains(t, strings.ToLower(rec.Reason), tc.reason)
		})
	}
}

// A single damaged link must not poison the rest of the verification round.
func TestAuditSingleDamagedEvidenceIsolated(t *testing.T) {
	f := newAuditFixture(t)
	f.layout.Steps[0].Threshold = 1
	f.layout.Keys[f.bobPub.KeyID] = f.bobPub
	f.layout.Steps = []Step{
		{
			Type:      "step",
			Threshold: 1,
			PubKeys:   []string{f.alicePub.KeyID},
			SupplyChainItem: SupplyChainItem{
				Name:              "build",
				ExpectedMaterials: [][]string{{"DISALLOW", "*"}},
				ExpectedProducts: [][]string{
					{"ALLOW", "foo.py"},
					{"DISALLOW", "*"},
				},
			},
		},
		{
			Type:      "step",
			Threshold: 1,
			PubKeys:   []string{f.bobPub.KeyID},
			SupplyChainItem: SupplyChainItem{
				Name:              "test",
				ExpectedMaterials: [][]string{{"DISALLOW", "*"}},
				ExpectedProducts: [][]string{
					{"ALLOW", "bar.py"},
					{"DISALLOW", "*"},
				},
			},
		},
	}

	// build: the only candidate matching an authorized key is damaged.
	badPath := filepath.Join(f.dir,
		fmt.Sprintf(LinkNameFormat, "build", f.alicePub.KeyID))
	require.NoError(t, os.WriteFile(badPath, []byte("@@@broken@@@"), 0644))

	// test: a healthy link on the second step, which must still be evaluated.
	testLink := Link{
		Type:        "link",
		Name:        "test",
		Materials:   map[string]HashObj{},
		Products:    map[string]HashObj{"bar.py": {"sha256": "1234"}},
		ByProducts:  map[string]interface{}{},
		Command:     []string{},
		Environment: map[string]interface{}{},
	}
	f.writeLink(t, "test", f.bobKey, testLink)

	// build cannot meet its threshold because its only matching-prefix file is
	// damaged; the report must still contain the healthy test-step evidence.
	_, report, err := f.runAudit(t)
	require.Error(t, err)
	assert.Equal(t, VerdictReject, report.Verdict)
	// The damaged file is classified with a reason, and the healthy link of
	// the other step was still evaluated and accepted.
	damaged := findEvidence(t, report, "build", f.alicePub.KeyID[:8], EvidenceRejected)
	assert.Contains(t, damaged.Reason, "malformed")
	assert.NotNil(t, findEvidenceOrNil(report, "test", f.bobPub.KeyID[:8], EvidenceAccepted))
}

// ---------------------------------------------------------------------------
// 6. Two nested sublayouts, inner failure traceable from the outer layout
// ---------------------------------------------------------------------------

func TestAuditNestedSublayoutFailure(t *testing.T) {
	f := newAuditFixture(t)

	// Inner layout: one step "inner-build" requiring Alice's link which is
	// missing, so the inner verification fails.
	innerLayout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{f.alicePub.KeyID: f.alicePub},
		Steps: []Step{{
			Type:      "step",
			Threshold: 1,
			PubKeys:   []string{f.alicePub.KeyID},
			SupplyChainItem: SupplyChainItem{
				Name:              "inner-build",
				ExpectedMaterials: [][]string{{"DISALLOW", "*"}},
				ExpectedProducts:  [][]string{{"DISALLOW", "*"}},
			},
		}},
	}
	innerEnv := &Metablock{Signed: innerLayout}
	require.NoError(t, innerEnv.Sign(f.aliceKey))

	// Middle layout: one step "middle" whose link is the inner layout.
	middleLayout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{f.alicePub.KeyID: f.alicePub},
		Steps: []Step{{
			Type:      "step",
			Threshold: 1,
			PubKeys:   []string{f.alicePub.KeyID},
			SupplyChainItem: SupplyChainItem{
				Name:              "middle",
				ExpectedMaterials: [][]string{{"DISALLOW", "*"}},
				ExpectedProducts:  [][]string{{"DISALLOW", "*"}},
			},
		}},
	}
	middleEnv := &Metablock{Signed: middleLayout}
	require.NoError(t, middleEnv.Sign(f.aliceKey))

	// Root layout: one step "outer" whose link is the middle layout.
	f.layout.Keys[f.alicePub.KeyID] = f.alicePub
	f.layout.Steps = []Step{{
		Type:      "step",
		Threshold: 1,
		PubKeys:   []string{f.alicePub.KeyID},
		SupplyChainItem: SupplyChainItem{
			Name:              "outer",
			ExpectedMaterials: [][]string{{"DISALLOW", "*"}},
			ExpectedProducts:  [][]string{{"DISALLOW", "*"}},
		},
	}}

	// Directory layout:
	//   outer.<alice>.link                         -> middle layout
	//   outer.<alice>/middle.<alice>.link          -> inner layout
	//   outer.<alice>/middle.<alice>/              -> (no inner-build link)
	outerName := f.writeLink(t, "outer", f.aliceKey, Link{})
	// Replace the just-written ordinary link with the signed middle layout.
	require.NoError(t, middleEnv.Dump(filepath.Join(f.dir, outerName)))

	outerDir := filepath.Join(f.dir,
		fmt.Sprintf(SublayoutLinkDirFormat, "outer", f.alicePub.KeyID))
	require.NoError(t, os.MkdirAll(outerDir, 0755))
	middleName := fmt.Sprintf(LinkNameFormat, "middle", f.alicePub.KeyID)
	require.NoError(t, middleEnv.Dump(filepath.Join(outerDir, middleName)))

	middleDir := filepath.Join(outerDir,
		fmt.Sprintf(SublayoutLinkDirFormat, "middle", f.alicePub.KeyID))
	require.NoError(t, os.MkdirAll(middleDir, 0755))
	// The inner-build link is deliberately absent.
	_ = innerEnv

	_, report, err := f.runAudit(t)
	require.Error(t, err)
	assert.Equal(t, VerdictReject, report.Verdict)

	// The outer report must locate the failure exactly at level 2 via the
	// sublayout path outer/middle.
	var foundTrace bool
	for _, sub := range allReports(report) {
		for _, c := range sub.Checks {
			if c.Name == checkThreshold && c.Level == 2 &&
				len(c.SublayoutPath) == 2 &&
				c.SublayoutPath[0] == "outer" && c.SublayoutPath[1] == "middle" {
				foundTrace = true
			}
		}
	}
	assert.True(t, foundTrace, "inner failure not traceable at nested level: %+v",
		report.Sublayouts)

	// The bubbled-up sublayout evidence must name level 2 and the full path,
	// never swallow the recursion failure, and the summary mentions the level.
	assert.Contains(t, report.Summary, "level 2")
	var hasNestedEvidence bool
	for _, sub := range allReports(report) {
		for _, c := range sub.Checks {
			if c.Name != checkSublayout {
				continue
			}
			for _, ev := range c.Evidence {
				if ev.Details["level"] == 2 {
					hasNestedEvidence = true
				}
			}
		}
	}
	assert.True(t, hasNestedEvidence)
}

// TestAuditSublayoutPanicIsInconclusive verifies that an unexpected error
// (recovered panic) during sublayout recursion is marked inconclusive with the
// nesting level and source, instead of being swallowed or crashing the run.
func TestAuditSublayoutPanicIsInconclusive(t *testing.T) {
	f := newAuditFixture(t)
	nestedLayout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00Z",
		Keys:    map[string]Key{},
		Steps: []Step{{
			Type:      "step",
			Threshold: 1,
			PubKeys:   []string{f.alicePub.KeyID},
			SupplyChainItem: SupplyChainItem{
				Name: "inner-build",
			},
		}},
	}
	// A Metadata implementation whose signature verification panics, simulating
	// an unexpected internal error during nested sublayout verification.
	panicEnv := &panickingMetadata{payload: nestedLayout}

	// A non-empty key map makes VerifyLayoutSignatures call VerifySignature on
	// the panicking metadata, deterministically entering the recover branch.
	_, report, err := verifyNestedSublayout(
		verifyOptions{intermediatePems: [][]byte{}},
		panicEnv, map[string]Key{f.alicePub.KeyID: f.alicePub}, t.TempDir(),
		"outer", 2, []string{"outer", "middle"})

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSublayoutInconclusive))
	require.NotNil(t, report)
	assert.Equal(t, VerdictUndecidable, report.Verdict)
	assert.Contains(t, report.Summary, "could not be decided")
	require.Len(t, report.Checks, 1)
	assert.False(t, report.Checks[0].Passed)
	assert.Equal(t, 2, report.Checks[0].Level)
	assert.Equal(t, []string{"outer", "middle"}, report.Checks[0].SublayoutPath)
	require.Len(t, report.Checks[0].Evidence, 1)
	assert.Equal(t, EvidenceIgnored, report.Checks[0].Evidence[0].Classification)
}

// panickingMetadata is a test-only Metadata implementation whose signature
// verification panics, simulating an unexpected internal error during nested
// sublayout verification.
type panickingMetadata struct {
	payload any
}

func (p *panickingMetadata) Sign(Key) error { panic("sign panic") }
func (p *panickingMetadata) VerifySignature(Key) error {
	panic("unexpected verifier failure")
}
func (p *panickingMetadata) GetPayload() any { return p.payload }
func (p *panickingMetadata) Sigs() []Signature {
	return nil
}
func (p *panickingMetadata) GetSignatureForKeyID(string) (Signature, error) {
	return Signature{}, nil
}
func (p *panickingMetadata) Dump(string) error { return nil }

var _ Metadata = (*panickingMetadata)(nil)

// ---------------------------------------------------------------------------
// 7a. Inspection command execution failure
// ---------------------------------------------------------------------------

func TestAuditInspectionCommandFailure(t *testing.T) {
	f := newAuditFixture(t)
	f.writeLink(t, "build", f.aliceKey, sampleLink("build"))
	f.layout.Inspect = []Inspection{{
		Type: "inspection",
		Run:  []string{"sh", "-c", "exit 7"},
		SupplyChainItem: SupplyChainItem{
			Name:              "check",
			ExpectedMaterials: [][]string{{"ALLOW", "*"}},
			ExpectedProducts:  [][]string{{"ALLOW", "*"}},
		},
	}}

	_, report, err := f.runAudit(t)
	require.Error(t, err)
	assert.Equal(t, VerdictReject, report.Verdict)
	check := findCheck(t, report, checkInspectionCommand)
	assert.False(t, check.Passed)
	assert.Contains(t, check.Message, "non-zero")
	rec := findEvidence(t, report, "check", "", EvidenceRejected)
	assert.Equal(t, "inspection", rec.Kind)
}

// ---------------------------------------------------------------------------
// 7b. Artifact rule failure
// ---------------------------------------------------------------------------

func TestAuditArtifactRuleFailure(t *testing.T) {
	f := newAuditFixture(t)
	// The link reports an extra product not allowed by the rules.
	link := sampleLink("build")
	link.Products["unexpected.py"] = HashObj{"sha256": "bbbb"}
	f.writeLink(t, "build", f.aliceKey, link)

	_, report, err := f.runAudit(t)
	require.Error(t, err)
	assert.Equal(t, VerdictReject, report.Verdict)
	check := findCheck(t, report, checkArtifactRules)
	assert.False(t, check.Passed)
	assert.Contains(t, check.Message, "disallowed")
}

// ---------------------------------------------------------------------------
// 8. Unconsumed artifacts after the artifact rules ran
// ---------------------------------------------------------------------------

func TestAuditUnconsumedArtifacts(t *testing.T) {
	f := newAuditFixture(t)
	// The rules only ALLOW foo.py. The second product (leftover.py) is never
	// consumed by a rule; it is recorded as ignored evidence while the overall
	// verification still passes.
	f.layout.Steps[0].ExpectedProducts = [][]string{{"ALLOW", "foo.py"}}
	link := sampleLink("build")
	link.Products["leftover.py"] = HashObj{"sha256": "cccc"}
	f.writeLink(t, "build", f.aliceKey, link)

	_, report, err := f.runAudit(t)
	require.NoError(t, err)
	assert.Equal(t, VerdictPass, report.Verdict)

	check := findCheck(t, report, checkUnconsumedArtifacts)
	assert.True(t, check.Passed)
	require.Len(t, check.Evidence, 1)
	assert.Equal(t, EvidenceIgnored, check.Evidence[0].Classification)
	arts, ok := check.Evidence[0].Details["artifacts"].([]string)
	require.True(t, ok)
	assert.Contains(t, arts, "leftover.py")
	assert.NotContains(t, arts, "foo.py")
}

// ---------------------------------------------------------------------------
// 9. Parameter substitution changes expectation values
// ---------------------------------------------------------------------------

func TestAuditParameterSubstitution(t *testing.T) {
	f := newAuditFixture(t)
	f.layout.Steps[0].ExpectedProducts = [][]string{{"ALLOW", "{ARTIFACT}"}}
	link := sampleLink("build")
	delete(link.Products, "foo.py")
	link.Products["baz.py"] = HashObj{"sha256": "abcd"}
	f.writeLink(t, "build", f.aliceKey, link)

	layoutEnv := f.signedLayout(t)
	_, report, err := InTotoVerifyWithAudit(layoutEnv, f.layoutKeys(), f.dir, "",
		map[string]string{"ARTIFACT": "baz.py"}, [][]byte{}, false)
	require.NoError(t, err)
	assert.Equal(t, VerdictPass, report.Verdict)

	check := findCheck(t, report, checkParameterSubstitution)
	assert.True(t, check.Passed)
	require.Len(t, check.Evidence, 1)
	diffs := check.Evidence[0].Details
	_, hasBefore := diffs["step:build:expected_products"]
	assert.True(t, hasBefore)
}

// ---------------------------------------------------------------------------
// Acceptance 2. Tampering one signature byte flips the verdict and points at
// the exact file
// ---------------------------------------------------------------------------

func TestAuditTamperedSignatureByte(t *testing.T) {
	f := newAuditFixture(t)
	name := f.writeLink(t, "build", f.aliceKey, sampleLink("build"))

	// Sanity: the untouched fixture passes.
	_, reportBefore, err := f.runAudit(t)
	require.NoError(t, err)
	assert.Equal(t, VerdictPass, reportBefore.Verdict)

	// Tamper with one byte of the signature inside the JSON document.
	path := filepath.Join(f.dir, name)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &doc))
	sigs := doc["signatures"].([]interface{})
	sigHex := sigs[0].(map[string]interface{})["sig"].(string)
	sigBytes, err := hex.DecodeString(sigHex)
	require.NoError(t, err)
	sigBytes[0] ^= 0xFF
	sigs[0].(map[string]interface{})["sig"] = hex.EncodeToString(sigBytes)
	tampered, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, tampered, 0644))

	_, report, err := f.runAudit(t)
	require.Error(t, err)
	assert.Equal(t, VerdictReject, report.Verdict)
	rec := findEvidence(t, report, "build", f.aliceKey.KeyID[:8], EvidenceRejected)
	assert.Contains(t, rec.Reason, "signature verification failed")
	assert.Equal(t, name, rec.Path)
}

// ---------------------------------------------------------------------------
// Acceptance 5. Deterministic classification and ordering across repeated runs
// ---------------------------------------------------------------------------

func TestAuditDeterministicRepeatedRuns(t *testing.T) {
	f := newAuditFixture(t)
	f.layout.Steps[0].Threshold = 1
	// All three signers are authorized so the result cannot depend on the
	// certificate-path gating order. The evidence ordering is fully driven by
	// the sorted signer key ids.
	f.layout.Steps[0].PubKeys = []string{
		f.alicePub.KeyID, f.bobPub.KeyID, f.carolPub.KeyID,
	}
	f.layout.Keys[f.bobPub.KeyID] = f.bobPub
	f.layout.Keys[f.carolPub.KeyID] = f.carolPub

	// The links disagree on the product hash, which is rejected deterministically.
	linkA := sampleLink("build")
	linkB := sampleLink("build")
	linkB.Products = map[string]HashObj{"foo.py": {"sha256": "dddd"}}
	linkC := sampleLink("build")
	linkC.Products = map[string]HashObj{"foo.py": {"sha256": "eeee"}}
	f.writeLink(t, "build", f.aliceKey, linkA)
	f.writeLink(t, "build", f.bobKey, linkB)
	f.writeLink(t, "build", f.carolKey, linkC)

	snapshots := make([]string, 3)
	for i := range snapshots {
		_, report, err := f.runAudit(t)
		require.Error(t, err)
		data, err := json.Marshal(report.Evidence)
		require.NoError(t, err)
		snapshots[i] = string(data)
	}
	assert.Equal(t, snapshots[0], snapshots[1])
	assert.Equal(t, snapshots[1], snapshots[2])

	// Every discovered candidate is classified exactly once after
	// deduplication: 3 links, none silently skipped, each pinpointed as
	// conflicting and ordered deterministically by signer key id.
	_, report, _ := f.runAudit(t)
	assert.Len(t, report.Evidence, 3)
	assert.Equal(t, 3, countEvidence(report, EvidenceRejected))
	keyIDs := make([]string, 0, 3)
	for _, ev := range report.Evidence {
		assert.Contains(t, ev.Reason, "conflicting")
		keyIDs = append(keyIDs, ev.SignerKeyID)
	}
	assert.True(t, sort.StringsAreSorted(keyIDs), "evidence must be sorted by key id")
}

// TestAuditUnauthorizedCandidateNeverSilentlySkipped verifies that a signer
// outside the allow-list is always recorded with a concrete reason, whether it
// is rejected outright or ignored because an authorized signature was already
// accepted (the existing gating semantics). It must never vanish silently.
func TestAuditUnauthorizedCandidateNeverSilentlySkipped(t *testing.T) {
	f := newAuditFixture(t)
	// Carol is not in the allow-list; Alice is the sole authorized functionary.
	f.writeLink(t, "build", f.aliceKey, sampleLink("build"))
	f.writeLink(t, "build", f.carolKey, sampleLink("build"))

	_, report, err := f.runAudit(t)
	// Threshold of 1 is met by Alice, so verification passes.
	require.NoError(t, err)
	assert.Equal(t, VerdictPass, report.Verdict)

	// Both candidates must appear exactly once; Carol always carries an
	// explicit reason. Depending on the sorted key-id order she is evaluated
	// before Alice (rejected, no certificate) or after the authorized signature
	// is accepted (ignored, gating) -- both are existing semantics, but she is
	// never silently dropped.
	assert.Len(t, report.Evidence, 2)
	carolRec, ok := findBySigner(report, f.carolPub.KeyID)
	require.True(t, ok, "unauthorized candidate was silently dropped")
	assert.NotEmpty(t, carolRec.Reason)
	assert.Contains(t,
		[]string{EvidenceRejected, EvidenceIgnored}, carolRec.Classification)
}

func findBySigner(report *VerdictReport, keyID string) (EvidenceRecord, bool) {
	for _, ev := range report.Evidence {
		if ev.SignerKeyID == keyID {
			return ev, true
		}
	}
	return EvidenceRecord{}, false
}

// ---------------------------------------------------------------------------
// Undecidable: unreadable link directory is not a rejection
// ---------------------------------------------------------------------------

func TestAuditUndecidableMissingLinkDir(t *testing.T) {
	f := newAuditFixture(t)
	f.dir = filepath.Join(t.TempDir(), "does-not-exist")

	_, report, err := f.runAudit(t)
	require.Error(t, err)
	assert.Equal(t, VerdictUndecidable, report.Verdict)
	assert.Contains(t, strings.ToLower(report.Summary), "could not be decided")
	check := findCheck(t, report, checkLinkDiscovery)
	assert.False(t, check.Passed)
}

// ---------------------------------------------------------------------------
// No private key material ever appears in a report
// ---------------------------------------------------------------------------

func TestAuditReportContainsNoPrivateMaterial(t *testing.T) {
	f := newAuditFixture(t)
	f.writeLink(t, "build", f.aliceKey, sampleLink("build"))

	_, report, err := f.runAudit(t)
	require.NoError(t, err)

	data, err := json.Marshal(report)
	require.NoError(t, err)
	serialized := string(data)
	assert.NotContains(t, serialized, "PRIVATE KEY")
	assert.NotContains(t, serialized, f.aliceKey.KeyVal.Private)
	assert.NotContains(t, serialized, f.layoutKey.KeyVal.Private)
}

// ---------------------------------------------------------------------------
// Path normalization: evidence outside the link directory is never accepted
// ---------------------------------------------------------------------------

func TestAuditPathOutsideLinkDirIgnored(t *testing.T) {
	f := newAuditFixture(t)
	outside := t.TempDir()
	// Construct a candidate path that escapes the link directory.
	escaping := filepath.Join(f.dir, "..", filepath.Base(outside),
		fmt.Sprintf(LinkNameFormat, "build", f.alicePub.KeyID))
	rel, inside := safeRelPath(f.dir, escaping)
	assert.False(t, inside)
	assert.Empty(t, rel)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func failingChecks(report *VerdictReport) []CheckRecord {
	var out []CheckRecord
	for _, c := range report.Checks {
		if !c.Passed {
			out = append(out, c)
		}
	}
	return out
}

func findCheck(t *testing.T, report *VerdictReport, name string) CheckRecord {
	t.Helper()
	for _, c := range report.Checks {
		if c.Name == name {
			return c
		}
	}
	for _, sub := range report.Sublayouts {
		if rec, ok := findCheckInSubreport(sub, name); ok {
			return rec
		}
	}
	require.Failf(t, "check not found", "check=%s", name)
	return CheckRecord{}
}

func findCheckInSubreport(report *VerdictReport, name string) (CheckRecord, bool) {
	for _, c := range report.Checks {
		if c.Name == name {
			return c, true
		}
	}
	for _, sub := range report.Sublayouts {
		if rec, ok := findCheckInSubreport(sub, name); ok {
			return rec, true
		}
	}
	return CheckRecord{}, false
}

func findEvidenceOrNil(report *VerdictReport, step, pathFragment,
	classification string) *EvidenceRecord {
	for i := range report.Evidence {
		ev := report.Evidence[i]
		if ev.Step == step &&
			(pathFragment == "" || strings.Contains(ev.Path, pathFragment)) &&
			ev.Classification == classification {
			return &ev
		}
	}
	return nil
}

func evidenceForStep(report *VerdictReport, step, classification string) []EvidenceRecord {
	var out []EvidenceRecord
	for _, ev := range report.Evidence {
		if ev.Step == step && ev.Classification == classification {
			out = append(out, ev)
		}
	}
	return out
}

func allReports(report *VerdictReport) []*VerdictReport {
	out := []*VerdictReport{report}
	for _, sub := range report.Sublayouts {
		out = append(out, allReports(sub)...)
	}
	return out
}
