package in_toto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditParityWithInTotoVerify guarantees the hard constraint that the
// auditing entry point never loosens or tightens the verdict: for the same
// inputs the audited pipeline must fail exactly when InTotoVerify fails and
// pass exactly when it passes.
func TestAuditParityWithInTotoVerify(t *testing.T) {
	// Build a matrix of scenarios and run both implementations against each.
	type scenario struct {
		name   string
		mutate func(f *auditFixture)
	}

	scenarios := []scenario{
		{"healthy single link", func(f *auditFixture) {
			f.writeLink(t, "build", f.aliceKey, sampleLink("build"))
		}},
		{"unauthorized signer", func(f *auditFixture) {
			f.writeLink(t, "build", f.carolKey, sampleLink("build"))
		}},
		{"no links at all", func(f *auditFixture) {}},
		{"threshold of two with one link", func(f *auditFixture) {
			f.layout.Steps[0].Threshold = 2
			f.layout.Steps[0].PubKeys = []string{f.alicePub.KeyID, f.bobPub.KeyID}
			f.writeLink(t, "build", f.aliceKey, sampleLink("build"))
		}},
		{"threshold of two with two consistent links", func(f *auditFixture) {
			f.layout.Steps[0].Threshold = 2
			f.layout.Steps[0].PubKeys = []string{f.alicePub.KeyID, f.bobPub.KeyID}
			link := sampleLink("build")
			f.writeLink(t, "build", f.aliceKey, link)
			f.writeLink(t, "build", f.bobKey, link)
		}},
		{"two links with conflicting artifacts", func(f *auditFixture) {
			f.layout.Steps[0].PubKeys = []string{f.alicePub.KeyID, f.bobPub.KeyID}
			linkA := sampleLink("build")
			linkB := sampleLink("build")
			linkB.Products = map[string]HashObj{"foo.py": {"sha256": "eeee"}}
			f.writeLink(t, "build", f.aliceKey, linkA)
			f.writeLink(t, "build", f.bobKey, linkB)
		}},
		{"artifact rule violation", func(f *auditFixture) {
			link := sampleLink("build")
			link.Products["extra.py"] = HashObj{"sha256": "ffff"}
			f.writeLink(t, "build", f.aliceKey, link)
		}},
		{"failing inspection command", func(f *auditFixture) {
			f.writeLink(t, "build", f.aliceKey, sampleLink("build"))
			f.layout.Inspect = []Inspection{{
				Type: "inspection",
				Run:  []string{"sh", "-c", "exit 3"},
				SupplyChainItem: SupplyChainItem{
					Name:              "check",
					ExpectedMaterials: [][]string{{"ALLOW", "*"}},
					ExpectedProducts:  [][]string{{"ALLOW", "*"}},
				},
			}}
		}},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			// Two independent copies of the fixture so each implementation gets
			// identical on-disk state.
			fA := newAuditFixture(t)
			fB := newAuditFixture(t)
			// Keep both fixtures' layouts in lockstep by reusing the same
			// mutation through a shared key-independent layout change. The
			// mutation uses the fixture's own keys, so apply it to both.
			sc.mutate(fA)
			sc.mutate(fB)

			layoutEnvA := fA.signedLayout(t)
			_, classicErr := InTotoVerify(layoutEnvA, fA.layoutKeys(), fA.dir, "",
				map[string]string{}, [][]byte{}, false)

			layoutEnvB := fB.signedLayout(t)
			_, report, auditErr := InTotoVerifyWithAudit(layoutEnvB, fB.layoutKeys(),
				fB.dir, "", map[string]string{}, [][]byte{}, false)

			require.NotNil(t, report)
			if classicErr != nil {
				assert.Error(t, auditErr, "classic verification failed but the audited one passed")
				assert.Equal(t, VerdictReject, report.Verdict)
				// A rejection must always carry at least one failing check with
				// a concrete reason and at least one rejected evidence record.
				var failingChecks int
				for _, c := range report.Checks {
					if !c.Passed {
						failingChecks++
						assert.NotEmpty(t, c.Message)
					}
				}
				assert.GreaterOrEqual(t, failingChecks, 1)
				assert.GreaterOrEqual(t, countEvidence(report, EvidenceRejected), 1)
			} else {
				assert.NoError(t, auditErr, "classic verification passed but the audited one failed: %v", auditErr)
				assert.Equal(t, VerdictPass, report.Verdict)
			}
		})
	}
}

// TestAuditParityOnRepoFixtures runs both implementations over the
// repository's own demo fixtures, ensuring the existing passing layout still
// passes through the audited pipeline.
func TestAuditParityOnRepoFixtures(t *testing.T) {
	layoutMb, err := LoadMetadata("demo.layout")
	require.NoError(t, err)

	var pubKey Key
	require.NoError(t, pubKey.LoadKey("alice.pub", "rsassa-pss-sha256",
		[]string{"sha256", "sha512"}))
	layoutKeys := map[string]Key{pubKey.KeyID: pubKey}

	classicSummary, classicErr := InTotoVerify(layoutMb, layoutKeys, ".", "",
		map[string]string{}, [][]byte{}, testOSisWindows())
	require.NoError(t, classicErr)
	require.NotNil(t, classicSummary)

	layoutMb2, err := LoadMetadata("demo.layout")
	require.NoError(t, err)
	auditSummary, report, auditErr := InTotoVerifyWithAudit(layoutMb2, layoutKeys,
		".", "", map[string]string{}, [][]byte{}, testOSisWindows())
	require.NoError(t, auditErr)
	require.NotNil(t, auditSummary)
	assert.Equal(t, VerdictPass, report.Verdict)
	// Every candidate link discovered in the demo layout is classified, none
	// silently skipped.
	assert.NotEmpty(t, report.Evidence)
	for _, ev := range report.Evidence {
		assert.Contains(t, []string{EvidenceAccepted, EvidenceRejected, EvidenceIgnored},
			ev.Classification)
	}
}
