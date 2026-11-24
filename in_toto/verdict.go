package in_toto

import (
	"encoding/json"
	"os"
)

// Verdict outcomes of an in-toto verification run.
const (
	// VerdictPass means every check of the verification workflow succeeded.
	VerdictPass = "pass"
	// VerdictReject means at least one check failed with conclusive evidence.
	VerdictReject = "reject"
	// VerdictUndecidable means verification could not be completed because a
	// required source of evidence (e.g. the link metadata directory) could not
	// be read.  An undecidable run never produces a rejection without evidence.
	VerdictUndecidable = "undecidable"
)

// Classification of a candidate piece of evidence discovered during
// verification.  Every discovered candidate is classified exactly once.
const (
	// EvidenceAccepted marks evidence that was used in support of the verdict,
	// e.g. a link with a valid signature from an authorized functionary.
	EvidenceAccepted = "accepted"
	// EvidenceRejected marks evidence that was discovered but failed one of the
	// required checks, together with the reason of the rejection.
	EvidenceRejected = "rejected"
	// EvidenceIgnored marks evidence that could not be used but does not carry
	// any authority for the current verification, e.g. an unreadable file, a
	// link whose signer cannot be associated with the step, or evidence outside
	// of the link metadata directory.
	EvidenceIgnored = "ignored"
)

// Check names reported in the verdict report.  They follow the order of the
// verification workflow documented on InTotoVerify.
const (
	checkLayoutSignature       = "layout-signature"
	checkLayoutExpiration      = "layout-expiration"
	checkParameterSubstitution = "parameter-substitution"
	checkLinkDiscovery         = "link-discovery"
	checkLinkLoad              = "link-load"
	checkLinkAuthorization     = "link-authorization"
	checkLinkSignature         = "link-signature"
	checkLinkKeySupport        = "link-key-support"
	checkThreshold             = "threshold"
	checkEvidenceConsistency   = "evidence-consistency"
	checkSublayout             = "sublayout"
	checkArtifactRules         = "artifact-rules"
	checkUnconsumedArtifacts   = "unconsumed-artifacts"
	checkInspectionCommand     = "inspection-command"
)

// EvidenceRecord describes one candidate piece of evidence that the
// verification workflow discovered and how it was classified.
type EvidenceRecord struct {
	// Classification is one of EvidenceAccepted, EvidenceRejected or
	// EvidenceIgnored.
	Classification string `json:"classification"`

	// Kind identifies what kind of evidence this is, e.g. "link", "layout" or
	// "inspection-link".
	Kind string `json:"kind"`

	// Step is the layout step (or inspection) the evidence belongs to.  It may
	// be empty for evidence that cannot be associated with a step.
	Step string `json:"step,omitempty"`

	// Path is the normalized, link-directory-relative location of the evidence
	// file.  Paths are cleaned and evidence referencing files outside of the
	// link directory is never accepted.
	Path string `json:"path,omitempty"`

	// SignerKeyID is the key id carried by the evidence signature.  It is
	// recorded for link metadata and never contains private key material.
	SignerKeyID string `json:"signer_key_id,omitempty"`

	// Reason explains why the evidence was rejected or ignored.  It is empty
	// for accepted evidence.
	Reason string `json:"reason,omitempty"`

	// Details carries optional structured information, e.g. the threshold
	// counts or the artifact paths involved in a conflict.
	Details map[string]interface{} `json:"details,omitempty"`
}

// CheckRecord describes the outcome of one verification check within the
// workflow.
type CheckRecord struct {
	// Name is one of the check* constants.
	Name string `json:"name"`

	// Passed reports whether the check succeeded.
	Passed bool `json:"passed"`

	// Message carries the failure reason.  A failing check always records the
	// reason, it is never an empty conclusion.
	Message string `json:"message,omitempty"`

	// Level locates the check inside nested sublayouts.  The root layout has
	// level 0; each nested sublayout increments the level by one.
	Level int `json:"level"`

	// SublayoutPath traces the chain of sublayout steps from the root layout
	// to the layout that owns this check, e.g. ["outer", "inner"].  It is
	// empty for checks of the root layout.
	SublayoutPath []string `json:"sublayout_path,omitempty"`

	// Evidence lists the evidence records produced or consumed by this check.
	Evidence []EvidenceRecord `json:"evidence,omitempty"`

	// Details carries optional structured information such as threshold
	// counts (accepted/candidates/missing/surplus).
	Details map[string]interface{} `json:"details,omitempty"`
}

// VerdictReport is the structured, machine-readable report of a full in-toto
// verification run.  It is an optional additional output: producing it never
// changes the pass/reject conclusion or the return values of the existing
// verification entry points.
type VerdictReport struct {
	// Verdict is one of VerdictPass, VerdictReject or VerdictUndecidable.
	Verdict string `json:"verdict"`

	// Summary is a one-line human readable description of the outcome.
	Summary string `json:"summary"`

	// LinkDir is the normalized path of the directory the link metadata was
	// loaded from.
	LinkDir string `json:"link_dir"`

	// Checks contains all checks executed during the run in deterministic
	// workflow order.  Checks of nested sublayouts appear at their position in
	// the workflow and carry their level and sublayout path.
	Checks []CheckRecord `json:"checks"`

	// Evidence is the flat, deterministically ordered list of every candidate
	// evidence discovered during the run.  No discovered candidate is silently
	// skipped.
	Evidence []EvidenceRecord `json:"evidence"`

	// Sublayouts carries the reports of recursively verified sublayouts.
	Sublayouts []*VerdictReport `json:"sublayouts,omitempty"`
}

// WriteJSON serializes the report as indented JSON to the given path.
func (r *VerdictReport) WriteJSON(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// addCheck appends a check record. The flat evidence list is rebuilt and
// deduplicated on finalization (see finalizeEvidence), so check records keep
// their own detailed evidence while a candidate file appears exactly once in
// the report-wide list, carrying its most authoritative classification.
func (r *VerdictReport) addCheck(c CheckRecord) {
	r.Checks = append(r.Checks, c)
}

// evidenceKey identifies a single candidate piece of evidence.
func evidenceKey(e EvidenceRecord) string {
	return e.Step + "\x00" + e.Path + "\x00" + e.SignerKeyID
}

// finalizeEvidence rebuilds the flat, deduplicated and deterministically
// ordered evidence list from every check of this report and every nested
// sublayout report. When the same candidate is seen more than once (e.g. once
// at load time and again during signature verification) the most
// authoritative classification wins: rejected beats accepted beats ignored.
func (r *VerdictReport) finalizeEvidence() {
	byKey := map[string]EvidenceRecord{}
	var order []string

	var collect func(report *VerdictReport)
	collect = func(report *VerdictReport) {
		for _, check := range report.Checks {
			for _, ev := range check.Evidence {
				key := evidenceKey(ev)
				if existing, ok := byKey[key]; ok {
					byKey[key] = mergeEvidence(existing, ev)
				} else {
					byKey[key] = ev
					order = append(order, key)
				}
			}
		}
		for _, sub := range report.Sublayouts {
			collect(sub)
		}
	}
	collect(r)

	r.Evidence = make([]EvidenceRecord, 0, len(order))
	for _, key := range order {
		r.Evidence = append(r.Evidence, byKey[key])
	}
	sortEvidenceRecords(r.Evidence)
}

// mergeEvidence combines two records describing the same candidate, keeping
// the strongest classification: rejected beats accepted beats ignored, so a
// candidate that loaded fine but failed signature verification is reported as
// rejected rather than silently remaining accepted.
func mergeEvidence(a, b EvidenceRecord) EvidenceRecord {
	if classificationRank(b.Classification) > classificationRank(a.Classification) {
		a, b = b, a
	}
	// a now has the stronger (higher rank) classification. Keep its reason when
	// the classifications differ, otherwise prefer the record with a reason.
	if a.Classification == b.Classification && a.Reason == "" && b.Reason != "" {
		a.Reason = b.Reason
	}
	if len(a.Details) == 0 && len(b.Details) > 0 {
		a.Details = b.Details
	}
	return a
}
