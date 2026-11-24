package in_toto

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// errMsg wraps a plain message as an error. It uses errors.New so go vet does
// not flag a non-constant format string, while keeping the exact message
// produced by the underlying check.
func errMsg(message string) error {
	return errors.New(message)
}

/*
verifyOptions carries the inputs of an InTotoVerify run through the auditing
pipeline.  They are identical to the arguments of InTotoVerify /
InTotoVerifyWithDirectory.
*/
type verifyOptions struct {
	layoutEnv           Metadata
	layoutKeys          map[string]Key
	linkDir             string
	runDir              string
	stepName            string
	parameterDictionary map[string]string
	intermediatePems    [][]byte
	lineNormalization   bool
	// depth is the absolute nesting depth of the layout being verified within
	// the sublayout tree. The root layout is at depth 0; each nested sublayout
	// increments it. It is internal to the recursive pipeline.
	depth int
	// parentPath traces the sublayout steps from the root to the current
	// layout. Empty for the root.
	parentPath []string
}

// InTotoVerifyWithAudit performs exactly the same verification as InTotoVerify
// and additionally produces a structured VerdictReport that records every
// check executed and every candidate piece of evidence discovered, classified
// as accepted, rejected or ignored.
//
// The pass/reject conclusion is identical to the one of InTotoVerify: the
// auditing pipeline calls the same verification routines and aborts at the
// first failing check, mirroring the existing behavior.  The returned metadata
// and error are the values InTotoVerify would return; the report is an
// optional additional output and is never nil.
func InTotoVerifyWithAudit(layoutEnv Metadata, layoutKeys map[string]Key,
	linkDir string, stepName string, parameterDictionary map[string]string,
	intermediatePems [][]byte, lineNormalization bool) (Metadata, *VerdictReport, error) {

	return inTotoVerifyAudited(verifyOptions{
		layoutEnv:           layoutEnv,
		layoutKeys:          layoutKeys,
		linkDir:             linkDir,
		runDir:              "",
		stepName:            stepName,
		parameterDictionary: parameterDictionary,
		intermediatePems:    intermediatePems,
		lineNormalization:   lineNormalization,
	})
}

// InTotoVerifyWithDirectoryAudit is the auditing counterpart of
// InTotoVerifyWithDirectory.  It performs the same verification, including the
// run-directory sanity checks, and additionally returns a VerdictReport.
func InTotoVerifyWithDirectoryAudit(layoutEnv Metadata, layoutKeys map[string]Key,
	linkDir string, runDir string, stepName string,
	parameterDictionary map[string]string, intermediatePems [][]byte,
	lineNormalization bool) (Metadata, *VerdictReport, error) {

	return inTotoVerifyAudited(verifyOptions{
		layoutEnv:           layoutEnv,
		layoutKeys:          layoutKeys,
		linkDir:             linkDir,
		runDir:              runDir,
		stepName:            stepName,
		parameterDictionary: parameterDictionary,
		intermediatePems:    intermediatePems,
		lineNormalization:   lineNormalization,
	})
}

func inTotoVerifyAudited(opts verifyOptions) (Metadata, *VerdictReport, error) {
	report := &VerdictReport{
		LinkDir: normalizeLinkDir(opts.linkDir),
	}

	// InTotoVerifyWithDirectory performs run-directory sanity checks before any
	// in-toto check.  A failure here is a rejection with the underlying error.
	if opts.runDir != "" {
		if err := checkRunDir(opts.runDir); err != nil {
			report.fail("inspection run directory is not usable: "+err.Error(),
				CheckRecord{Name: checkInspectionCommand, Level: opts.depth,
					Message: err.Error()})
			return nil, report, err
		}
	}

	// 1. Verify layout signatures (same routine as InTotoVerify).
	if err := VerifyLayoutSignatures(opts.layoutEnv, opts.layoutKeys); err != nil {
		report.fail("layout signature verification failed: "+err.Error(),
			CheckRecord{Name: checkLayoutSignature, Level: opts.depth,
				Message: err.Error()})
		return nil, report, err
	}
	report.addCheck(CheckRecord{Name: checkLayoutSignature, Passed: true, Level: opts.depth})

	useDSSE := false
	if _, ok := opts.layoutEnv.(*Envelope); ok {
		useDSSE = true
	}

	layout, ok := opts.layoutEnv.GetPayload().(Layout)
	if !ok {
		err := ErrNotLayout
		report.fail("verification workflow passed a non-layout: "+err.Error(),
			CheckRecord{Name: checkLayoutSignature, Level: opts.depth,
				Message: err.Error()})
		return nil, report, err
	}

	// 2. Verify layout expiration.
	if err := VerifyLayoutExpiration(layout); err != nil {
		report.fail("layout expiration check failed: "+err.Error(),
			CheckRecord{Name: checkLayoutExpiration, Level: opts.depth,
				Message: err.Error()})
		return nil, report, err
	}
	report.addCheck(CheckRecord{Name: checkLayoutExpiration, Passed: true, Level: opts.depth})

	// 3. Substitute parameters.  Record the before/after expectation values.
	substitutedLayout, subCheck := auditSubstituteParameters(layout,
		opts.parameterDictionary, opts.depth, opts.parentPath)
	report.addCheck(subCheck)
	if !subCheck.Passed {
		err := errMsg(subCheck.Message)
		report.fail("parameter substitution failed: " + subCheck.Message)
		return nil, report, err
	}
	layout = substitutedLayout

	rootCertPool, intermediateCertPool, err := LoadLayoutCertificates(layout, opts.intermediatePems)
	if err != nil {
		report.fail("failed to load layout certificates: "+err.Error(),
			CheckRecord{Name: checkLinkKeySupport, Level: opts.depth,
				Message: err.Error()})
		return nil, report, err
	}

	// 4. Load links for the layout, recording every discovered candidate.
	stepsMetadata, loadChecks := auditLoadLinks(layout, report.LinkDir,
		opts.depth, opts.parentPath)
	for _, c := range loadChecks {
		report.addCheck(c)
	}
	if undecidable := report.undecidableLoadFailure(loadChecks); undecidable != "" {
		report.markUndecidable(undecidable)
		return nil, report, errMsg(undecidable)
	}

	// 5. Verify link signatures and thresholds with full evidence tracking.
	stepsMetadataVerified, thresholdChecks := auditLinkSignatureThresholds(
		layout, stepsMetadata, rootCertPool, intermediateCertPool, report.LinkDir,
		opts.depth, opts.parentPath)
	for _, c := range thresholdChecks {
		report.addCheck(c)
	}
	if failed := firstFailedCheck(thresholdChecks); failed != nil {
		err := errMsg(failed.Message)
		report.fail("link signature/threshold verification failed: " + failed.Message)
		return nil, report, err
	}

	// 6. Verify and resolve sublayouts recursively.
	stepsSublayoutVerified, subChecks := auditVerifySublayouts(opts, layout,
		stepsMetadataVerified, rootCertPool, intermediateCertPool,
		opts.depth, opts.parentPath)
	for _, c := range subChecks.checks {
		report.addCheck(c)
	}
	report.Sublayouts = append(report.Sublayouts, subChecks.reports...)
	if subChecks.err != nil {
		report.fail("sublayout verification failed: " + subChecks.err.Error())
		return nil, report, subChecks.err
	}

	// 7. Command alignment only warns; it never changes the verdict.
	VerifyStepCommandAlignment(layout, stepsSublayoutVerified)

	// 8. Reduce links, recording conflicting evidence instead of silently
	// erroring without context.
	stepsMetadataReduced, reduceChecks := auditReduceStepsMetadata(layout,
		stepsSublayoutVerified, opts.depth, opts.parentPath)
	for _, c := range reduceChecks {
		report.addCheck(c)
	}
	if failed := firstFailedCheck(reduceChecks); failed != nil {
		err := errMsg(failed.Message)
		report.fail("evidence consistency check failed: " + failed.Message)
		return nil, report, err
	}

	// 9. Verify artifact rules of steps, tracking unconsumed artifacts.
	stepRuleChecks := auditVerifyArtifacts(layout.stepsAsInterfaceSlice(),
		stepsMetadataReduced, opts.depth, opts.parentPath)
	for _, c := range stepRuleChecks {
		report.addCheck(c)
	}
	if failed := firstFailedCheck(stepRuleChecks); failed != nil {
		err := errMsg(failed.Message)
		report.fail("artifact rule verification failed: " + failed.Message)
		return nil, report, err
	}

	// 10. Execute inspections (generates unsigned link metadata).
	inspectionMetadata, inspCheck := auditRunInspections(layout, opts.runDir,
		opts.lineNormalization, useDSSE, opts.depth, opts.parentPath)
	report.addCheck(inspCheck)
	if !inspCheck.Passed {
		err := errMsg(inspCheck.Message)
		report.fail("inspection command failed: " + inspCheck.Message)
		return nil, report, err
	}
	for k, v := range stepsMetadataReduced {
		inspectionMetadata[k] = v
	}

	// 11. Verify artifact rules of inspections.
	inspRuleChecks := auditVerifyArtifacts(layout.inspectAsInterfaceSlice(),
		inspectionMetadata, opts.depth, opts.parentPath)
	for _, c := range inspRuleChecks {
		report.addCheck(c)
	}
	if failed := firstFailedCheck(inspRuleChecks); failed != nil {
		err := errMsg(failed.Message)
		report.fail("inspection artifact rule verification failed: " + failed.Message)
		return nil, report, err
	}

	summaryLink, err := GetSummaryLink(layout, stepsMetadataReduced, opts.stepName, useDSSE)
	if err != nil {
		report.fail("failed to build summary link: "+err.Error(),
			CheckRecord{Name: checkArtifactRules, Level: opts.depth, Message: err.Error()})
		return nil, report, err
	}

	report.Verdict = VerdictPass
	report.Summary = "all verification checks passed"
	report.finalizeEvidence()
	return summaryLink, report, nil
}

// checkRunDir mirrors the run-directory sanity checks performed by
// InTotoVerifyWithDirectory.
func checkRunDir(runDir string) error {
	info, err := os.Stat(runDir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == os.ModeSymlink {
		return ErrInspectionRunDirIsSymlink
	}
	if err := isWritable(runDir); err != nil {
		return err
	}
	f, err := os.Open(runDir)
	if err != nil {
		return err
	}
	defer f.Close()
	// Mirrors InTotoVerifyWithDirectory exactly: an empty directory returns
	// io.EOF from Readdirnames and that error is propagated; a non-empty
	// directory makes verification continue.
	if _, err = f.Readdirnames(1); err != nil && err != io.EOF {
		return err
	}
	return nil
}

// fail finalizes the report as a rejection.  Every rejection carries at least
// one failing check with a concrete reason and at least one piece of rejected
// evidence; an empty rejection is treated as a bug and backfilled rather than
// emitted.
func (r *VerdictReport) fail(summary string, failing ...CheckRecord) {
	for _, c := range failing {
		if c.Name == "" {
			continue
		}
		r.addCheck(c)
	}
	// Hard guarantee: no rejection without a concrete failing check and a
	// rejected evidence record pointing at the cause.
	if !r.hasFailingCheck() {
		r.addCheck(CheckRecord{
			Name:    "verification",
			Passed:  false,
			Level:   0,
			Message: summary,
			Evidence: []EvidenceRecord{{
				Classification: EvidenceRejected,
				Kind:           "verification",
				Reason:         summary,
			}},
		})
	}
	r.Verdict = VerdictReject
	r.Summary = summary
	r.finalizeEvidence()
}

// hasFailingCheck reports whether any check already recorded on the report did
// not pass and carries an explanatory message.
func (r *VerdictReport) hasFailingCheck() bool {
	for _, c := range r.Checks {
		if !c.Passed && c.Message != "" {
			return true
		}
	}
	return false
}

// markUndecidable finalizes the report as undecidable, used when a required
// evidence source cannot be read.  It must never be used for an ordinary
// check failure.
func (r *VerdictReport) markUndecidable(reason string) {
	r.Verdict = VerdictUndecidable
	r.Summary = "verification could not be decided: " + reason
	r.finalizeEvidence()
}

func firstFailedCheck(checks []CheckRecord) *CheckRecord {
	for i := range checks {
		if !checks[i].Passed {
			return &checks[i]
		}
	}
	return nil
}

// undecidableLoadFailure returns the reason if link loading failed because the
// link directory itself could not be read (glob error), which is undecidable
// rather than a rejection.
func (r *VerdictReport) undecidableLoadFailure(checks []CheckRecord) string {
	for _, c := range checks {
		if !c.Passed && strings.HasPrefix(c.Message, "cannot read link metadata directory") {
			return c.Message
		}
	}
	return ""
}

// normalizeLinkDir returns the cleaned absolute form of the link directory.
// Evidence paths recorded in the report are relative to this directory, and
// evidence outside of it is never accepted.
func normalizeLinkDir(linkDir string) string {
	if linkDir == "" {
		linkDir = "."
	}
	abs, err := filepath.Abs(linkDir)
	if err != nil {
		return filepath.Clean(linkDir)
	}
	return filepath.Clean(abs)
}

// safeRelPath cleans the candidate path and verifies that it is located inside
// the link directory.  The returned path is directory-relative.  An empty
// string means the candidate escapes the link directory and must not be
// accepted.
func safeRelPath(linkDir, candidate string) (string, bool) {
	cleanDir := filepath.Clean(linkDir)
	absCandidate := candidate
	if !filepath.IsAbs(absCandidate) {
		absCandidate = filepath.Join(cleanDir, candidate)
	}
	absCandidate = filepath.Clean(absCandidate)
	rel, err := filepath.Rel(cleanDir, absCandidate)
	if err != nil {
		return "", false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) ||
		filepath.IsAbs(rel) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// sortEvidenceRecords orders evidence deterministically so that repeated runs
// over the same evidence produce identical classification and ordering.
func sortEvidenceRecords(records []EvidenceRecord) {
	sort.SliceStable(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if a.Step != b.Step {
			return a.Step < b.Step
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.SignerKeyID != b.SignerKeyID {
			return a.SignerKeyID < b.SignerKeyID
		}
		if a.Classification != b.Classification {
			return classificationRank(a.Classification) < classificationRank(b.Classification)
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Reason < b.Reason
	})
}

func classificationRank(c string) int {
	switch c {
	case EvidenceAccepted:
		return 0
	case EvidenceRejected:
		return 1
	case EvidenceIgnored:
		return 2
	default:
		return 3
	}
}

// auditSubstituteParameters mirrors SubstituteParameters and records the
// expectation values before and after substitution.
func auditSubstituteParameters(layout Layout, parameterDictionary map[string]string,
	level int, sublayoutPath []string) (Layout, CheckRecord) {
	check := CheckRecord{
		Name:          checkParameterSubstitution,
		Passed:        true,
		Level:         level,
		SublayoutPath: cloneStrings(sublayoutPath),
	}

	if len(parameterDictionary) == 0 {
		return layout, check
	}

	before := collectSubstitutionExpectations(layout)
	substituted, err := SubstituteParameters(layout, parameterDictionary)
	if err != nil {
		check.Passed = false
		check.Message = err.Error()
		return layout, check
	}
	after := collectSubstitutionExpectations(substituted)

	differences := map[string]interface{}{}
	for key, beforeVal := range before {
		if afterVal, ok := after[key]; ok && !reflect.DeepEqual(beforeVal, afterVal) {
			differences[key] = map[string]interface{}{
				"before": beforeVal,
				"after":  afterVal,
			}
		}
	}
	if len(differences) > 0 {
		check.Evidence = append(check.Evidence, EvidenceRecord{
			Classification: EvidenceAccepted,
			Kind:           "parameter-substitution",
			Reason:         "",
			Details:        differences,
		})
	}
	return substituted, check
}

func collectSubstitutionExpectations(layout Layout) map[string]interface{} {
	result := map[string]interface{}{}
	for _, step := range layout.Steps {
		result["step:"+step.Name+":expected_materials"] = step.ExpectedMaterials
		result["step:"+step.Name+":expected_products"] = step.ExpectedProducts
		result["step:"+step.Name+":expected_command"] = step.ExpectedCommand
	}
	for _, inspection := range layout.Inspect {
		result["inspection:"+inspection.Name+":expected_materials"] = inspection.ExpectedMaterials
		result["inspection:"+inspection.Name+":expected_products"] = inspection.ExpectedProducts
		result["inspection:"+inspection.Name+":run"] = inspection.Run
	}
	return result
}

// auditLoadLinks mirrors LoadLinksForLayout but classifies every discovered
// candidate file: accepted loads, rejected unreadable/malformed/empty files
// and ignored files that cannot be associated to a step signer, plus files
// escaping the link directory.
func auditLoadLinks(layout Layout, linkDir string,
	level int, sublayoutPath []string) (map[string]map[string]Metadata, []CheckRecord) {
	stepsMetadata := make(map[string]map[string]Metadata)
	var checks []CheckRecord

	// If the link metadata directory itself cannot be read, no conclusion about
	// the evidence is possible: the run is undecidable rather than rejected.
	if info, err := os.Stat(linkDir); err != nil {
		checks = append(checks, CheckRecord{
			Name:          checkLinkDiscovery,
			Passed:        false,
			Level:         level,
			SublayoutPath: cloneStrings(sublayoutPath),
			Message:       fmt.Sprintf("cannot read link metadata directory '%s': %s", linkDir, err.Error()),
		})
		for _, step := range layout.Steps {
			stepsMetadata[step.Name] = map[string]Metadata{}
		}
		return stepsMetadata, checks
	} else if !info.IsDir() {
		checks = append(checks, CheckRecord{
			Name:          checkLinkDiscovery,
			Passed:        false,
			Level:         level,
			SublayoutPath: cloneStrings(sublayoutPath),
			Message:       fmt.Sprintf("cannot read link metadata directory '%s': not a directory", linkDir),
		})
		for _, step := range layout.Steps {
			stepsMetadata[step.Name] = map[string]Metadata{}
		}
		return stepsMetadata, checks
	}
	for _, step := range layout.Steps {
		check := CheckRecord{
			Name:          checkLinkLoad,
			Passed:        true,
			Level:         level,
			SublayoutPath: cloneStrings(sublayoutPath),
		}
		linksPerStep := make(map[string]Metadata)

		globPattern := path.Join(linkDir, fmt.Sprintf(LinkGlobFormat, step.Name))
		linkFiles, globErr := filepath.Glob(globPattern)
		if globErr != nil {
			check.Passed = false
			check.Message = fmt.Sprintf("cannot read link metadata directory for step '%s': %s",
				step.Name, globErr.Error())
			checks = append(checks, check)
			stepsMetadata[step.Name] = linksPerStep
			continue
		}
		sort.Strings(linkFiles)

		for _, linkPath := range linkFiles {
			relPath, inside := safeRelPath(linkDir, linkPath)
			if !inside {
				check.Evidence = append(check.Evidence, EvidenceRecord{
					Classification: EvidenceIgnored,
					Kind:           "link",
					Step:           step.Name,
					Path:           filepath.ToSlash(filepath.Clean(linkPath)),
					Reason:         "link file is located outside of the link metadata directory",
				})
				continue
			}

			linkEnv, loadErr := LoadMetadata(linkPath)
			if loadErr != nil {
				reason := classifyLoadError(loadErr)
				check.Evidence = append(check.Evidence, EvidenceRecord{
					Classification: EvidenceRejected,
					Kind:           "link",
					Step:           step.Name,
					Path:           relPath,
					Reason:         reason,
					Details: map[string]interface{}{
						"error": loadErr.Error(),
					},
				})
				continue
			}

			signerShortKeyID := strings.TrimSuffix(
				strings.TrimPrefix(filepath.Base(linkPath), step.Name+"."), ".link")
			associated := false
			var associatedKeyID string
			for _, sig := range linkEnv.Sigs() {
				if strings.HasPrefix(sig.KeyID, signerShortKeyID) {
					linksPerStep[sig.KeyID] = linkEnv
					associated = true
					associatedKeyID = sig.KeyID
					break
				}
			}

			if !associated {
				check.Evidence = append(check.Evidence, EvidenceRecord{
					Classification: EvidenceIgnored,
					Kind:           "link",
					Step:           step.Name,
					Path:           relPath,
					Reason:         "no signature in the metadata matches the link file name key id prefix '" + signerShortKeyID + "'",
				})
				continue
			}

			check.Evidence = append(check.Evidence, EvidenceRecord{
				Classification: EvidenceAccepted,
				Kind:           "link",
				Step:           step.Name,
				Path:           relPath,
				SignerKeyID:    associatedKeyID,
			})
		}

		// The load stage only discovers and classifies candidate files. The
		// authoritative threshold decision (with its detailed evidence) is made
		// by auditLinkSignatureThresholds, so a low candidate count is recorded
		// here as information and does not fail this check. This mirrors
		// LoadLinksForLayout's preliminary count while keeping the full
		// evidence-gathering round alive.
		if len(linksPerStep) < step.Threshold {
			check.Message = fmt.Sprintf(
				"step '%s' preliminarily found '%d' link metadata file(s), threshold is '%d'",
				step.Name, len(linksPerStep), step.Threshold)
		}
		checks = append(checks, check)
		stepsMetadata[step.Name] = linksPerStep
	}
	return stepsMetadata, checks
}

// classifyLoadError maps a metadata loading error to a stable reason string,
// distinguishing corrupted files, format mismatches and empty content.
func classifyLoadError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unexpected end of JSON input"),
		strings.Contains(msg, "EOF"):
		return "evidence file is empty or truncated"
	case strings.Contains(msg, "invalid character"),
		strings.Contains(msg, "cannot unmarshal"),
		strings.Contains(msg, "error decoding payload"),
		strings.Contains(msg, "required field"),
		strings.Contains(msg, "requires 'signed' and 'signatures'"),
		strings.Contains(msg, "requires 'payload' and 'signatures'"),
		strings.Contains(msg, "unknown metadata type"):
		return "evidence file is malformed or does not conform to the link metadata format"
	default:
		return "evidence file could not be parsed: " + msg
	}
}

// auditLinkSignatureThresholds mirrors VerifyLinkSignatureThesholds and
// records, for every candidate link of every step, why it was accepted,
// rejected or ignored.
func auditLinkSignatureThresholds(layout Layout,
	stepsMetadata map[string]map[string]Metadata,
	rootCertPool, intermediateCertPool *x509.CertPool,
	linkDir string, level int, sublayoutPath []string) (
	map[string]map[string]Metadata, []CheckRecord) {

	stepsMetadataVerified := make(map[string]map[string]Metadata)
	var checks []CheckRecord

	// Iterate steps in layout order for deterministic output.
	for _, step := range layout.Steps {
		check := CheckRecord{
			Name:          checkThreshold,
			Passed:        true,
			Level:         level,
			SublayoutPath: cloneStrings(sublayoutPath),
		}
		linksPerStepVerified := make(map[string]Metadata)
		linksPerStep := stepsMetadata[step.Name]

		if len(linksPerStep) == 0 {
			check.Passed = false
			check.Message = fmt.Sprintf("step '%s' requires '%d' link metadata file(s). "+
				"'0' out of '0' available link(s) have a valid signature from an authorized signer",
				step.Name, step.Threshold)
			check.Evidence = append(check.Evidence, EvidenceRecord{
				Classification: EvidenceRejected,
				Kind:           "step",
				Step:           step.Name,
				Reason:         check.Message,
				Details: map[string]interface{}{
					"threshold":  step.Threshold,
					"candidates": 0,
					"accepted":   0,
				},
			})
			checks = append(checks, check)
			stepsMetadataVerified[step.Name] = linksPerStepVerified
			continue
		}

		// Deterministic iteration over signer key ids.
		keyIDs := make([]string, 0, len(linksPerStep))
		for keyID := range linksPerStep {
			keyIDs = append(keyIDs, keyID)
		}
		sort.Strings(keyIDs)

		var lastErr error
		// Mirrors VerifyLinkSignatureThesholds exactly: this flag is set as soon
		// as one authorized-key link verifies and is never reset within the
		// step, so later certificate-path candidates are skipped once an
		// authorized signature was accepted. Keeping it guarantees the audited
		// verdict is identical to the existing one.
		isAuthorizedSignature := false
		for _, signerKeyID := range keyIDs {
			linkEnv := linksPerStep[signerKeyID]
			relPath := filepath.ToSlash(filepath.Clean(linkFileNameFor(step.Name, signerKeyID)))
			record := EvidenceRecord{
				Kind:        "link",
				Step:        step.Name,
				Path:        relPath,
				SignerKeyID: signerKeyID,
			}

			authorized, authorizedKeyID := isAuthorizedKeyID(signerKeyID, step.PubKeys)
			if authorized {
				verifierKey, keyKnown := layout.Keys[authorizedKeyID]
				if !keyKnown {
					record.Classification = EvidenceRejected
					record.Reason = fmt.Sprintf(
						"signer key '%s' is authorized for step '%s' but the layout carries no verification key",
						signerKeyID, step.Name)
					lastErr = errMsg(record.Reason)
					check.Evidence = append(check.Evidence, record)
					continue
				}
				if err := linkEnv.VerifySignature(verifierKey); err != nil {
					record.Classification = EvidenceRejected
					record.Reason = "signature verification failed: " + err.Error()
					record.Details = map[string]interface{}{"error": err.Error()}
					lastErr = err
					check.Evidence = append(check.Evidence, record)
					continue
				}
				record.Classification = EvidenceAccepted
				record.Reason = "valid signature from an authorized functionary"
				linksPerStepVerified[signerKeyID] = linkEnv
				isAuthorizedSignature = true
				check.Evidence = append(check.Evidence, record)
				continue
			}

			// Legacy gate: once an authorized layout-key signature was accepted,
			// the certificate branch is no longer consulted for the step.
			if isAuthorizedSignature {
				record.Classification = EvidenceIgnored
				record.Reason = "signer key is not in the step allow-list; certificate evaluation was skipped because an authorized functionary signature was already accepted"
				check.Evidence = append(check.Evidence, record)
				continue
			}

			// Not an authorized layout key: try the certificate path, exactly
			// like VerifyLinkSignatureThesholds does.
			sig, err := linkEnv.GetSignatureForKeyID(signerKeyID)
			if err != nil {
				record.Classification = EvidenceRejected
				record.Reason = "no signature found for signer key: " + err.Error()
				lastErr = err
				check.Evidence = append(check.Evidence, record)
				continue
			}
			cert, err := sig.GetCertificate()
			if err != nil {
				record.Classification = EvidenceRejected
				record.Reason = "signer key is not authorized by the layout and carries no usable certificate: " + err.Error()
				lastErr = err
				check.Evidence = append(check.Evidence, record)
				continue
			}
			if err := step.CheckCertConstraints(cert, layout.RootCAIDs(), rootCertPool, intermediateCertPool); err != nil {
				record.Classification = EvidenceRejected
				record.Reason = "signer key is not authorized for this step and certificate constraints failed: " + err.Error()
				lastErr = err
				check.Evidence = append(check.Evidence, record)
				continue
			}
			if err := linkEnv.VerifySignature(cert); err != nil {
				record.Classification = EvidenceRejected
				record.Reason = "signature verification against the functionary certificate failed: " + err.Error()
				lastErr = err
				check.Evidence = append(check.Evidence, record)
				continue
			}
			record.Classification = EvidenceAccepted
			record.Reason = "valid signature from a certificate-authorized functionary"
			linksPerStepVerified[signerKeyID] = linkEnv
			isAuthorizedSignature = true
			check.Evidence = append(check.Evidence, record)
		}

		if len(linksPerStepVerified) < step.Threshold {
			check.Passed = false
			check.Message = fmt.Sprintf(
				"step '%s' requires '%d' link metadata file(s). '%d' out of '%d' available link(s) have a valid signature from an authorized signer: %v",
				step.Name, step.Threshold, len(linksPerStepVerified),
				len(linksPerStep), errorString(lastErr))
			// Guarantee a failing threshold check always carries rejected
			// evidence even when every candidate was only ignored.
			if !checkHasClassification(check, EvidenceRejected) {
				check.Evidence = append(check.Evidence, EvidenceRecord{
					Classification: EvidenceRejected,
					Kind:           "step",
					Step:           step.Name,
					Reason:         check.Message,
					Details: map[string]interface{}{
						"threshold":  step.Threshold,
						"candidates": len(linksPerStep),
						"accepted":   len(linksPerStepVerified),
					},
				})
			}
		} else {
			check.Message = fmt.Sprintf(
				"step '%s' threshold satisfied: %d accepted of %d candidate link(s), threshold %d",
				step.Name, len(linksPerStepVerified), len(linksPerStep), step.Threshold)
		}
		check.Details = map[string]interface{}{
			"threshold":  step.Threshold,
			"accepted":   len(linksPerStepVerified),
			"candidates": len(linksPerStep),
			"missing":    maxInt(step.Threshold-len(linksPerStepVerified), 0),
			"surplus":    maxInt(len(linksPerStepVerified)-step.Threshold, 0),
		}
		checks = append(checks, check)
		stepsMetadataVerified[step.Name] = linksPerStepVerified
	}
	return stepsMetadataVerified, checks
}

func isAuthorizedKeyID(signerKeyID string, authorizedKeyIDs []string) (bool, string) {
	for _, authorizedKeyID := range authorizedKeyIDs {
		if signerKeyID == authorizedKeyID {
			return true, authorizedKeyID
		}
	}
	return false, ""
}

// checkHasClassification reports whether the check already contains an
// evidence record with the given classification.
func checkHasClassification(check CheckRecord, classification string) bool {
	for _, ev := range check.Evidence {
		if ev.Classification == classification {
			return true
		}
	}
	return false
}

func linkFileNameFor(stepName, keyID string) string {
	return fmt.Sprintf(LinkNameFormat, stepName, keyID)
}

func errorString(err error) interface{} {
	if err == nil {
		return nil
	}
	return err.Error()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	// NOTE: the package tests define a package-level helper named "copy",
	// which shadows the built-in; append on a fresh slice is equivalent.
	return append(make([]string, 0, len(in)), in...)
}

// auditReduceStepsMetadata mirrors ReduceStepsMetadata: links of a step must
// report identical materials and products.  A mismatch is recorded as
// conflicting, deterministically ordered evidence.
func auditReduceStepsMetadata(layout Layout,
	stepsMetadata map[string]map[string]Metadata,
	level int, sublayoutPath []string) (map[string]Metadata, []CheckRecord) {

	stepsMetadataReduced := make(map[string]Metadata)
	var checks []CheckRecord

	for _, step := range layout.Steps {
		check := CheckRecord{
			Name:          checkEvidenceConsistency,
			Passed:        true,
			Level:         level,
			SublayoutPath: cloneStrings(sublayoutPath),
		}
		linksPerStep, ok := stepsMetadata[step.Name]
		if !ok || len(linksPerStep) < 1 {
			// Mirrors the panic precondition in ReduceStepsMetadata; in the
			// audited pipeline the threshold check guarantees this cannot
			// happen, but guard it explicitly.
			check.Passed = false
			check.Message = "no link metadata found for step '" + step.Name + "'"
			checks = append(checks, check)
			continue
		}

		keyIDs := make([]string, 0, len(linksPerStep))
		for keyID := range linksPerStep {
			keyIDs = append(keyIDs, keyID)
		}
		sort.Strings(keyIDs)

		referenceKeyID := keyIDs[0]
		referenceLinkEnv := linksPerStep[referenceKeyID]
		if len(linksPerStep) == 1 {
			stepsMetadataReduced[step.Name] = referenceLinkEnv
			continue
		}

		refLink, refOK := referenceLinkEnv.GetPayload().(Link)
		if !refOK {
			check.Passed = false
			check.Message = "invalid metadata"
			checks = append(checks, check)
			continue
		}

		var conflict error
		for _, keyID := range keyIDs[1:] {
			linkEnv := linksPerStep[keyID]
			link, ok := linkEnv.GetPayload().(Link)
			if !ok {
				check.Passed = false
				check.Message = "invalid metadata"
				conflict = fmt.Errorf("invalid metadata")
				break
			}
			materialsDiffer := !reflect.DeepEqual(link.Materials, refLink.Materials)
			productsDiffer := !reflect.DeepEqual(link.Products, refLink.Products)
			if materialsDiffer || productsDiffer {
				diffs := []string{}
				if materialsDiffer {
					diffs = append(diffs, "materials")
				}
				if productsDiffer {
					diffs = append(diffs, "products")
				}
				conflict = fmt.Errorf("link '%s' and '%s' have different artifacts",
					fmt.Sprintf(LinkNameFormat, step.Name, referenceKeyID),
					fmt.Sprintf(LinkNameFormat, step.Name, keyID))
				check.Evidence = append(check.Evidence,
					EvidenceRecord{
						Classification: EvidenceRejected,
						Kind:           "link",
						Step:           step.Name,
						Path:           fmt.Sprintf(LinkNameFormat, step.Name, referenceKeyID),
						SignerKeyID:    referenceKeyID,
						Reason:         "conflicting " + strings.Join(diffs, " and ") + " reported across links above the threshold",
						Details: map[string]interface{}{
							"conflicting_with": fmt.Sprintf(LinkNameFormat, step.Name, keyID),
							"differences":      diffs,
						},
					},
					EvidenceRecord{
						Classification: EvidenceRejected,
						Kind:           "link",
						Step:           step.Name,
						Path:           fmt.Sprintf(LinkNameFormat, step.Name, keyID),
						SignerKeyID:    keyID,
						Reason:         "conflicting " + strings.Join(diffs, " and ") + " reported across links above the threshold",
						Details: map[string]interface{}{
							"conflicting_with": fmt.Sprintf(LinkNameFormat, step.Name, referenceKeyID),
							"differences":      diffs,
						},
					})
			}
		}

		if conflict != nil {
			check.Passed = false
			check.Message = conflict.Error()
			checks = append(checks, check)
			continue
		}
		stepsMetadataReduced[step.Name] = referenceLinkEnv
	}
	return stepsMetadataReduced, checks
}

// auditVerifyArtifacts mirrors VerifyArtifacts and, in addition to the rule
// failure, records the artifacts left unconsumed after all rules ran.
func auditVerifyArtifacts(items []interface{},
	itemsMetadata map[string]Metadata, level int,
	sublayoutPath []string) []CheckRecord {

	var checks []CheckRecord

	for _, itemI := range items {
		var itemName string
		itemKind := "step"

		switch item := itemI.(type) {
		case Step:
			itemName = item.Name
		case Inspection:
			itemName = item.Name
			itemKind = "inspection"
		default:
			checks = append(checks, CheckRecord{
				Name:          checkArtifactRules,
				Passed:        false,
				Level:         level,
				SublayoutPath: cloneStrings(sublayoutPath),
				Message: fmt.Sprintf("VerifyArtifacts received an item of invalid type, got: '%s'",
					reflect.TypeOf(itemI)),
			})
			continue
		}

		// Invoke the canonical implementation so the verdict cannot diverge.
		err := VerifyArtifacts([]interface{}{itemI}, itemsMetadata)
		check := CheckRecord{
			Name:          checkArtifactRules,
			Passed:        err == nil,
			Level:         level,
			SublayoutPath: cloneStrings(sublayoutPath),
		}
		if err != nil {
			check.Message = err.Error()
			check.Evidence = append(check.Evidence, EvidenceRecord{
				Classification: EvidenceRejected,
				Kind:           itemKind,
				Step:           itemName,
				Reason:         err.Error(),
			})
			checks = append(checks, check)
			continue
		}

		// On success, report any artifacts still unconsumed by the rules as
		// ignored evidence (informational; the canonical implementation already
		// decided the rules passed).
		if unconsumed := unconsumedArtifacts(itemI, itemsMetadata); len(unconsumed) > 0 {
			sort.Strings(unconsumed)
			check.Evidence = append(check.Evidence, EvidenceRecord{
				Classification: EvidenceIgnored,
				Kind:           "unconsumed-artifact",
				Step:           itemName,
				Reason:         "artifacts reported by the link were not consumed by any artifact rule",
				Details:        map[string]interface{}{"artifacts": unconsumed},
			})
			checks = append(checks, CheckRecord{
				Name:          checkUnconsumedArtifacts,
				Passed:        true,
				Level:         level,
				SublayoutPath: cloneStrings(sublayoutPath),
				Message:       fmt.Sprintf("%d artifact(s) unconsumed after artifact rules", len(unconsumed)),
				Evidence: []EvidenceRecord{{
					Classification: EvidenceIgnored,
					Kind:           "unconsumed-artifact",
					Step:           itemName,
					Reason:         "artifacts reported by the link were not consumed by any artifact rule",
					Details:        map[string]interface{}{"artifacts": unconsumed},
				}},
			})
		}
		checks = append(checks, check)
	}
	return checks
}

// unconsumedArtifacts recomputes the artifact queues of an item and reports
// the paths that remain after the item's rules ran.
func unconsumedArtifacts(itemI interface{}, itemsMetadata map[string]Metadata) []string {
	var itemName string
	var expectedMaterials, expectedProducts [][]string
	switch item := itemI.(type) {
	case Step:
		itemName, expectedMaterials, expectedProducts = item.Name, item.ExpectedMaterials, item.ExpectedProducts
	case Inspection:
		itemName, expectedMaterials, expectedProducts = item.Name, item.ExpectedMaterials, item.ExpectedProducts
	default:
		return nil
	}
	srcLinkEnv, exists := itemsMetadata[itemName]
	if !exists {
		return nil
	}
	link, ok := srcLinkEnv.GetPayload().(Link)
	if !ok {
		return nil
	}

	collect := func(rules [][]string, artifacts map[string]HashObj) []string {
		queue := NewSet()
		for _, p := range artifactsDictKeyStrings(artifacts) {
			queue.Add(path.Clean(p))
		}
		for _, rule := range rules {
			ruleData, err := UnpackRule(rule)
			if err != nil {
				continue
			}
			filtered := queue.Filter(path.Clean(ruleData["pattern"]))
			var consumed Set
			switch ruleData["type"] {
			case "match":
				consumed = verifyMatchRule(ruleData, artifacts, queue, itemsMetadata)
			case "allow":
				consumed = filtered
			case "create":
				created := NewSet()
				for _, p := range artifactsDictKeyStrings(link.Products) {
					created.Add(path.Clean(p))
				}
				consumed = filtered.Intersection(created)
			case "delete":
				deleted := NewSet()
				for _, p := range artifactsDictKeyStrings(link.Materials) {
					deleted.Add(path.Clean(p))
				}
				consumed = filtered.Intersection(deleted)
			case "modify":
				consumed = NewSet()
			case "disallow", "require":
				consumed = NewSet()
			default:
				consumed = NewSet()
			}
			queue = queue.Difference(consumed)
		}
		return queue.Slice()
	}

	var out []string
	out = append(out, collect(expectedMaterials, link.Materials)...)
	out = append(out, collect(expectedProducts, link.Products)...)
	return out
}

// auditRunInspections mirrors RunInspections and records the failing
// inspection command with its return value as evidence.
func auditRunInspections(layout Layout, runDir string,
	lineNormalization, useDSSE bool,
	level int, sublayoutPath []string) (map[string]Metadata, CheckRecord) {

	check := CheckRecord{
		Name:          checkInspectionCommand,
		Passed:        true,
		Level:         level,
		SublayoutPath: cloneStrings(sublayoutPath),
	}
	inspectionMetadata := make(map[string]Metadata)

	for _, inspection := range layout.Inspect {
		paths := []string{"."}
		if runDir != "" {
			paths = []string{runDir}
		}
		linkEnv, err := InTotoRun(inspection.Name, runDir, paths, paths,
			inspection.Run, Key{}, []string{"sha256"}, nil, nil,
			lineNormalization, false, useDSSE)
		if err != nil {
			check.Passed = false
			check.Message = fmt.Sprintf("inspection command '%s' of inspection '%s' failed: %s",
				strings.Join(inspection.Run, " "), inspection.Name, err.Error())
			check.Evidence = append(check.Evidence, EvidenceRecord{
				Classification: EvidenceRejected,
				Kind:           "inspection",
				Step:           inspection.Name,
				Reason:         check.Message,
				Details:        map[string]interface{}{"error": err.Error()},
			})
			return nil, check
		}

		link, ok := linkEnv.GetPayload().(Link)
		if !ok {
			check.Passed = false
			check.Message = "inspection '" + inspection.Name + "' produced invalid metadata"
			check.Evidence = append(check.Evidence, EvidenceRecord{
				Classification: EvidenceRejected,
				Kind:           "inspection",
				Step:           inspection.Name,
				Reason:         check.Message,
			})
			return nil, check
		}
		retVal := link.ByProducts["return-value"]
		if retVal != float64(0) {
			check.Passed = false
			check.Message = fmt.Sprintf(
				"inspection command '%s' of inspection '%s' returned a non-zero value: %d",
				strings.Join(inspection.Run, " "), inspection.Name, retVal)
			check.Evidence = append(check.Evidence, EvidenceRecord{
				Classification: EvidenceRejected,
				Kind:           "inspection",
				Step:           inspection.Name,
				Reason:         check.Message,
				Details:        map[string]interface{}{"return-value": retVal},
			})
			return nil, check
		}

		linkName := fmt.Sprintf(LinkNameFormatShort, inspection.Name)
		if err := linkEnv.Dump(linkName); err != nil {
			fmt.Printf("JSON serialization or writing failed: %s", err)
		}
		inspectionMetadata[inspection.Name] = linkEnv
		check.Evidence = append(check.Evidence, EvidenceRecord{
			Classification: EvidenceAccepted,
			Kind:           "inspection-link",
			Step:           inspection.Name,
			Path:           linkName,
			Reason:         "inspection command executed successfully",
		})
	}
	return inspectionMetadata, check
}

// ErrSublayoutInconclusive marks a sublayout whose recursive verification
// could not be completed because of an unexpected internal error (a recovered
// panic). It is reported as inconclusive rather than silently swallowed or
// turned into an ordinary rejection without evidence.
var ErrSublayoutInconclusive = errors.New("sublayout verification is inconclusive")

// sublayoutAuditResult bundles the nested reports of recursive
// sublayout verification.
type sublayoutAuditResult struct {
	checks  []CheckRecord
	reports []*VerdictReport
	err     error
}

// auditVerifySublayouts mirrors VerifySublayouts.  Recursion failures are
// recorded as inconclusive, carrying the nested level and the originating
// sublayout step; they are never swallowed.
func auditVerifySublayouts(opts verifyOptions, layout Layout,
	stepsMetadataVerified map[string]map[string]Metadata,
	rootCertPool, intermediateCertPool *x509.CertPool,
	level int, parentPath []string) (map[string]map[string]Metadata, sublayoutAuditResult) {

	result := sublayoutAuditResult{}

	stepNames := make([]string, 0, len(stepsMetadataVerified))
	for stepName := range stepsMetadataVerified {
		stepNames = append(stepNames, stepName)
	}
	sort.Strings(stepNames)

	for _, stepName := range stepNames {
		linkData := stepsMetadataVerified[stepName]
		keyIDs := make([]string, 0, len(linkData))
		for keyID := range linkData {
			keyIDs = append(keyIDs, keyID)
		}
		sort.Strings(keyIDs)

		for _, keyID := range keyIDs {
			metadata := linkData[keyID]
			if _, isLayout := metadata.GetPayload().(Layout); !isLayout {
				continue
			}

			nestedPath := append(cloneStrings(parentPath), stepName)
			layoutKeys := map[string]Key{keyID: layout.Keys[keyID]}
			sublayoutLinkDir := fmt.Sprintf(SublayoutLinkDirFormat, stepName, keyID)
			sublayoutLinkPath := filepath.Join(opts.linkDir, sublayoutLinkDir)

			// The nested layout lives one level deeper and inherits the path
			// chain. Passing the absolute depth makes every check of the nested
			// report carry its correct, tree-wide level without a later rewrite.
			nestedSummary, nestedReport, nestedErr := verifyNestedSublayout(
				opts, metadata, layoutKeys, sublayoutLinkPath, stepName,
				level+1, nestedPath)

			result.reports = append(result.reports, nestedReport)

			// The depth of this sublayout in the tree, derived from its path so
			// that a failure bubbling up from a deeply nested layout still names
			// the correct level rather than the immediate parent's level + 1.
			nestedLevel := len(nestedPath)

			check := CheckRecord{
				Name:          checkSublayout,
				Passed:        nestedErr == nil,
				Level:         level,
				SublayoutPath: cloneStrings(parentPath),
			}
			if nestedErr != nil {
				inconclusive := errors.Is(nestedErr, ErrSublayoutInconclusive) ||
					nestedReport.Verdict == VerdictUndecidable
				if inconclusive {
					check.Message = fmt.Sprintf(
						"sublayout at level %d (path: %s, source step '%s', key '%s') is inconclusive: %s",
						nestedLevel, strings.Join(nestedPath, "/"), stepName, keyID, nestedReport.Summary)
				} else {
					check.Message = fmt.Sprintf(
						"sublayout at level %d (path: %s, source step '%s', key '%s') failed: %s",
						nestedLevel, strings.Join(nestedPath, "/"), stepName, keyID, nestedErr.Error())
				}
				evidenceClassification := EvidenceRejected
				if inconclusive {
					evidenceClassification = EvidenceIgnored
				}
				check.Evidence = append(check.Evidence, EvidenceRecord{
					Classification: evidenceClassification,
					Kind:           "sublayout",
					Step:           stepName,
					SignerKeyID:    keyID,
					Reason:         check.Message,
					Details: map[string]interface{}{
						"level":          nestedLevel,
						"sublayout_path": nestedPath,
						"nested_verdict": nestedReport.Verdict,
						"inconclusive":   inconclusive,
					},
				})
				result.checks = append(result.checks, check)
				result.err = errMsg(check.Message)
				return stepsMetadataVerified, result
			}

			check.Message = fmt.Sprintf("sublayout '%s' verified and reduced to a summary link", stepName)
			check.Evidence = append(check.Evidence, EvidenceRecord{
				Classification: EvidenceAccepted,
				Kind:           "sublayout",
				Step:           stepName,
				SignerKeyID:    keyID,
				Reason:         check.Message,
				Details: map[string]interface{}{
					"level":          nestedLevel,
					"sublayout_path": nestedPath,
				},
			})
			result.checks = append(result.checks, check)
			linkData[keyID] = nestedSummary
		}
	}
	return stepsMetadataVerified, result
}

// verifyNestedSublayout runs the audited verification of one nested sublayout
// and converts any unexpected panic into an inconclusive result that carries
// the nesting level and originating path. This guarantees a recursion
// exception is reported rather than swallowed or crashing the whole run.
func verifyNestedSublayout(opts verifyOptions, metadata Metadata,
	layoutKeys map[string]Key, sublayoutLinkPath, stepName string,
	depth int, nestedPath []string) (summary Metadata, report *VerdictReport, err error) {

	report = &VerdictReport{LinkDir: normalizeLinkDir(sublayoutLinkPath)}
	defer func() {
		if r := recover(); r != nil {
			reason := fmt.Sprintf(
				"sublayout at level %d (path: %s, source step '%s') raised an unexpected error: %v",
				depth, strings.Join(nestedPath, "/"), stepName, r)
			report.Verdict = VerdictUndecidable
			report.Summary = "verification could not be decided: " + reason
			report.addCheck(CheckRecord{
				Name:          checkSublayout,
				Passed:        false,
				Level:         depth,
				SublayoutPath: cloneStrings(nestedPath),
				Message:       reason,
				Evidence: []EvidenceRecord{{
					Classification: EvidenceIgnored,
					Kind:           "sublayout",
					Step:           stepName,
					Reason:         reason,
					Details: map[string]interface{}{
						"level":          depth,
						"sublayout_path": nestedPath,
						"panic":          fmt.Sprintf("%v", r),
					},
				}},
			})
			report.finalizeEvidence()
			summary = nil
			err = fmt.Errorf("%w: %s", ErrSublayoutInconclusive, reason)
		}
	}()

	summary, nestedReport, nestedErr := inTotoVerifyAudited(verifyOptions{
		layoutEnv:           metadata,
		layoutKeys:          layoutKeys,
		linkDir:             sublayoutLinkPath,
		runDir:              "",
		stepName:            stepName,
		parameterDictionary: map[string]string{},
		intermediatePems:    opts.intermediatePems,
		lineNormalization:   opts.lineNormalization,
		depth:               depth,
		parentPath:          nestedPath,
	})
	if nestedReport != nil {
		report = nestedReport
	}
	return summary, report, nestedErr
}
