package in_toto

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
)

// Worker and file size limits for link aggregation.
const (
	// DefaultAggregationWorkers is the default upper bound for concurrently
	// processed link candidates when the caller does not request an explicit
	// worker count.
	DefaultAggregationWorkers = 8
	// MaxAggregationWorkers is the largest worker count honored by
	// ResolveLinkWorkers.
	MaxAggregationWorkers = 64
	// MaxLinkFileSize is the maximum size (16 MiB) of a link file that is
	// read for aggregation. Larger files are rejected without being read.
	MaxLinkFileSize int64 = 16 << 20
)

// LinkState describes the lifecycle state of a link candidate.
type LinkState string

const (
	// LinkStateVerified marks candidates whose signature validated against an
	// authorized key or certificate.
	LinkStateVerified LinkState = "verified"
	// LinkStateRejected marks candidates that failed one of the validation
	// stages.
	LinkStateRejected LinkState = "rejected"
	// LinkStateConflicting marks verified candidates that disagree with
	// another candidate of the same step and signer.
	LinkStateConflicting LinkState = "conflicting"
)

// LinkRejectReason classifies why a candidate was rejected.
type LinkRejectReason string

const (
	RejectNotRegularFile    LinkRejectReason = "not_regular_file"
	RejectFileTooLarge      LinkRejectReason = "file_too_large"
	RejectLoadFailed        LinkRejectReason = "load_failed"
	RejectSignerMismatch    LinkRejectReason = "signer_mismatch"
	RejectNameMismatch      LinkRejectReason = "name_mismatch"
	RejectUnauthorized      LinkRejectReason = "unauthorized"
	RejectBadSignature      LinkRejectReason = "bad_signature"
	RejectCertificate       LinkRejectReason = "certificate_rejected"
	RejectConflictingSigner LinkRejectReason = "conflicting_signer"
	RejectDuplicateFile     LinkRejectReason = "duplicate_file"
)

// ResolveLinkWorkers bounds the requested worker count n.
//
//   - n <= 0: min(runtime.GOMAXPROCS(0), DefaultAggregationWorkers), at least 1
//   - n > MaxAggregationWorkers: 64
//   - otherwise: n unchanged
func ResolveLinkWorkers(n int) int {
	if n <= 0 {
		workers := runtime.GOMAXPROCS(0)
		if workers > DefaultAggregationWorkers {
			workers = DefaultAggregationWorkers
		}
		if workers < 1 {
			workers = 1
		}
		return workers
	}
	if n > MaxAggregationWorkers {
		return MaxAggregationWorkers
	}
	return n
}

// LinkAggregator concurrently discovers, parses and verifies link metadata
// files for a layout. The zero value is usable; an empty LinkDir is treated
// as the current directory. A LinkAggregator value is safe for concurrent
// use by multiple goroutines: Aggregate is a value receiver and only reads
// the aggregator's configuration.
type LinkAggregator struct {
	// LinkDir is the directory scanned for link metadata files.
	LinkDir string
	// Workers is the desired upper bound of concurrently processed
	// candidates. Non-positive and out-of-range values are normalized via
	// ResolveLinkWorkers.
	Workers int
	// RootCertPool holds the trusted root certificates used when verifying
	// certificate-signed links. A nil pool is treated as an empty pool.
	RootCertPool *x509.CertPool
	// IntermediateCertPool holds intermediate certificates used when
	// verifying certificate-signed links. A nil pool is treated as an empty
	// pool.
	IntermediateCertPool *x509.CertPool
}

// LinkCandidate is a single link file discovered in the link directory
// together with its validation outcome.
type LinkCandidate struct {
	// Path is the full path of the candidate, joined from LinkDir and the
	// directory entry name.
	Path string
	// StepName is the layout step the candidate belongs to.
	StepName string
	// SignerKeyID is the full key id of the signature matching the file
	// name's short key id prefix.
	SignerKeyID string
	// State is the final state of the candidate.
	State LinkState
	// Reason is set when State is not LinkStateVerified.
	Reason LinkRejectReason
	// Err carries the underlying error that caused a rejection, if any.
	Err error
}

// StepLinkReport aggregates the candidates and verified links of one layout
// step.
type StepLinkReport struct {
	// StepName is the name of the layout step.
	StepName string
	// Threshold is the step's required number of distinct verified signers.
	Threshold int
	// Candidates are all files matching the step's link name pattern,
	// ordered by Path.
	Candidates []LinkCandidate
	// Verified maps the full signer key id to the verified metadata. It is
	// always non-nil.
	Verified map[string]Metadata
}

// LinkReport is the result of an aggregation run.
type LinkReport struct {
	// Steps holds one report per layout step, in layout order.
	Steps []StepLinkReport
}

// StepLinkFailure records that a step did not meet its link threshold.
type StepLinkFailure struct {
	// StepName is the name of the failing step.
	StepName string
	// Threshold is the required number of distinct verified signers.
	Threshold int
	// Verified is the number of distinct verified signers found.
	Verified int
	// Rejected is the number of candidates whose state is not verified.
	Rejected int
}

// LinkAggregationError aggregates the per-step threshold failures of an
// aggregation run.
type LinkAggregationError struct {
	// Failures holds the failing steps in layout order.
	Failures []StepLinkFailure
}

// Error implements the error interface.
func (e *LinkAggregationError) Error() string {
	parts := make([]string, 0, len(e.Failures))
	for _, f := range e.Failures {
		parts = append(parts, fmt.Sprintf(
			"step %q: threshold %d, verified %d, rejected %d",
			f.StepName, f.Threshold, f.Verified, f.Rejected))
	}
	return "link aggregation failed: " + strings.Join(parts, "; ")
}

// VerifiedLinks returns a fresh map of verified metadata keyed by step name
// and signer key id. Both the outer and inner maps are newly allocated, so
// callers may mutate them without affecting the report.
func (r *LinkReport) VerifiedLinks() map[string]map[string]Metadata {
	out := make(map[string]map[string]Metadata, len(r.Steps))
	for _, step := range r.Steps {
		inner := make(map[string]Metadata, len(step.Verified))
		for keyID, md := range step.Verified {
			inner[keyID] = md
		}
		out[step.StepName] = inner
	}
	return out
}

// Step returns the report for the named step. Unknown step names return the
// zero value and false.
func (r *LinkReport) Step(name string) (StepLinkReport, bool) {
	for i := range r.Steps {
		if r.Steps[i].StepName == name {
			return r.Steps[i], true
		}
	}
	return StepLinkReport{}, false
}

// discoveredCandidate is the immutable input to a worker.
type discoveredCandidate struct {
	path     string
	stepName string
	shortID  string
}

// processedCandidate is the output written to a pre-allocated result slot.
type processedCandidate struct {
	candidate   LinkCandidate
	metadata    Metadata
	canonical   []byte
	canonicalOK bool
}

// Aggregate scans the configured link directory once, processes every
// matching link file with a bounded number of concurrent workers, and
// verifies signatures, deduplicates and detects conflicting signers.
//
// A non-nil report is returned together with a *LinkAggregationError when one
// or more steps fail their threshold. Directory read failures and context
// cancellation return a nil report.
func (a LinkAggregator) Aggregate(ctx context.Context, layout Layout) (*LinkReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	linkDir := a.LinkDir
	if linkDir == "" {
		linkDir = "."
	}

	info, err := os.Stat(linkDir)
	if err != nil {
		return nil, fmt.Errorf("link aggregation: cannot access link directory %q: %w", linkDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("link aggregation: link directory %q is not a directory", linkDir)
	}

	// An empty layout yields an empty but non-nil report.
	if len(layout.Steps) == 0 {
		return &LinkReport{Steps: []StepLinkReport{}}, nil
	}

	entries, err := os.ReadDir(linkDir)
	if err != nil {
		return nil, fmt.Errorf("link aggregation: cannot read link directory %q: %w", linkDir, err)
	}

	rootPool := a.RootCertPool
	if rootPool == nil {
		rootPool = x509.NewCertPool()
	}
	intermediatePool := a.IntermediateCertPool
	if intermediatePool == nil {
		intermediatePool = x509.NewCertPool()
	}

	discovered := a.discover(entries, linkDir, layout)

	// Each worker writes its result into its own slot; goroutines never share
	// a writable map.
	results := make([]processedCandidate, len(discovered))
	workers := ResolveLinkWorkers(a.Workers)
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

dispatch:
	for i, dc := range discovered {
		select {
		case <-ctx.Done():
			// Stop dispatching new candidates. Everything already in flight
			// is awaited below so no goroutine is leaked.
			break dispatch
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(index int, input discoveredCandidate) {
			defer wg.Done()
			defer func() { <-sem }()
			results[index] = a.processCandidate(input, layout, rootPool, intermediatePool)
		}(i, dc)
	}

	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return a.buildReport(layout, results)
}

// discover performs the single directory scan and assigns each matching file
// to the longest matching step name. Entries are already sorted by file name
// by os.ReadDir.
func (a LinkAggregator) discover(entries []os.DirEntry, linkDir string, layout Layout) []discoveredCandidate {
	out := make([]discoveredCandidate, 0)
	for _, entry := range entries {
		name := entry.Name()
		stepName, shortID, ok := matchLinkFileName(name, layout)
		if !ok {
			continue
		}
		out = append(out, discoveredCandidate{
			path:     filepath.Join(linkDir, name),
			stepName: stepName,
			shortID:  shortID,
		})
	}
	return out
}

// matchLinkFileName checks that name is exactly "<step>.<8 hex>.link" and
// returns the longest matching step name and the 8 hex characters.
func matchLinkFileName(name string, layout Layout) (string, string, bool) {
	const suffixLen = len(".link")
	if len(name) <= suffixLen {
		return "", "", false
	}
	if !strings.HasSuffix(name, ".link") {
		return "", "", false
	}
	stem := name[:len(name)-suffixLen]
	dot := strings.LastIndex(stem, ".")
	if dot <= 0 {
		return "", "", false
	}
	prefix := stem[:dot]
	shortID := stem[dot+1:]
	if len(shortID) != 8 || !isLowerHex(shortID) {
		return "", "", false
	}

	stepName := ""
	for _, step := range layout.Steps {
		if prefix == step.Name && len(step.Name) > len(stepName) {
			stepName = step.Name
		}
	}
	if stepName == "" {
		return "", "", false
	}
	return stepName, shortID, true
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// processCandidate runs all per-file validation stages. It never panics on
// malformed or empty metadata; every failure is recorded on the candidate.
func (a LinkAggregator) processCandidate(input discoveredCandidate, layout Layout,
	rootPool, intermediatePool *x509.CertPool) processedCandidate {

	cand := LinkCandidate{
		Path:     input.path,
		StepName: input.stepName,
	}

	// Lstat does not follow symlinks.
	info, err := os.Lstat(input.path)
	if err != nil {
		cand.State = LinkStateRejected
		cand.Reason = RejectLoadFailed
		cand.Err = fmt.Errorf("link aggregation: stat %q failed: %w", input.path, err)
		return processedCandidate{candidate: cand}
	}

	// Only regular files are read. Symlinks, directories and device files
	// are rejected without reading their content.
	if !info.Mode().IsRegular() {
		cand.State = LinkStateRejected
		cand.Reason = RejectNotRegularFile
		cand.Err = fmt.Errorf("link aggregation: %q is not a regular file", input.path)
		return processedCandidate{candidate: cand}
	}

	// Size is checked before any byte is read.
	if info.Size() > MaxLinkFileSize {
		cand.State = LinkStateRejected
		cand.Reason = RejectFileTooLarge
		cand.Err = fmt.Errorf("link aggregation: %q size %d exceeds maximum %d",
			input.path, info.Size(), MaxLinkFileSize)
		return processedCandidate{candidate: cand}
	}

	md, err := LoadMetadata(input.path)
	if err != nil {
		cand.State = LinkStateRejected
		cand.Reason = RejectLoadFailed
		cand.Err = fmt.Errorf("link aggregation: cannot parse %q: %w", input.path, err)
		return processedCandidate{candidate: cand}
	}

	sigs := md.Sigs()
	if sigs == nil || len(sigs) == 0 {
		cand.State = LinkStateRejected
		cand.Reason = RejectLoadFailed
		cand.Err = fmt.Errorf("link aggregation: %q has no signatures", input.path)
		return processedCandidate{candidate: cand}
	}

	// The file name's 8 character key id prefix must match exactly one
	// signature's key id prefix, ignoring case.
	signerKeyID, matchCount := "", 0
	for _, sig := range sigs {
		if len(sig.KeyID) >= 8 && strings.EqualFold(sig.KeyID[:8], input.shortID) {
			signerKeyID = sig.KeyID
			matchCount++
		}
	}
	if matchCount != 1 {
		cand.State = LinkStateRejected
		cand.Reason = RejectSignerMismatch
		cand.Err = fmt.Errorf("link aggregation: %q short key id %q matches %d signature(s)",
			input.path, input.shortID, matchCount)
		return processedCandidate{candidate: cand}
	}
	cand.SignerKeyID = signerKeyID

	payload := md.GetPayload()
	if payload == nil {
		cand.State = LinkStateRejected
		cand.Reason = RejectLoadFailed
		cand.Err = fmt.Errorf("link aggregation: %q has an empty payload", input.path)
		return processedCandidate{candidate: cand}
	}

	switch p := payload.(type) {
	case Link:
		if p.Name != input.stepName {
			cand.State = LinkStateRejected
			cand.Reason = RejectNameMismatch
			cand.Err = fmt.Errorf("link aggregation: %q link name %q does not match step %q",
				input.path, p.Name, input.stepName)
			return processedCandidate{candidate: cand}
		}
	case Layout:
		// Sublayout payloads skip the name check.
	default:
		cand.State = LinkStateRejected
		cand.Reason = RejectLoadFailed
		cand.Err = fmt.Errorf("link aggregation: %q has an unsupported payload type %T",
			input.path, payload)
		return processedCandidate{candidate: cand}
	}

	reason, verifyErr := a.verifyCandidate(input, layout, md, signerKeyID, rootPool, intermediatePool)
	if reason != "" {
		cand.State = LinkStateRejected
		cand.Reason = reason
		cand.Err = verifyErr
		return processedCandidate{candidate: cand}
	}

	canonical, err := cjson.EncodeCanonical(payload)
	if err != nil {
		cand.State = LinkStateRejected
		cand.Reason = RejectLoadFailed
		cand.Err = fmt.Errorf("link aggregation: cannot canonicalize payload of %q: %w",
			input.path, err)
		return processedCandidate{candidate: cand}
	}

	cand.State = LinkStateVerified
	return processedCandidate{
		candidate:   cand,
		metadata:    md,
		canonical:   canonical,
		canonicalOK: true,
	}
}

// verifyCandidate tries the public-key path first and falls back to the
// certificate path. It returns a non-empty reject reason and error when both
// fail.
func (a LinkAggregator) verifyCandidate(input discoveredCandidate, layout Layout,
	md Metadata, signerKeyID string, rootPool, intermediatePool *x509.CertPool) (LinkRejectReason, error) {

	step := findStep(layout, input.stepName)

	publicKeyAvailable := false
	for _, authorizedKeyID := range step.PubKeys {
		if authorizedKeyID != signerKeyID {
			continue
		}
		verifierKey, ok := layout.Keys[authorizedKeyID]
		if !ok {
			continue
		}
		publicKeyAvailable = true
		if err := md.VerifySignature(verifierKey); err == nil {
			return "", nil
		}
	}

	// Certificate path.
	sig, sigErr := md.GetSignatureForKeyID(signerKeyID)
	if sigErr != nil {
		if !publicKeyAvailable {
			return RejectUnauthorized, fmt.Errorf(
				"link aggregation: %q has no authorized public key for signer %q and no certificate: %w",
				input.path, signerKeyID, sigErr)
		}
		return RejectBadSignature, fmt.Errorf(
			"link aggregation: signature verification failed for %q: %w", input.path, sigErr)
	}

	cert, certErr := sig.GetCertificate()
	if certErr != nil {
		if !publicKeyAvailable {
			return RejectUnauthorized, fmt.Errorf(
				"link aggregation: %q has no authorized public key for signer %q and no usable certificate: %w",
				input.path, signerKeyID, certErr)
		}
		return RejectBadSignature, fmt.Errorf(
			"link aggregation: signature verification failed for %q: %w", input.path, certErr)
	}

	if err := step.CheckCertConstraints(cert, layout.RootCAIDs(), rootPool, intermediatePool); err != nil {
		return RejectCertificate, fmt.Errorf(
			"link aggregation: certificate constraints failed for %q: %w", input.path, err)
	}

	if err := md.VerifySignature(cert); err != nil {
		return RejectCertificate, fmt.Errorf(
			"link aggregation: certificate signature verification failed for %q: %w",
			input.path, err)
	}

	return "", nil
}

func findStep(layout Layout, name string) Step {
	for _, step := range layout.Steps {
		if step.Name == name {
			return step
		}
	}
	return Step{}
}

// buildReport performs the single-threaded, deterministic post-processing:
// grouping, deduplication, conflict detection and threshold accounting.
func (a LinkAggregator) buildReport(layout Layout, results []processedCandidate) (*LinkReport, error) {
	type groupKey struct {
		stepName string
		keyID    string
	}
	groups := make(map[groupKey][]int)

	// Candidates stay in path order because results mirrors the sorted
	// discovery slice.
	for i, res := range results {
		if !res.canonicalOK {
			continue
		}
		key := groupKey{res.candidate.StepName, res.candidate.SignerKeyID}
		groups[key] = append(groups[key], i)
	}

	groupKeys := make([]groupKey, 0, len(groups))
	for key := range groups {
		groupKeys = append(groupKeys, key)
	}
	sort.Slice(groupKeys, func(i, j int) bool {
		if groupKeys[i].stepName != groupKeys[j].stepName {
			return groupKeys[i].stepName < groupKeys[j].stepName
		}
		return groupKeys[i].keyID < groupKeys[j].keyID
	})

	for _, key := range groupKeys {
		indices := groups[key]
		if len(indices) == 1 {
			continue
		}

		allEqual := true
		first := results[indices[0]].canonical
		for _, idx := range indices[1:] {
			if !bytesEqual(first, results[idx].canonical) {
				allEqual = false
				break
			}
		}

		if allEqual {
			// Indices are in path order, so the first is the lexicographically
			// smallest path. The rest are duplicate files.
			for _, idx := range indices[1:] {
				res := &results[idx]
				res.candidate.State = LinkStateRejected
				res.candidate.Reason = RejectDuplicateFile
				res.candidate.Err = fmt.Errorf(
					"link aggregation: %q duplicates %q for step %q signer %q",
					res.candidate.Path, results[indices[0]].candidate.Path,
					key.stepName, key.keyID)
				res.canonicalOK = false
				res.metadata = nil
			}
			continue
		}

		// Different payloads for the same step and signer: the whole group
		// conflicts and never enters Verified.
		for _, idx := range indices {
			res := &results[idx]
			res.candidate.State = LinkStateConflicting
			res.candidate.Reason = RejectConflictingSigner
			res.candidate.Err = fmt.Errorf(
				"link aggregation: conflicting links for step %q signer %q",
				key.stepName, key.keyID)
			res.canonicalOK = false
			res.metadata = nil
		}
	}

	report := &LinkReport{Steps: make([]StepLinkReport, 0, len(layout.Steps))}
	var failures []StepLinkFailure

	for _, step := range layout.Steps {
		stepReport := StepLinkReport{
			StepName:   step.Name,
			Threshold:  step.Threshold,
			Candidates: make([]LinkCandidate, 0),
			Verified:   make(map[string]Metadata),
		}

		rejected := 0
		for _, res := range results {
			if res.candidate.StepName != step.Name {
				continue
			}
			stepReport.Candidates = append(stepReport.Candidates, res.candidate)
			if res.candidate.State != LinkStateVerified {
				rejected++
				continue
			}
			stepReport.Verified[res.candidate.SignerKeyID] = res.metadata
		}

		report.Steps = append(report.Steps, stepReport)

		if step.Threshold < 1 || len(stepReport.Verified) < step.Threshold {
			failures = append(failures, StepLinkFailure{
				StepName:  step.Name,
				Threshold: step.Threshold,
				Verified:  len(stepReport.Verified),
				Rejected:  rejected,
			})
		}
	}

	if len(failures) > 0 {
		// The report stays available for auditing; the error signals the
		// threshold failure and is recognizable via errors.As.
		return report, &LinkAggregationError{Failures: failures}
	}
	return report, nil
}

// bytesEqual compares two canonical payload byte slices.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
