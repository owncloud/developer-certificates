package ledger

// Decision is the outcome of the first-come-first-served ownership check
// (design §6, enrollment spec §4 step 8).
type Decision int

const (
	// DecisionNewClaim: no ledger file exists for this appId — a new claim,
	// bound to the proven target repo.
	DecisionNewClaim Decision = iota
	// DecisionAllowed: the appId is already owned by the same target repo —
	// a renewal or an additional concurrent certificate is permitted.
	DecisionAllowed
	// DecisionRejectedMismatch: the appId is owned by a different repo — reject.
	DecisionRejectedMismatch
	// DecisionRejectedReserved: the appId is a first-party reservation — reject
	// any third-party attempt.
	DecisionRejectedReserved
)

// Decide implements the FCFS ownership rule. existing is nil when no ledger
// file exists for the appId; targetRepo is the "owner/name" slug the requester
// proved control of.
//
// The reserved check comes before the repo comparison so a reservation always
// rejects, even if the request's repo happened to (or was forged to) match the
// reserved entry's owner.repo field.
func Decide(existing *Ledger, targetRepo string) Decision {
	if existing == nil {
		return DecisionNewClaim
	}
	if existing.Reserved {
		return DecisionRejectedReserved
	}
	if existing.Owner.Repo == targetRepo {
		return DecisionAllowed
	}
	return DecisionRejectedMismatch
}
