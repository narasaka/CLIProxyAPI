package auth

import (
	"context"
	"errors"
	"maps"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	log "github.com/sirupsen/logrus"
)

// AttributeClaudeExtraUsage carries a credential's own claude extra-usage policy.
const AttributeClaudeExtraUsage = "extra_usage"

// maxClaudeExtraUsageBlock bounds a block to the longest Anthropic subscription
// window (7 days) plus clock-skew allowance. A later reset is not a plan window.
const maxClaudeExtraUsageBlock = 7*24*time.Hour + time.Hour

var errClaudeExtraUsageBlocked = errors.New("subscription usage limit reached and extra usage is blocked (claude.extra-usage: block)")

// ApplyClaudeExtraUsageMetadata copies a valid "extra_usage" auth-file field into
// the credential's attributes. Auth.Metadata must not be read on the request path,
// so loaders resolve it once while the auth is still private to them.
func ApplyClaudeExtraUsageMetadata(auth *Auth) {
	if auth == nil {
		return
	}
	delete(auth.Attributes, AttributeClaudeExtraUsage)
	rawValue, present := auth.Metadata[AttributeClaudeExtraUsage]
	raw, _ := rawValue.(string)
	value := internalconfig.NormalizeClaudeExtraUsage(raw)
	if value == "" {
		if present && rawValue != nil && strings.EqualFold(strings.TrimSpace(auth.Provider), "claude") {
			log.Warnf("auth %s: unrecognized extra_usage %v (supported: allow, block); using claude.extra-usage", auth.ID, rawValue)
		}
		return
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes[AttributeClaudeExtraUsage] = value
}

// claudeExtraUsageKeep selects whether observeResultHeaders keeps a Claude
// extra-usage block against stale responses, and at which snapshot level.
type claudeExtraUsageKeep int

const (
	claudeExtraUsageKeepOff claudeExtraUsageKeep = iota
	claudeExtraUsageKeepCredential
	claudeExtraUsageKeepModel
)

// claudeExtraUsageEnforced reports whether the extra-usage policy blocks auth:
// a Claude subscription credential whose effective policy is block.
func (m *Manager) claudeExtraUsageEnforced(auth *Auth) bool {
	return auth != nil && executorKeyFromAuth(auth) == "claude" && claudeSubscriptionCredential(auth) &&
		claudeExtraUsageBlocked(m.runtimeConfigSnapshot(), auth)
}

// claudeExtraUsageKeepFor returns the keep mode for auth's snapshot at one level.
// Without an enforced block, observations behave as for any other provider.
func (m *Manager) claudeExtraUsageKeepFor(auth *Auth, credentialLevel bool) claudeExtraUsageKeep {
	switch {
	case !m.claudeExtraUsageEnforced(auth):
		return claudeExtraUsageKeepOff
	case credentialLevel:
		return claudeExtraUsageKeepCredential
	default:
		return claudeExtraUsageKeepModel
	}
}

// claudeSubscriptionCredential reports whether auth bills against a Claude plan,
// the only kind of credential extra usage applies to. It matches the Claude
// executor's classification: an OAuth token is a subscription credential even
// when configured as an API key, and a real API key is always billed at API rates.
func claudeSubscriptionCredential(auth *Auth) bool {
	apiKey := strings.TrimSpace(authAttribute(auth, AttributeAPIKey))
	if strings.Contains(apiKey, "sk-ant-oat") {
		return true
	}
	if auth.AuthKind() == AuthKindAPIKey {
		return false
	}
	return apiKey == ""
}

// claudeExtraUsageBlocked reports whether the effective policy for auth is block:
// the credential's own value wins over the global claude.extra-usage setting.
func claudeExtraUsageBlocked(cfg *internalconfig.Config, auth *Auth) bool {
	policy := ""
	if auth != nil {
		policy = internalconfig.NormalizeClaudeExtraUsage(auth.Attributes[AttributeClaudeExtraUsage])
	}
	if policy == "" && cfg != nil {
		policy = internalconfig.NormalizeClaudeExtraUsage(cfg.Claude.ExtraUsage)
	}
	return policy == internalconfig.ClaudeExtraUsageBlock
}

// claudeExtraUsageRefusal refuses auth for the current request when the policy is
// block and the latest Anthropic response for this credential, or for this model
// on it, was billed as extra usage. The refusal is request-scoped: nothing is
// recorded on the credential, so switching the policy back to allow takes effect
// on the next request. Once no other credential can serve the request, the client
// receives a 429 that carries the plan's reset time.
func (m *Manager) claudeExtraUsageRefusal(auth *Auth, stateModel, routeModel string, now time.Time) error {
	if !m.claudeExtraUsageEnforced(auth) {
		return nil
	}
	credentialSignals, modelSignals := m.claudeExtraUsageSnapshots(auth, stateModel, routeModel)
	signals := credentialSignals
	resetAt, blocked := claudeExtraUsageResetAt(credentialSignals, true, now)
	// The requested model may also be blocked by its own weekly window, which can
	// outlast the shared ones. The later deadline is the real one.
	if modelResetAt, modelBlocked := claudeExtraUsageResetAt(modelSignals, false, now); modelBlocked && modelResetAt.After(resetAt) {
		signals, resetAt, blocked = modelSignals, modelResetAt, true
	}
	if !blocked {
		return nil
	}
	log.WithFields(log.Fields{
		"auth_id":  auth.ID,
		"model":    stateModel,
		"reset_at": resetAt.Format(time.RFC3339),
	}).Debug("claude extra-usage blocked: skipping credential whose plan limit is used up")
	cooldown := newModelCooldownErrorForCandidates(stateModel, "claude", resetAt.Sub(now), errClaudeExtraUsageBlocked, true, claudeExtraUsageRefusalSignals(signals))
	return &credentialTerminatedError{terminal: cooldown, recoverAt: resetAt}
}

// claudeExtraUsageSnapshots returns the newest credential-level and model-level
// rate-limit snapshots for auth. The picked auth can be a per-model scheduler copy
// that missed responses for other models on the same credential, so the manager's
// live auth is consulted too; a Home-dispatched auth may exist only as the copy.
// The live model state is found under the key MarkResult records it under.
func (m *Manager) claudeExtraUsageSnapshots(auth *Auth, stateModel, routeModel string) (credential, model map[string]string) {
	credentialQuota := auth.Quota
	var modelQuota QuotaState
	if state := existingModelState(auth, stateModel); state != nil {
		modelQuota = state.Quota
	}
	m.mu.RLock()
	if live := m.auths[auth.ID]; live != nil {
		if observationIsNewer(live.Quota, credentialQuota) {
			credentialQuota = live.Quota
		}
		if state := existingModelState(live, m.claudeObservationModelKeyLocked(live, stateModel, routeModel)); state != nil && observationIsNewer(state.Quota, modelQuota) {
			modelQuota = state.Quota
		}
	}
	credential, model = maps.Clone(credentialQuota.Signals), maps.Clone(modelQuota.Signals)
	m.mu.RUnlock()
	return credential, model
}

// observationIsNewer reports whether candidate's snapshot is newer than current's:
// by header arrival when both carry one, since recording order can differ from
// arrival order, and by observation time otherwise.
func observationIsNewer(candidate, current QuotaState) bool {
	if candidate.observedSeq > 0 && current.observedSeq > 0 && candidate.observedSeq != current.observedSeq {
		return candidate.observedSeq > current.observedSeq
	}
	// Equal stamps can differ when an older extra-usage response was adopted
	// under the newer stamp; the adoption is the later observation.
	return candidate.ObservedAt.After(current.ObservedAt)
}

// watchClaudeResponseHeaders records a local Claude attempt's rate-limit headers
// the moment they arrive. A result is recorded only after the whole response
// (or stream) is done, so otherwise a response showing the plan limit used up
// would not block new requests for as long as it runs. Arrival ordering keeps the
// later result from replacing anything newer, and the same staleness check as
// MarkResult keeps an attempt on a replaced credential off its successor.
func (m *Manager) watchClaudeResponseHeaders(ctx context.Context, attempt *Auth, accessToken, provider, model, routeModel string) {
	if m == nil || attempt == nil || !strings.EqualFold(strings.TrimSpace(provider), "claude") {
		return
	}
	identity := Result{
		AuthID:            attempt.ID,
		AccessToken:       accessToken,
		CredentialVersion: attempt.CredentialVersion,
		RegistrationEpoch: attempt.RegistrationEpoch,
	}
	internallogging.ObserveResponseHeaders(ctx, func(headers http.Header, arrival uint64) {
		m.observeClaudeResponseHeaders(identity, provider, model, routeModel, headers, arrival)
	})
}

func (m *Manager) observeClaudeResponseHeaders(identity Result, provider, model, routeModel string, headers http.Header, arrival uint64) {
	if len(collectQuotaSignals("claude", headers)) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	auth := m.auths[identity.AuthID]
	if auth == nil || isStaleExecutionResult(identity, auth) {
		return
	}
	auth.Quota.observeResultHeaders(provider, headers, arrival, now, m.claudeExtraUsageKeepFor(auth, true))
	if state := ensureModelState(auth, m.claudeObservationModelKeyLocked(auth, model, routeModel)); state != nil {
		state.Quota.observeResultHeaders(provider, headers, arrival, now, m.claudeExtraUsageKeepFor(auth, false))
	}
}

// claudeObservationModelKeyLocked returns the model-state key MarkResult records
// a result for model under, so early observations and refusal lookups use the
// same per-model snapshot as recorded results (aliases and prefixes included).
// The caller holds m.mu.
func (m *Manager) claudeObservationModelKeyLocked(auth *Auth, model, routeModel string) string {
	modelKey := canonicalModelKey(model)
	if modelKey == "" {
		modelKey = canonicalModelKey(routeModel)
	}
	if modelKey == "" {
		return ""
	}
	return m.resolveMarkResultModelKeyLocked(auth, modelKey, routeModel)
}

// keepClaudeExtraUsageSnapshot reports whether current, a snapshot whose windows
// at this level show extra usage still in effect, must survive incoming headers.
// The headers of a response are fixed when Anthropic admits the request, so a
// response admitted just before the limit was crossed can arrive after the one
// that crossed it. Such a response describes the same plan window; only a window
// that has rolled over to a later reset proves the block is over. Incoming
// headers that show extra usage at this level replace the snapshot unless they
// would shorten its deadline. The block also ends on its own once its reset
// passes.
func keepClaudeExtraUsageSnapshot(current map[string]string, incoming http.Header, credentialLevel bool, now time.Time) bool {
	currentDeadline, blocked := claudeExtraUsageResetAt(current, credentialLevel, now)
	if !blocked {
		return false
	}
	incomingSignals := collectQuotaSignals("claude", incoming)
	if len(incomingSignals) == 0 {
		return false
	}
	currentHeaders := make(http.Header, len(current))
	for key, value := range current {
		currentHeaders.Set(key, value)
	}
	incomingHeaders := make(http.Header, len(incomingSignals))
	for key, value := range incomingSignals {
		incomingHeaders.Set(key, value)
	}
	if claudeBlockingWindowRolledOver(currentHeaders, incomingHeaders, credentialLevel) {
		return false
	}
	// Judged at the same level: a per-model window in extra usage says nothing
	// about the shared windows a credential-level block rests on. Another
	// extra-usage response replaces the block unless it would shorten it.
	if incomingDeadline, inExtraUsage := claudeExtraUsageResetAt(incomingSignals, credentialLevel, now); inExtraUsage {
		return incomingDeadline.Before(currentDeadline)
	}
	return true
}

// claudeBlockingWindowRolledOver reports whether incoming shows a window that
// blocks current already started over, which proves the block is over.
func claudeBlockingWindowRolledOver(current, incoming http.Header, credentialLevel bool) bool {
	for _, window := range rejectedClaudeUnifiedWindows(current) {
		if (window == "5h" || window == "7d") != credentialLevel {
			continue
		}
		if claudeResetRolledOver(current, incoming, claudeUnifiedWindowHeader(window, "Reset")) {
			return true
		}
	}
	// A block known only from the unified headers rolls over when a response for
	// the same representative claim reports a later unified reset.
	claim := strings.ToLower(strings.TrimSpace(current.Get("Anthropic-Ratelimit-Unified-Representative-Claim")))
	return claim != "" && strings.HasPrefix(claim, "seven_day_") != credentialLevel &&
		strings.EqualFold(strings.TrimSpace(incoming.Get("Anthropic-Ratelimit-Unified-Representative-Claim")), claim) &&
		claudeResetRolledOver(current, incoming, "Anthropic-Ratelimit-Unified-Reset")
}

// claudeResetRolledOver reports whether incoming carries a later value than
// current for the given reset header, meaning that window started over.
func claudeResetRolledOver(current, incoming http.Header, resetHeader string) bool {
	currentReset, okCurrent := parseClaudeResetEpoch(current.Get(resetHeader))
	incomingReset, okIncoming := parseClaudeResetEpoch(incoming.Get(resetHeader))
	return okCurrent && okIncoming && incomingReset.After(currentReset)
}

// claudeExtraUsageResetAt reports whether signals, one upstream response's
// Anthropic rate-limit headers, show a request billed as extra usage, and when the
// plan limit behind it resets. This is the response shape Claude Code reports as
// "using extra usage": unified status rejected while overage is allowed.
//
// credentialLevel selects which windows count. The credential-level snapshot
// decides the plan-wide 5h and 7d windows, which every model shares. A model's
// snapshot decides only that model's own windows (a seven_day_* claim), which
// bill only that model as extra usage. Keeping the levels disjoint means a
// model's copy of a shared window can never outlive the credential's view of it.
//
// Without a future reset no block applies: blocked credentials receive no traffic,
// so an open-ended block would never see the response that lifts it.
func claudeExtraUsageResetAt(signals map[string]string, credentialLevel bool, now time.Time) (time.Time, bool) {
	if len(signals) == 0 {
		return time.Time{}, false
	}
	headers := make(http.Header, len(signals))
	for key, value := range signals {
		headers.Set(key, value)
	}
	if !strings.EqualFold(strings.TrimSpace(headers.Get("Anthropic-Ratelimit-Unified-Status")), "rejected") {
		return time.Time{}, false
	}
	if !isAllowedClaudeWindowStatus(headers.Get("Anthropic-Ratelimit-Unified-Overage-Status")) {
		return time.Time{}, false
	}
	claim := strings.ToLower(strings.TrimSpace(headers.Get("Anthropic-Ratelimit-Unified-Representative-Claim")))
	var resetHeaders []string
	sharedWindowRejected, modelWindowRejected := false, false
	for _, window := range rejectedClaudeUnifiedWindows(headers) {
		shared := window == "5h" || window == "7d"
		sharedWindowRejected = sharedWindowRejected || shared
		modelWindowRejected = modelWindowRejected || !shared
		if shared == credentialLevel {
			resetHeaders = append(resetHeaders, claudeUnifiedWindowHeader(window, "Reset"))
		}
	}
	// The unified reset belongs to the representative claim. Without a claim it is
	// shared unless the only rejected windows are per-model ones.
	unifiedShared := !strings.HasPrefix(claim, "seven_day_") && (claim != "" || sharedWindowRejected || !modelWindowRejected)
	if unifiedShared == credentialLevel {
		resetHeaders = append(resetHeaders, "Anthropic-Ratelimit-Unified-Reset")
	}
	var latest time.Time
	for _, name := range resetHeaders {
		resetAt, ok := parseClaudeResetEpoch(headers.Get(name))
		if !ok || !resetAt.After(now) || resetAt.Sub(now) > maxClaudeExtraUsageBlock {
			continue
		}
		if resetAt.After(latest) {
			latest = resetAt
		}
	}
	if latest.IsZero() {
		return time.Time{}, false
	}
	return latest, true
}

// claudeExtraUsageRefusalSignals reshapes the observed headers into the ones a
// plan without extra usage returns, so clients show the plan limit and its reset.
func claudeExtraUsageRefusalSignals(signals map[string]string) map[string]string {
	refusal := maps.Clone(signals)
	for key := range refusal {
		if strings.HasPrefix(strings.ToLower(key), "anthropic-ratelimit-unified-overage-") {
			delete(refusal, key)
		}
	}
	refusal["Anthropic-Ratelimit-Unified-Overage-Status"] = "rejected"
	return refusal
}

func parseClaudeResetEpoch(raw string) (time.Time, bool) {
	seconds, errParse := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if errParse != nil || seconds <= 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds > math.MaxInt64/2 {
		return time.Time{}, false
	}
	whole, frac := math.Modf(seconds)
	return time.Unix(int64(whole), int64(frac*1e9)), true
}
