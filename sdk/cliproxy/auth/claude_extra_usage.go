package auth

import (
	"errors"
	"maps"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
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
	raw, _ := auth.Metadata[AttributeClaudeExtraUsage].(string)
	value := internalconfig.NormalizeClaudeExtraUsage(raw)
	if value == "" {
		return
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes[AttributeClaudeExtraUsage] = value
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
func (m *Manager) claudeExtraUsageRefusal(auth *Auth, stateModel string, now time.Time) error {
	if auth == nil || executorKeyFromAuth(auth) != "claude" || !claudeExtraUsageBlocked(m.runtimeConfigSnapshot(), auth) {
		return nil
	}
	credentialSignals, modelSignals := m.claudeExtraUsageSnapshots(auth, stateModel)
	signals := credentialSignals
	resetAt, blocked := claudeExtraUsageResetAt(credentialSignals, true, now)
	// The requested model may also be blocked by its own weekly window, which can
	// outlast the shared one. The later deadline is the real one.
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
func (m *Manager) claudeExtraUsageSnapshots(auth *Auth, stateModel string) (credential, model map[string]string) {
	credentialQuota := auth.Quota
	var modelQuota QuotaState
	if state := existingModelState(auth, stateModel); state != nil {
		modelQuota = state.Quota
	}
	m.mu.RLock()
	if live := m.auths[auth.ID]; live != nil {
		if live.Quota.ObservedAt.After(credentialQuota.ObservedAt) {
			credentialQuota = live.Quota
		}
		if state := existingModelState(live, stateModel); state != nil && state.Quota.ObservedAt.After(modelQuota.ObservedAt) {
			modelQuota = state.Quota
		}
	}
	credential, model = maps.Clone(credentialQuota.Signals), maps.Clone(modelQuota.Signals)
	m.mu.RUnlock()
	return credential, model
}

// claudeExtraUsageResetAt reports whether signals, one upstream response's
// Anthropic rate-limit headers, show a request billed as extra usage, and when the
// plan limit behind it resets. This is the response shape Claude Code reports as
// "using extra usage": unified status rejected while overage is allowed.
//
// sharedOnly limits the match to the plan-wide 5h and 7d windows. A per-model
// weekly window (a seven_day_* claim) only bills that model as extra usage, so the
// credential-level snapshot, which reflects whichever model ran last, must not
// block every other model on it, nor for longer than the shared windows last.
//
// Without a future reset no block applies: blocked credentials receive no traffic,
// so an open-ended block would never see the response that lifts it.
func claudeExtraUsageResetAt(signals map[string]string, sharedOnly bool, now time.Time) (time.Time, bool) {
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
		if !sharedOnly || shared {
			resetHeaders = append(resetHeaders, claudeUnifiedWindowHeader(window, "Reset"))
		}
	}
	// The unified reset belongs to the representative claim. Without a claim it is
	// shared unless the only rejected windows are per-model ones.
	unifiedShared := !strings.HasPrefix(claim, "seven_day_") && (claim != "" || sharedWindowRejected || !modelWindowRejected)
	if !sharedOnly || unifiedShared {
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
