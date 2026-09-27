package security

import (
	"math"
	"sync"
)

// PromptProfile tracks "normal" prompt behavior per tenant for anomaly detection.
// Builds a statistical profile of prompt characteristics and flags deviations.
type PromptProfile struct {
	mu         sync.RWMutex
	profiles   map[string]*tenantProfile
	minSamples int
}

type tenantProfile struct {
	count       int
	sumLength   float64
	sumLengthSq float64
	// Prior versions carried sumWordCount, sumWordCountSq, maxLength
	// and lastAlertLength on this struct, all written into during
	// Observe but never read anywhere in the package (lastAlertLength
	// was never even written — golangci-lint's `unused` linter caught
	// that one; the others got missed because they had a written
	// side). Dropped rather than kept as scaffolding: dead per-tenant
	// state grows with the tenant map (see the cap-then-overflow work
	// in pkg/proxy/stats and pkg/security/ratelimit) and every unread
	// float64 was 8 bytes × up to 4096 tenants of memory waste.
}

// AnomalyResult describes a detected prompt anomaly.
type AnomalyResult struct {
	IsAnomaly    bool
	Score        float64 // standard deviations from mean
	Reason       string
	PromptLength int
	MeanLength   float64
	StdDev       float64
}

// NewPromptProfile creates an anomaly detector.
// minSamples is how many prompts to observe before alerting (learning period).
func NewPromptProfile(minSamples int) *PromptProfile {
	return &PromptProfile{
		profiles:   make(map[string]*tenantProfile),
		minSamples: minSamples,
	}
}

// Observe records a prompt and returns any anomaly detected.
func (pp *PromptProfile) Observe(tenant, prompt string) AnomalyResult {
	length := len(prompt)

	pp.mu.Lock()
	p, ok := pp.profiles[tenant]
	if !ok {
		p = &tenantProfile{}
		pp.profiles[tenant] = p
	}

	p.count++
	p.sumLength += float64(length)
	p.sumLengthSq += float64(length) * float64(length)

	count := p.count
	sumLen := p.sumLength
	sumLenSq := p.sumLengthSq
	pp.mu.Unlock()

	// Don't alert during learning period
	if count < pp.minSamples {
		return AnomalyResult{PromptLength: length}
	}

	// Compute z-score for prompt length
	mean := sumLen / float64(count)
	variance := (sumLenSq / float64(count)) - (mean * mean)
	stddev := math.Sqrt(math.Abs(variance))

	if stddev < 1 {
		stddev = 1 // prevent division by zero for uniform prompts
	}

	zscore := math.Abs(float64(length)-mean) / stddev

	result := AnomalyResult{
		PromptLength: length,
		MeanLength:   math.Round(mean),
		StdDev:       math.Round(stddev*10) / 10,
		Score:        math.Round(zscore*100) / 100,
	}

	// Flag as anomaly if >3 standard deviations from mean
	if zscore > 3.0 {
		result.IsAnomaly = true
		if float64(length) > mean {
			result.Reason = "Prompt significantly longer than tenant's typical pattern"
		} else {
			result.Reason = "Prompt significantly shorter than tenant's typical pattern"
		}
	}

	// Also flag sudden 10x length spikes
	if count > pp.minSamples && float64(length) > mean*10 && length > 500 {
		result.IsAnomaly = true
		result.Reason = "Prompt length spike: 10x above mean"
	}

	return result
}

// TenantStats returns the current profile stats for a tenant.
func (pp *PromptProfile) TenantStats(tenant string) (count int, meanLength float64, stddev float64) {
	pp.mu.RLock()
	defer pp.mu.RUnlock()

	p, ok := pp.profiles[tenant]
	if !ok || p.count == 0 {
		return 0, 0, 0
	}

	mean := p.sumLength / float64(p.count)
	variance := (p.sumLengthSq / float64(p.count)) - (mean * mean)
	std := math.Sqrt(math.Abs(variance))

	return p.count, math.Round(mean), math.Round(std*10) / 10
}

func countWords(s string) int {
	words := 0
	inWord := false
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\t' {
			inWord = false
		} else if !inWord {
			inWord = true
			words++
		}
	}
	return words
}
