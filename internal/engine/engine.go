package engine

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"argos/internal/domain"
	"argos/internal/providers"
	"argos/internal/storage"
)

const DefaultCacheTTL = 24 * time.Hour

func DetectIndicatorType(raw string) (string, domain.ArtifactType) {
	norm, artType, ok := ClassifyArtifact(raw)
	if !ok {
		return strings.TrimSpace(raw), domain.TypeDomain
	}
	return norm, artType
}

type Orchestrator struct {
	store     *storage.SQLiteStore
	providers []providers.Provider
	workers   int
	cacheTTL  time.Duration
}

func NewOrchestrator(store *storage.SQLiteStore, provs []providers.Provider, workers int) *Orchestrator {
	if workers < 1 {
		workers = 4
	}
	return &Orchestrator{
		store:     store,
		providers: provs,
		workers:   workers,
		cacheTTL:  DefaultCacheTTL,
	}
}

func (o *Orchestrator) TriageBatch(ctx context.Context, rawItems []string) ([]domain.Artifact, domain.PivotSummary) {
	return o.TriageInvestigation(ctx, 1, rawItems)
}

func (o *Orchestrator) TriageInvestigation(ctx context.Context, investigationID int64, rawItems []string) ([]domain.Artifact, domain.PivotSummary) {
	if investigationID == 0 {
		investigationID = 1
	}

	type job struct {
		idx int
		raw string
	}

	jobs := make(chan job, len(rawItems))
	results := make([]domain.Artifact, len(rawItems))

	var wg sync.WaitGroup
	for w := 0; w < o.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results[j.idx] = o.triageOne(ctx, investigationID, j.raw)
			}
		}()
	}

	for i, raw := range rawItems {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		jobs <- job{idx: i, raw: trimmed}
	}
	close(jobs)
	wg.Wait()

	var compact []domain.Artifact
	for _, r := range results {
		if r.Value != "" {
			compact = append(compact, r)
		}
	}

	summary, _ := o.store.GetSummary()
	return compact, summary
}

func (o *Orchestrator) triageOne(ctx context.Context, investigationID int64, raw string) domain.Artifact {
	normVal, artType := DetectIndicatorType(raw)

	if cached, err := o.store.FindRecentByValue(normVal, o.cacheTTL); err == nil && cached != nil {
		copyRec := *cached
		copyRec.ID = 0
		copyRec.InvestigationID = investigationID
		copyRec.RawValue = raw
		_ = o.store.Save(&copyRec)
		return copyRec
	}

	var enrichments []domain.EnrichmentResult
	var mu sync.Mutex
	var pwg sync.WaitGroup

	for _, p := range o.providers {
		if !p.Supports(artType) {
			continue
		}
		pwg.Add(1)
		go func(prov providers.Provider) {
			defer pwg.Done()
			res, err := prov.Enrich(ctx, normVal, artType)
			if err != nil {
				return
			}
			mu.Lock()
			enrichments = append(enrichments, res)
			mu.Unlock()
		}(p)
	}
	pwg.Wait()

	sort.Slice(enrichments, func(i, j int) bool {
		return enrichments[i].Provider < enrichments[j].Provider
	})

	maxScore := 0
	anyMal := false
	for _, e := range enrichments {
		if e.Score > maxScore {
			maxScore = e.Score
		}
		if e.Malicious {
			anyMal = true
		}
	}

	verdict := "unknown"
	if len(enrichments) > 0 {
		switch {
		case anyMal || maxScore >= 70:
			verdict = "malicious"
		case maxScore >= 35:
			verdict = "suspicious"
		default:
			verdict = "clean"
		}
	}

	rec := domain.Artifact{
		InvestigationID: investigationID,
		Value:           normVal,
		RawValue:        raw,
		Type:            artType,
		Verdict:         verdict,
		RiskScore:       maxScore,
		Enrichments:     enrichments,
	}
	_ = o.store.Save(&rec)
	return rec
}
