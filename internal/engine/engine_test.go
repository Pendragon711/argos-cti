package engine

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"argos/internal/domain"
	"argos/internal/providers"
	"argos/internal/storage"
)

type fakeProvider struct {
	name  string
	score int
	mal   bool
}

func (f fakeProvider) Name() string                        { return f.name }
func (f fakeProvider) Supports(t domain.ArtifactType) bool { return true }
func (f fakeProvider) Enrich(_ context.Context, _ string, _ domain.ArtifactType) (domain.EnrichmentResult, error) {
	return domain.EnrichmentResult{
		Provider:  f.name,
		Malicious: f.mal,
		Score:     f.score,
		Tags:      []string{"test"},
	}, nil
}

func TestClassifyAndExtractArtifacts(t *testing.T) {
	val, typ := DetectIndicatorType("hxxps://c2-painel.exemplo[.]org/stage1.bin")
	if typ != domain.TypeURL || val != "https://c2-painel.exemplo.org/stage1.bin" {
		t.Fatalf("esperava URL limpa, veio %s (%s)", val, typ)
	}

	_, typIP := DetectIndicatorType("198.51.100.77")
	if typIP != domain.TypeIP {
		t.Fatalf("esperava IP, veio %s", typIP)
	}

	_, typDom := DetectIndicatorType("evil[.]example[.]com")
	if typDom != domain.TypeDomain {
		t.Fatalf("esperava domain, veio %s", typDom)
	}

	_, typEmail := DetectIndicatorType("ops[@]evil[.]example[.]com")
	if typEmail != domain.TypeEmail {
		t.Fatalf("esperava email, veio %s", typEmail)
	}

	_, typHash := DetectIndicatorType("d41d8cd98f00b204e9800998ecf8427e")
	if typHash != domain.TypeHash {
		t.Fatalf("esperava hash, veio %s", typHash)
	}

	extracted := ExtractArtifactsFromText("Alerta em 198.51.100.77 e hxxps://bad[.]example[.]org/dropper")
	if len(extracted) != 2 {
		t.Fatalf("esperava 2 artefatos extraídos, veio %+v", extracted)
	}
}

func TestInvestigationEvidenceGraphAssessmentAndExport(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "argos_full.db")
	store, err := storage.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	inv := &domain.Investigation{
		Title:       "Campanha Phishing Infra",
		Objective:   "Mapear domínio, IP e evidências",
		Scope:       "Infraestrutura externa",
		Limitations: "Sem acesso a logs internos completos",
	}
	if err := store.CreateInvestigation(inv); err != nil {
		t.Fatal(err)
	}

	orch := NewOrchestrator(store, []providers.Provider{
		fakeProvider{name: "fake", score: 85, mal: true},
	}, 2)

	res, summary := orch.TriageInvestigation(context.Background(), inv.ID, []string{"198.51.100.77", "c2.exemplo.org"})
	if len(res) != 2 || summary.MaliciousCount < 1 {
		t.Fatalf("triagem inesperada: len=%d summary=%+v", len(res), summary)
	}

	ev := &domain.Evidence{
		InvestigationID: inv.ID,
		ArtifactID:      res[0].ID,
		Source:          "telemetry-filter",
		Content:         "Conexão repetida em rota não mapeada",
		Certainty:       domain.CertaintyObserved,
	}
	if err := store.AddEvidence(ev); err != nil || ev.ContentSHA256 == "" {
		t.Fatalf("falha ao registrar evidência com SHA-256: %v", err)
	}

	rel := &domain.Relation{
		InvestigationID: inv.ID,
		SourceID:        res[1].ID,
		TargetID:        res[0].ID,
		Type:            domain.RelResolvesTo,
		Certainty:       "observed",
	}
	if err := store.AddRelation(rel); err != nil {
		t.Fatal(err)
	}

	nodes, err := store.PivotGraph(res[1].ID, 2)
	if err != nil || len(nodes) != 2 {
		t.Fatalf("pivot inválido: nodes=%+v err=%v", nodes, err)
	}

	arts, _ := store.ListByInvestigation(inv.ID)
	evs, _ := store.ListEvidences(inv.ID)
	rels, _ := store.ListRelations(inv.ID)

	assess := BuildAssessment(*inv, arts, evs, rels)
	if assess.ExposureRisk != "high" {
		t.Fatalf("esperava exposure_risk=high, veio %s", assess.ExposureRisk)
	}

	md := RenderMarkdownReport(*inv, assess, arts, evs, rels)
	if !strings.Contains(md, "Campanha Phishing Infra") {
		t.Fatalf("relatório markdown incompleto")
	}

	stixBytes, err := ExportSTIX21Bundle(*inv, arts)
	if err != nil || !strings.Contains(string(stixBytes), `"type": "bundle"`) {
		t.Fatalf("exportação STIX 2.1 falhou: %v", err)
	}

	csvBytes, err := ExportCSV(arts)
	if err != nil || !strings.Contains(string(csvBytes), "198.51.100.77") {
		t.Fatalf("exportação CSV falhou: %v", err)
	}
}
