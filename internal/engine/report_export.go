package engine

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"argos/internal/domain"
)

func BuildAssessment(inv domain.Investigation, artifacts []domain.Artifact, evidences []domain.Evidence, relations []domain.Relation) domain.Assessment {
	var malCount, susCount, maxScore int
	for _, a := range artifacts {
		if a.RiskScore > maxScore {
			maxScore = a.RiskScore
		}
		switch a.Verdict {
		case "malicious":
			malCount++
		case "suspicious":
			susCount++
		}
	}

	exposure := "low"
	if malCount > 0 || maxScore >= 75 {
		exposure = "high"
	} else if susCount > 0 || maxScore >= 40 {
		exposure = "medium"
	}

	var observedCount, unverifiedCount int
	for _, ev := range evidences {
		switch ev.Certainty {
		case domain.CertaintyObserved, domain.CertaintyReported:
			observedCount++
		case domain.CertaintyUnverified, domain.CertaintyInferred:
			unverifiedCount++
		}
	}

	confidence := "low"
	if observedCount >= 2 && len(artifacts) > 0 {
		confidence = "high"
	} else if observedCount >= 1 || len(artifacts) > 0 {
		confidence = "moderate"
	}

	impact := "baixo — sem indicadores maliciosos confirmados no escopo atual"
	if exposure == "high" {
		impact = fmt.Sprintf("alto — %d artefato(s) malicioso(s) identificado(s) (score máximo %d)", malCount, maxScore)
	} else if exposure == "medium" {
		impact = fmt.Sprintf("moderado — %d artefato(s) suspeito(s) em análise", susCount)
	}

	var gaps []string
	if len(evidences) == 0 {
		gaps = append(gaps, "Nenhuma evidência registrada com hash SHA-256 para a investigação.")
	}
	if unverifiedCount > 0 {
		gaps = append(gaps, fmt.Sprintf("%d evidência(s) ainda em nível inferred/unverified.", unverifiedCount))
	}
	if len(relations) == 0 && len(artifacts) > 1 {
		gaps = append(gaps, "Artefatos sem relações direcionadas mapeadas entre si.")
	}
	if strings.TrimSpace(inv.Limitations) != "" {
		gaps = append(gaps, "Limitação documentada: "+strings.TrimSpace(inv.Limitations))
	}

	notes := fmt.Sprintf(
		"Caso #%d (%s): %d artefato(s), %d evidência(s) e %d relação(ões). Exposição=%s, Confiança=%s.",
		inv.ID, inv.Title, len(artifacts), len(evidences), len(relations), exposure, confidence,
	)

	return domain.Assessment{
		InvestigationID: inv.ID,
		ExposureRisk:    exposure,
		ConfidenceLevel: confidence,
		OperationalImp:  impact,
		EvidenceGaps:    gaps,
		AnalyticalNotes: notes,
	}
}

func RenderMarkdownReport(inv domain.Investigation, assess domain.Assessment, artifacts []domain.Artifact, evidences []domain.Evidence, relations []domain.Relation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Relatório de Investigação CTI — #%d: %s\n\n", inv.ID, inv.Title)
	fmt.Fprintf(&b, "- **Status:** %s\n", inv.Status)
	fmt.Fprintf(&b, "- **Objetivo:** %s\n", inv.Objective)
	fmt.Fprintf(&b, "- **Escopo:** %s\n\n", inv.Scope)

	fmt.Fprintf(&b, "## Avaliação Analítica\n")
	fmt.Fprintf(&b, "- **Exposição:** %s\n", assess.ExposureRisk)
	fmt.Fprintf(&b, "- **Confiança:** %s\n", assess.ConfidenceLevel)
	fmt.Fprintf(&b, "- **Impacto Operacional:** %s\n", assess.OperationalImp)
	fmt.Fprintf(&b, "- **Resumo:** %s\n\n", assess.AnalyticalNotes)

	if len(assess.EvidenceGaps) > 0 {
		fmt.Fprintf(&b, "### Lacunas e Limitações\n")
		for _, g := range assess.EvidenceGaps {
			fmt.Fprintf(&b, "- %s\n", g)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Artefatos (%d)\n", len(artifacts))
	for _, a := range artifacts {
		fmt.Fprintf(&b, "- `%s` (%s) — veredito: **%s**, score: %d\n", a.Value, a.Type, a.Verdict, a.RiskScore)
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "## Evidências (%d)\n", len(evidences))
	for _, ev := range evidences {
		fmt.Fprintf(&b, "- [%s] **%s** (`sha256:%s`): %s\n", ev.Certainty, ev.Source, ev.ContentSHA256[:12], ev.Content)
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "## Relações (%d)\n", len(relations))
	for _, r := range relations {
		fmt.Fprintf(&b, "- Artefato #%d --[%s (%s)]--> Artefato #%d\n", r.SourceID, r.Type, r.Certainty, r.TargetID)
	}
	b.WriteString("\n")

	if strings.TrimSpace(inv.Notes) != "" {
		fmt.Fprintf(&b, "## Notas da Investigação\n%s\n\n", inv.Notes)
	}
	if strings.TrimSpace(inv.Conclusion) != "" {
		fmt.Fprintf(&b, "## Conclusão Analítica\n%s\n", inv.Conclusion)
	}
	return b.String()
}

func ExportCSV(artifacts []domain.Artifact) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"id", "investigation_id", "value", "type", "verdict", "risk_score", "created_at"})
	for _, a := range artifacts {
		_ = w.Write([]string{
			fmt.Sprintf("%d", a.ID),
			fmt.Sprintf("%d", a.InvestigationID),
			a.Value,
			string(a.Type),
			a.Verdict,
			fmt.Sprintf("%d", a.RiskScore),
			a.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func ExportSTIX21Bundle(inv domain.Investigation, artifacts []domain.Artifact) ([]byte, error) {
	type stixObj map[string]any
	objects := []stixObj{
		{
			"type":        "report",
			"spec_version": "2.1",
			"id":          fmt.Sprintf("report--%08d-0000-4000-8000-000000000001", inv.ID),
			"created":     time.Now().UTC().Format(time.RFC3339),
			"modified":    time.Now().UTC().Format(time.RFC3339),
			"name":        inv.Title,
			"description": inv.Objective,
			"published":   time.Now().UTC().Format(time.RFC3339),
		},
	}

	for _, a := range artifacts {
		pattern := fmt.Sprintf("[ipv4-addr:value = '%s']", a.Value)
		switch a.Type {
		case domain.TypeDomain:
			pattern = fmt.Sprintf("[domain-name:value = '%s']", a.Value)
		case domain.TypeURL:
			pattern = fmt.Sprintf("[url:value = '%s']", a.Value)
		case domain.TypeHash:
			pattern = fmt.Sprintf("[file:hashes.SHA256 = '%s']", a.Value)
		case domain.TypeEmail:
			pattern = fmt.Sprintf("[email-addr:value = '%s']", a.Value)
		}

		objects = append(objects, stixObj{
			"type":         "indicator",
			"spec_version": "2.1",
			"id":           fmt.Sprintf("indicator--%08d-0000-4000-8000-000000000000", a.ID),
			"created":      a.CreatedAt.UTC().Format(time.RFC3339),
			"modified":     a.CreatedAt.UTC().Format(time.RFC3339),
			"name":         a.Value,
			"pattern":      pattern,
			"pattern_type": "stix",
			"valid_from":   a.CreatedAt.UTC().Format(time.RFC3339),
		})
	}

	bundle := map[string]any{
		"type":    "bundle",
		"id":      fmt.Sprintf("bundle--%08d-0000-4000-8000-999999999999", inv.ID),
		"objects": objects,
	}
	return json.MarshalIndent(bundle, "", "  ")
}
