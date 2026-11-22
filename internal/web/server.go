package web

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"argos/internal/domain"
	"argos/internal/engine"
	"argos/internal/storage"
)

//go:embed static/*
var staticFiles embed.FS

type Server struct {
	store *storage.SQLiteStore
	orch  *engine.Orchestrator
}

func NewServer(store *storage.SQLiteStore, orch *engine.Orchestrator) *Server {
	if saved, err := store.LoadSavedProviderKeys(); err == nil {
		orch.ApplyProviderKeys(saved)
	}
	return &Server{store: store, orch: orch}
}

func (s *Server) ListenAndServe(addr string) error {
	mux := http.NewServeMux()

	subFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(subFS)))

	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "argos"})
	})

	mux.HandleFunc("GET /api/providers", func(w http.ResponseWriter, r *http.Request) {
		cfgs, err := s.store.ListProviderConfigs()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfgs)
	})

	mux.HandleFunc("POST /api/providers", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Keys map[string]string `json:"keys"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		for prov, key := range req.Keys {
			if err := s.store.SaveProviderKey(prov, key); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if saved, err := s.store.LoadSavedProviderKeys(); err == nil {
			s.orch.ApplyProviderKeys(saved)
		}
		cfgs, err := s.store.ListProviderConfigs()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfgs)
	})

	mux.HandleFunc("GET /api/summary", func(w http.ResponseWriter, r *http.Request) {
		summary, err := s.store.GetSummary()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(summary)
	})

	mux.HandleFunc("GET /api/investigations", func(w http.ResponseWriter, r *http.Request) {
		items, err := s.store.ListInvestigations()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(items)
	})

	mux.HandleFunc("POST /api/investigations", func(w http.ResponseWriter, r *http.Request) {
		var inv domain.Investigation
		if err := json.NewDecoder(r.Body).Decode(&inv); err != nil || strings.TrimSpace(inv.Title) == "" {
			http.Error(w, "invalid investigation payload", http.StatusBadRequest)
			return
		}
		if err := s.store.CreateInvestigation(&inv); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(inv)
	})

	mux.HandleFunc("PUT /api/investigations/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}
		var inv domain.Investigation
		if err := json.NewDecoder(r.Body).Decode(&inv); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}
		inv.ID = id
		if err := s.store.UpdateInvestigation(&inv); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(inv)
	})

	mux.HandleFunc("GET /api/indicators", func(w http.ResponseWriter, r *http.Request) {
		items, err := s.store.ListRecent(200)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
		verdictFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("verdict")))
		invFilter, _ := strconv.ParseInt(r.URL.Query().Get("investigation_id"), 10, 64)

		filtered := make([]domain.Artifact, 0)
		for _, item := range items {
			if invFilter > 0 && item.InvestigationID != invFilter {
				continue
			}
			if verdictFilter != "" && strings.ToLower(item.Verdict) != verdictFilter {
				continue
			}
			if q != "" &&
				!strings.Contains(strings.ToLower(item.Value), q) &&
				!strings.Contains(strings.ToLower(string(item.Type)), q) &&
				!strings.Contains(strings.ToLower(item.Verdict), q) {
				continue
			}
			filtered = append(filtered, item)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(filtered)
	})

	mux.HandleFunc("POST /api/triage", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			InvestigationID int64    `json:"investigation_id"`
			Indicators      []string `json:"indicators"`
			RawText         string   `json:"raw_text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		list := append([]string{}, req.Indicators...)
		if strings.TrimSpace(req.RawText) != "" {
			list = append(list, engine.ExtractArtifactsFromText(req.RawText)...)
		}
		invID := req.InvestigationID
		if invID == 0 {
			invID = 1
		}
		results, summary := s.orch.TriageInvestigation(r.Context(), invID, list)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"summary": summary,
			"results": results,
		})
	})

	mux.HandleFunc("GET /api/evidences", func(w http.ResponseWriter, r *http.Request) {
		invID, _ := strconv.ParseInt(r.URL.Query().Get("investigation_id"), 10, 64)
		if invID == 0 {
			invID = 1
		}
		list, err := s.store.ListEvidences(invID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	})

	mux.HandleFunc("POST /api/evidences", func(w http.ResponseWriter, r *http.Request) {
		var ev domain.Evidence
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil || strings.TrimSpace(ev.Source) == "" || strings.TrimSpace(ev.Content) == "" {
			http.Error(w, "invalid evidence payload", http.StatusBadRequest)
			return
		}
		if err := s.store.AddEvidence(&ev); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(ev)
	})

	mux.HandleFunc("GET /api/relations", func(w http.ResponseWriter, r *http.Request) {
		invID, _ := strconv.ParseInt(r.URL.Query().Get("investigation_id"), 10, 64)
		if invID == 0 {
			invID = 1
		}
		list, err := s.store.ListRelations(invID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	})

	mux.HandleFunc("POST /api/relations", func(w http.ResponseWriter, r *http.Request) {
		var rel domain.Relation
		if err := json.NewDecoder(r.Body).Decode(&rel); err != nil || rel.SourceID == 0 || rel.TargetID == 0 || rel.Type == "" {
			http.Error(w, "invalid relation payload", http.StatusBadRequest)
			return
		}
		if err := s.store.AddRelation(&rel); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(rel)
	})

	mux.HandleFunc("GET /api/pivot", func(w http.ResponseWriter, r *http.Request) {
		seedID, _ := strconv.ParseInt(r.URL.Query().Get("seed_id"), 10, 64)
		maxDepth, _ := strconv.Atoi(r.URL.Query().Get("max_depth"))
		if seedID == 0 {
			http.Error(w, "seed_id required", http.StatusBadRequest)
			return
		}
		nodes, err := s.store.PivotGraph(seedID, maxDepth)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nodes)
	})

	mux.HandleFunc("GET /api/assessment", func(w http.ResponseWriter, r *http.Request) {
		invID, _ := strconv.ParseInt(r.URL.Query().Get("investigation_id"), 10, 64)
		if invID == 0 {
			invID = 1
		}
		inv, err := s.store.GetInvestigation(invID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		arts, _ := s.store.ListByInvestigation(invID)
		evs, _ := s.store.ListEvidences(invID)
		rels, _ := s.store.ListRelations(invID)
		assess := engine.BuildAssessment(*inv, arts, evs, rels)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(assess)
	})

	mux.HandleFunc("GET /api/export", func(w http.ResponseWriter, r *http.Request) {
		invID, _ := strconv.ParseInt(r.URL.Query().Get("investigation_id"), 10, 64)
		if invID == 0 {
			invID = 1
		}
		format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
		if format == "" {
			format = "json"
		}

		inv, err := s.store.GetInvestigation(invID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		arts, _ := s.store.ListByInvestigation(invID)
		evs, _ := s.store.ListEvidences(invID)
		rels, _ := s.store.ListRelations(invID)
		assess := engine.BuildAssessment(*inv, arts, evs, rels)

		switch format {
		case "csv":
			data, err := engine.ExportCSV(arts)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			_, _ = w.Write(data)
		case "md", "markdown":
			md := engine.RenderMarkdownReport(*inv, assess, arts, evs, rels)
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			_, _ = w.Write([]byte(md))
		case "stix":
			data, err := engine.ExportSTIX21Bundle(*inv, arts)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write(data)
		default:
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"investigation": inv,
				"assessment":    assess,
				"artifacts":     arts,
				"evidences":     evs,
				"relations":     rels,
			})
		}
	})

	return http.ListenAndServe(addr, mux)
}
