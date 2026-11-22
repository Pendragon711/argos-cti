package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"

	"argos/internal/domain"
	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	schema := `
	CREATE TABLE IF NOT EXISTS investigations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		objective TEXT NOT NULL DEFAULT '',
		scope TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'open',
		notes TEXT NOT NULL DEFAULT '',
		limitations TEXT NOT NULL DEFAULT '',
		conclusion TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS indicators (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		investigation_id INTEGER NOT NULL DEFAULT 1,
		value TEXT NOT NULL,
		raw_value TEXT NOT NULL DEFAULT '',
		type TEXT NOT NULL,
		verdict TEXT NOT NULL,
		risk_score INTEGER NOT NULL,
		enrichments_json TEXT NOT NULL,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS evidences (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		investigation_id INTEGER NOT NULL,
		artifact_id INTEGER NOT NULL DEFAULT 0,
		source TEXT NOT NULL,
		content TEXT NOT NULL,
		content_sha256 TEXT NOT NULL,
		certainty TEXT NOT NULL,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS relations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		investigation_id INTEGER NOT NULL,
		source_id INTEGER NOT NULL,
		target_id INTEGER NOT NULL,
		type TEXT NOT NULL,
		certainty TEXT NOT NULL DEFAULT 'observed',
		created_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value);
	CREATE INDEX IF NOT EXISTS idx_indicators_verdict ON indicators(verdict);
	CREATE INDEX IF NOT EXISTS idx_evidences_inv ON evidences(investigation_id);
	CREATE INDEX IF NOT EXISTS idx_relations_inv ON relations(investigation_id);
	CREATE INDEX IF NOT EXISTS idx_relations_src ON relations(source_id);
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	var cnt int
	_ = db.QueryRow(`SELECT COUNT(*) FROM investigations`).Scan(&cnt)
	if cnt == 0 {
		now := time.Now().UTC()
		_, _ = db.Exec(
			`INSERT INTO investigations (title, objective, scope, status, notes, limitations, conclusion, created_at, updated_at)
			 VALUES (?, ?, ?, 'open', '', '', '', ?, ?)`,
			"Investigação Padrão", "Triagem e correlação de artefatos CTI", "Escopo local inicial", now, now,
		)
	}

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) CreateInvestigation(inv *domain.Investigation) error {
	now := time.Now().UTC()
	if inv.Status == "" {
		inv.Status = "open"
	}
	inv.CreatedAt = now
	inv.UpdatedAt = now

	res, err := s.db.Exec(
		`INSERT INTO investigations (title, objective, scope, status, notes, limitations, conclusion, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		inv.Title, inv.Objective, inv.Scope, inv.Status, inv.Notes, inv.Limitations, inv.Conclusion, inv.CreatedAt, inv.UpdatedAt,
	)
	if err != nil {
		return err
	}
	inv.ID, _ = res.LastInsertId()
	return nil
}

func (s *SQLiteStore) UpdateInvestigation(inv *domain.Investigation) error {
	inv.UpdatedAt = time.Now().UTC()
	_, err := s.db.Exec(
		`UPDATE investigations
		 SET title = ?, objective = ?, scope = ?, status = ?, notes = ?, limitations = ?, conclusion = ?, updated_at = ?
		 WHERE id = ?`,
		inv.Title, inv.Objective, inv.Scope, inv.Status, inv.Notes, inv.Limitations, inv.Conclusion, inv.UpdatedAt, inv.ID,
	)
	return err
}

func (s *SQLiteStore) GetInvestigation(id int64) (*domain.Investigation, error) {
	row := s.db.QueryRow(
		`SELECT id, title, objective, scope, status, notes, limitations, conclusion, created_at, updated_at
		 FROM investigations WHERE id = ?`, id,
	)
	var inv domain.Investigation
	if err := row.Scan(&inv.ID, &inv.Title, &inv.Objective, &inv.Scope, &inv.Status, &inv.Notes, &inv.Limitations, &inv.Conclusion, &inv.CreatedAt, &inv.UpdatedAt); err != nil {
		return nil, err
	}
	return &inv, nil
}

func (s *SQLiteStore) ListInvestigations() ([]domain.Investigation, error) {
	rows, err := s.db.Query(
		`SELECT id, title, objective, scope, status, notes, limitations, conclusion, created_at, updated_at
		 FROM investigations ORDER BY id DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []domain.Investigation
	for rows.Next() {
		var inv domain.Investigation
		if err := rows.Scan(&inv.ID, &inv.Title, &inv.Objective, &inv.Scope, &inv.Status, &inv.Notes, &inv.Limitations, &inv.Conclusion, &inv.CreatedAt, &inv.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, inv)
	}
	return list, nil
}

func (s *SQLiteStore) FindRecentByValue(value string, maxAge time.Duration) (*domain.Artifact, error) {
	cutoff := time.Now().UTC().Add(-maxAge)
	row := s.db.QueryRow(
		`SELECT id, investigation_id, value, raw_value, type, verdict, risk_score, enrichments_json, created_at
		 FROM indicators WHERE value = ? AND created_at >= ?
		 ORDER BY id DESC LIMIT 1`, value, cutoff,
	)

	var r domain.Artifact
	var rawJSON string
	if err := row.Scan(&r.ID, &r.InvestigationID, &r.Value, &r.RawValue, &r.Type, &r.Verdict, &r.RiskScore, &rawJSON, &r.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(rawJSON), &r.Enrichments)
	return &r, nil
}

func (s *SQLiteStore) Save(rec *domain.Artifact) error {
	if rec.InvestigationID == 0 {
		rec.InvestigationID = 1
	}
	if rec.RawValue == "" {
		rec.RawValue = rec.Value
	}
	data, err := json.Marshal(rec.Enrichments)
	if err != nil {
		return err
	}
	rec.CreatedAt = time.Now().UTC()

	res, err := s.db.Exec(
		`INSERT INTO indicators (investigation_id, value, raw_value, type, verdict, risk_score, enrichments_json, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.InvestigationID, rec.Value, rec.RawValue, rec.Type, rec.Verdict, rec.RiskScore, string(data), rec.CreatedAt,
	)
	if err != nil {
		return err
	}
	rec.ID, _ = res.LastInsertId()
	return nil
}

func (s *SQLiteStore) ListRecent(limit int) ([]domain.Artifact, error) {
	rows, err := s.db.Query(
		`SELECT id, investigation_id, value, raw_value, type, verdict, risk_score, enrichments_json, created_at
		 FROM indicators ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []domain.Artifact
	for rows.Next() {
		var r domain.Artifact
		var rawJSON string
		if err := rows.Scan(&r.ID, &r.InvestigationID, &r.Value, &r.RawValue, &r.Type, &r.Verdict, &r.RiskScore, &rawJSON, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(rawJSON), &r.Enrichments)
		list = append(list, r)
	}
	return list, nil
}

func (s *SQLiteStore) ListByInvestigation(invID int64) ([]domain.Artifact, error) {
	rows, err := s.db.Query(
		`SELECT id, investigation_id, value, raw_value, type, verdict, risk_score, enrichments_json, created_at
		 FROM indicators WHERE investigation_id = ? ORDER BY id DESC`, invID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []domain.Artifact
	for rows.Next() {
		var r domain.Artifact
		var rawJSON string
		if err := rows.Scan(&r.ID, &r.InvestigationID, &r.Value, &r.RawValue, &r.Type, &r.Verdict, &r.RiskScore, &rawJSON, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(rawJSON), &r.Enrichments)
		list = append(list, r)
	}
	return list, nil
}

func (s *SQLiteStore) AddEvidence(ev *domain.Evidence) error {
	if ev.InvestigationID == 0 {
		ev.InvestigationID = 1
	}
	if ev.Certainty == "" {
		ev.Certainty = domain.CertaintyUnverified
	}
	sum := sha256.Sum256([]byte(ev.Content))
	ev.ContentSHA256 = hex.EncodeToString(sum[:])
	ev.CreatedAt = time.Now().UTC()

	res, err := s.db.Exec(
		`INSERT INTO evidences (investigation_id, artifact_id, source, content, content_sha256, certainty, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ev.InvestigationID, ev.ArtifactID, ev.Source, ev.Content, ev.ContentSHA256, ev.Certainty, ev.CreatedAt,
	)
	if err != nil {
		return err
	}
	ev.ID, _ = res.LastInsertId()
	return nil
}

func (s *SQLiteStore) ListEvidences(invID int64) ([]domain.Evidence, error) {
	rows, err := s.db.Query(
		`SELECT id, investigation_id, artifact_id, source, content, content_sha256, certainty, created_at
		 FROM evidences WHERE investigation_id = ? ORDER BY id DESC`, invID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []domain.Evidence
	for rows.Next() {
		var ev domain.Evidence
		if err := rows.Scan(&ev.ID, &ev.InvestigationID, &ev.ArtifactID, &ev.Source, &ev.Content, &ev.ContentSHA256, &ev.Certainty, &ev.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, ev)
	}
	return list, nil
}

func (s *SQLiteStore) AddRelation(rel *domain.Relation) error {
	if rel.InvestigationID == 0 {
		rel.InvestigationID = 1
	}
	if rel.Certainty == "" {
		rel.Certainty = "observed"
	}
	rel.CreatedAt = time.Now().UTC()

	res, err := s.db.Exec(
		`INSERT INTO relations (investigation_id, source_id, target_id, type, certainty, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		rel.InvestigationID, rel.SourceID, rel.TargetID, rel.Type, rel.Certainty, rel.CreatedAt,
	)
	if err != nil {
		return err
	}
	rel.ID, _ = res.LastInsertId()
	return nil
}

func (s *SQLiteStore) ListRelations(invID int64) ([]domain.Relation, error) {
	rows, err := s.db.Query(
		`SELECT id, investigation_id, source_id, target_id, type, certainty, created_at
		 FROM relations WHERE investigation_id = ? ORDER BY id DESC`, invID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []domain.Relation
	for rows.Next() {
		var rel domain.Relation
		if err := rows.Scan(&rel.ID, &rel.InvestigationID, &rel.SourceID, &rel.TargetID, &rel.Type, &rel.Certainty, &rel.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, rel)
	}
	return list, nil
}

func (s *SQLiteStore) PivotGraph(seedID int64, maxDepth int) ([]domain.PivotNode, error) {
	if maxDepth < 1 {
		maxDepth = 1
	}
	if maxDepth > 5 {
		maxDepth = 5
	}

	artifacts, err := s.ListRecent(1000)
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]domain.Artifact, len(artifacts))
	for _, a := range artifacts {
		byID[a.ID] = a
	}

	rows, err := s.db.Query(`SELECT source_id, target_id, type FROM relations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type edge struct {
		nextID int64
		rel    string
	}
	adj := make(map[int64][]edge)
	for rows.Next() {
		var src, dst int64
		var rType string
		if err := rows.Scan(&src, &dst, &rType); err != nil {
			return nil, err
		}
		adj[src] = append(adj[src], edge{nextID: dst, rel: rType})
	}

	visited := map[int64]bool{seedID: true}
	queue := []domain.PivotNode{}
	if seed, ok := byID[seedID]; ok {
		queue = append(queue, domain.PivotNode{
			ArtifactID: seed.ID,
			Value:      seed.Value,
			Type:       seed.Type,
			Verdict:    seed.Verdict,
			Depth:      0,
		})
	}

	var result []domain.PivotNode
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		result = append(result, curr)

		if curr.Depth >= maxDepth {
			continue
		}
		for _, e := range adj[curr.ArtifactID] {
			if visited[e.nextID] {
				continue
			}
			visited[e.nextID] = true
			if nextArt, ok := byID[e.nextID]; ok {
				queue = append(queue, domain.PivotNode{
					ArtifactID: nextArt.ID,
					Value:      nextArt.Value,
					Type:       nextArt.Type,
					Verdict:    nextArt.Verdict,
					Depth:      curr.Depth + 1,
					ViaRel:     e.rel,
				})
			}
		}
	}

	return result, nil
}

func (s *SQLiteStore) GetSummary() (domain.PivotSummary, error) {
	summary := domain.PivotSummary{
		ByType: make(map[string]int),
	}

	rows, err := s.db.Query(`SELECT type, verdict, COUNT(*) FROM indicators GROUP BY type, verdict`)
	if err != nil {
		return summary, err
	}
	defer rows.Close()

	for rows.Next() {
		var indType, verdict string
		var cnt int
		if err := rows.Scan(&indType, &verdict, &cnt); err != nil {
			return summary, err
		}
		summary.TotalIndicators += cnt
		summary.ByType[indType] += cnt
		switch verdict {
		case "malicious":
			summary.MaliciousCount += cnt
		case "suspicious":
			summary.SuspiciousCount += cnt
		case "clean":
			summary.CleanCount += cnt
		}
	}
	return summary, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
