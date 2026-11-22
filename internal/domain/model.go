package domain

import "time"

type ArtifactType string

const (
	TypeIP     ArtifactType = "ip"
	TypeDomain ArtifactType = "domain"
	TypeURL    ArtifactType = "url"
	TypeHash   ArtifactType = "hash"
	TypeEmail  ArtifactType = "email"
)

type CertaintyLevel string

const (
	CertaintyObserved   CertaintyLevel = "observed"
	CertaintyReported   CertaintyLevel = "reported"
	CertaintyInferred   CertaintyLevel = "inferred"
	CertaintyUnverified CertaintyLevel = "unverified"
)

type RelationType string

const (
	RelResolvesTo     RelationType = "resolves_to"
	RelHostedOn       RelationType = "hosted_on"
	RelPartOf         RelationType = "part_of"
	RelContains       RelationType = "contains"
	RelAssociatedWith RelationType = "associated_with"
)

type Investigation struct {
	ID          int64     `json:"id"`
	Title       string    `json:"title"`
	Objective   string    `json:"objective"`
	Scope       string    `json:"scope"`
	Status      string    `json:"status"`
	Notes       string    `json:"notes"`
	Limitations string    `json:"limitations"`
	Conclusion  string    `json:"conclusion"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type EnrichmentResult struct {
	Provider  string         `json:"provider"`
	Malicious bool           `json:"malicious"`
	Score     int            `json:"score"`
	Tags      []string       `json:"tags,omitempty"`
	Summary   string         `json:"summary,omitempty"`
	Raw       map[string]any `json:"raw,omitempty"`
}

type Artifact struct {
	ID              int64              `json:"id"`
	InvestigationID int64              `json:"investigation_id"`
	Value           string             `json:"value"`
	RawValue        string             `json:"raw_value"`
	Type            ArtifactType       `json:"type"`
	Verdict         string             `json:"verdict"`
	RiskScore       int                `json:"risk_score"`
	Enrichments     []EnrichmentResult `json:"enrichments,omitempty"`
	CreatedAt       time.Time          `json:"created_at"`
}

type Evidence struct {
	ID              int64          `json:"id"`
	InvestigationID int64          `json:"investigation_id"`
	ArtifactID      int64          `json:"artifact_id,omitempty"`
	Source          string         `json:"source"`
	Content         string         `json:"content"`
	ContentSHA256   string         `json:"content_sha256"`
	Certainty       CertaintyLevel `json:"certainty"`
	CreatedAt       time.Time      `json:"created_at"`
}

type Relation struct {
	ID              int64        `json:"id"`
	InvestigationID int64        `json:"investigation_id"`
	SourceID        int64        `json:"source_id"`
	TargetID        int64        `json:"target_id"`
	Type            RelationType `json:"type"`
	Certainty       string       `json:"certainty"`
	CreatedAt       time.Time    `json:"created_at"`
}

type PivotNode struct {
	ArtifactID int64        `json:"artifact_id"`
	Value      string       `json:"value"`
	Type       ArtifactType `json:"type"`
	Verdict    string       `json:"verdict"`
	Depth      int          `json:"depth"`
	ViaRel     string       `json:"via_relation,omitempty"`
}

type Assessment struct {
	InvestigationID int64    `json:"investigation_id"`
	ExposureRisk    string   `json:"exposure_risk"`
	ConfidenceLevel string   `json:"confidence_level"`
	OperationalImp  string   `json:"operational_impact"`
	EvidenceGaps    []string `json:"evidence_gaps"`
	AnalyticalNotes string   `json:"analytical_notes"`
}

type PivotSummary struct {
	TotalIndicators int            `json:"total_indicators"`
	MaliciousCount  int            `json:"malicious_count"`
	SuspiciousCount int            `json:"suspicious_count"`
	CleanCount      int            `json:"clean_count"`
	ByType          map[string]int `json:"by_type"`
}
