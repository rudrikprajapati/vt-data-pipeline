package models

import (
	"time"

	"github.com/jmoiron/sqlx/types"
)

// Domain represents the domains table
type Domain struct {
	ID               string     `db:"id" json:"id"`
	Type             string     `db:"type" json:"type"`
	CreationDate     *time.Time `db:"creation_date" json:"creation_date,omitempty"`
	ExpirationDate   *time.Time `db:"expiration_date" json:"expiration_date,omitempty"`
	LastAnalysisDate *time.Time `db:"last_analysis_date" json:"last_analysis_date,omitempty"`
	Reputation       *int       `db:"reputation" json:"reputation,omitempty"`
	Registrar        *string    `db:"registrar" json:"registrar,omitempty"`
	TLD              *string    `db:"tld" json:"tld,omitempty"`
	WhoisDate        *time.Time `db:"whois_date" json:"whois_date,omitempty"`
	HarmlessCount    *int       `db:"harmless_count" json:"harmless_count,omitempty"`
	MaliciousCount   *int       `db:"malicious_count" json:"malicious_count,omitempty"`
	SuspiciousCount  *int       `db:"suspicious_count" json:"suspicious_count,omitempty"`
	UndetectedCount  *int       `db:"undetected_count" json:"undetected_count,omitempty"`
	TimeoutCount     *int       `db:"timeout_count" json:"timeout_count,omitempty"`
	CreatedAt        time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt        time.Time  `db:"updated_at" json:"updated_at"`
}

// DomainCategory represents the domain_categories table
type DomainCategory struct {
	ID         int    `db:"id" json:"id"`
	DomainID   string `db:"domain_id" json:"domain_id"`
	EngineName string `db:"engine_name" json:"engine_name"`
	Category   string `db:"category" json:"category"`
}

// DomainAnalysisResult represents the domain_analysis_results table
type DomainAnalysisResult struct {
	ID         int    `db:"id" json:"id"`
	DomainID   string `db:"domain_id" json:"domain_id"`
	EngineName string `db:"engine_name" json:"engine_name"`
	Category   string `db:"category" json:"category"`
	Result     string `db:"result" json:"result"`
	Method     string `db:"method" json:"method"`
}

// DomainDetails represents the domain_details table
type DomainDetails struct {
	ID                   int            `db:"id" json:"id"`
	DomainID             string         `db:"domain_id" json:"domain_id"`
	LastDNSRecords       types.JSONText `db:"last_dns_records" json:"last_dns_records"`
	LastHTTPSCertificate types.JSONText `db:"last_https_certificate" json:"last_https_certificate"`
	RDAP                 types.JSONText `db:"rdap" json:"rdap"`
	Whois                string         `db:"whois" json:"whois"`
	PopularityRanks      types.JSONText `db:"popularity_ranks" json:"popularity_ranks"`
	TotalVotes           types.JSONText `db:"total_votes" json:"total_votes"`
}

// CacheEntry represents the domain_cache table
type CacheEntry struct {
	ID        string         `db:"id" json:"id"`
	Data      types.JSONText `db:"data" json:"data"`
	CachedAt  time.Time      `db:"cached_at" json:"cached_at"`
	ExpiresAt time.Time      `db:"expires_at" json:"expires_at"`
}

// VirusTotalResponse represents the response from VirusTotal API
type VirusTotalResponse struct {
	Data struct {
		Attributes struct {
			CreationDate        int64             `json:"creation_date"`
			ExpirationDate      int64             `json:"expiration_date"`
			LastAnalysisDate    int64             `json:"last_analysis_date"`
			Reputation          int               `json:"reputation"`
			Registrar           string            `json:"registrar"`
			TLD                 string            `json:"tld"`
			WhoisDate           int64             `json:"whois_date"`
			LastAnalysisStats   map[string]int    `json:"last_analysis_stats"`
			Categories          map[string]string `json:"categories"`
			LastAnalysisResults map[string]struct {
				Category string `json:"category"`
				Result   string `json:"result"`
				Method   string `json:"method"`
			} `json:"last_analysis_results"`
			LastDNSRecords       []interface{} `json:"last_dns_records"`
			LastHTTPSCertificate interface{}   `json:"last_https_certificate"`
			RDAP                 interface{}   `json:"rdap"`
			Whois                string        `json:"whois"`
			PopularityRanks      interface{}   `json:"popularity_ranks"`
			TotalVotes           interface{}   `json:"total_votes"`
		} `json:"attributes"`
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
}
