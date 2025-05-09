package models

import (
	"time"

	"github.com/jmoiron/sqlx/types"
)

type IPAddress struct {
	ID                       string     `db:"id" json:"id"`
	Type                     string     `db:"type" json:"type"`
	LastAnalysisDate         *time.Time `db:"last_analysis_date" json:"last_analysis_date,omitempty"`
	ASN                      *int       `db:"asn" json:"asn,omitempty"`
	Reputation               *int       `db:"reputation" json:"reputation,omitempty"`
	Country                  *string    `db:"country" json:"country,omitempty"`
	ASOwner                  *string    `db:"as_owner" json:"as_owner,omitempty"`
	RegionalInternetRegistry *string    `db:"regional_internet_registry" json:"regional_internet_registry,omitempty"`
	Network                  *string    `db:"network" json:"network,omitempty"`
	WhoisDate                *time.Time `db:"whois_date" json:"whois_date,omitempty"`
	LastModificationDate     *time.Time `db:"last_modification_date" json:"last_modification_date,omitempty"`
	Continent                *string    `db:"continent" json:"continent,omitempty"`
	HarmlessCount            *int       `db:"harmless_count" json:"harmless_count,omitempty"`
	MaliciousCount           *int       `db:"malicious_count" json:"malicious_count,omitempty"`
	SuspiciousCount          *int       `db:"suspicious_count" json:"suspicious_count,omitempty"`
	UndetectedCount          *int       `db:"undetected_count" json:"undetected_count,omitempty"`
	TimeoutCount             *int       `db:"timeout_count" json:"timeout_count,omitempty"`
	CreatedAt                time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt                time.Time  `db:"updated_at" json:"updated_at"`
}

type IPTag struct {
	ID   int    `db:"id" json:"id"`
	IPID string `db:"ip_id" json:"ip_id"`
	Tag  string `db:"tag" json:"tag"`
}

type IPAnalysisResult struct {
	ID         int    `db:"id" json:"id"`
	IPID       string `db:"ip_id" json:"ip_id"`
	EngineName string `db:"engine_name" json:"engine_name"`
	Category   string `db:"category" json:"category"`
	Result     string `db:"result" json:"result"`
	Method     string `db:"method" json:"method"`
}

type IPDetails struct {
	ID         int            `db:"id" json:"id"`
	IPID       string         `db:"ip_id" json:"ip_id"`
	Whois      string         `db:"whois" json:"whois"`
	TotalVotes types.JSONText `db:"total_votes" json:"total_votes"`
}

// VirusTotalIPResponse represents the response structure from VirusTotal API for IP addresses
type VirusTotalIPResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisDate         int64          `json:"last_analysis_date"`
			ASN                      int            `json:"asn"`
			Reputation               int            `json:"reputation"`
			Country                  string         `json:"country"`
			ASOwner                  string         `json:"as_owner"`
			RegionalInternetRegistry string         `json:"regional_internet_registry"`
			Network                  string         `json:"network"`
			WhoisDate                int64          `json:"whois_date"`
			LastModificationDate     int64          `json:"last_modification_date"`
			Continent                string         `json:"continent"`
			Tags                     []string       `json:"tags"`
			LastAnalysisStats        map[string]int `json:"last_analysis_stats"`
			LastAnalysisResults      map[string]struct {
				Category string `json:"category"`
				Result   string `json:"result"`
				Method   string `json:"method"`
			} `json:"last_analysis_results"`
			Whois      string `json:"whois"`
			TotalVotes any    `json:"total_votes"`
		} `json:"attributes"`
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
}
