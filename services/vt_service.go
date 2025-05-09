package services

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"vt-data-pipeline/config"
	"vt-data-pipeline/models"
	"vt-data-pipeline/repositories"

	"github.com/jmoiron/sqlx"
)

type VTService struct {
	cfg        *config.Config
	db         *sqlx.DB
	domainRepo *repositories.DomainRepository
}

func NewVTService(cfg *config.Config, db *sqlx.DB) *VTService {
	return &VTService{
		cfg:        cfg,
		db:         db,
		domainRepo: repositories.NewDomainRepository(db),
	}
}

func (s *VTService) FetchVTReport(id, reportType string) (*models.Domain, error) {
	log.Printf("Starting FetchVTReport for ID: %s, Type: %s", id, reportType)

	// Check cache first
	cache, err := s.domainRepo.GetFromCache(id)
	if err == nil {
		log.Printf("Cache hit for ID: %s", id)
		var domain models.Domain
		if err := json.Unmarshal(cache.Data, &domain); err != nil {
			log.Printf("Error unmarshaling cached data for ID %s: %v", id, err)
			return nil, err
		}
		return &domain, nil
	}
	log.Printf("Cache miss for ID: %s, proceeding with API call", id)

	// Fetch from VirusTotal API
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/%s/%s", reportType, id)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("x-apikey", s.cfg.VirusTotal.APIKey)

	client := &http.Client{}
	log.Printf("Making API request to VirusTotal for ID: %s", id)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error making API request for ID %s: %v", id, err)
		return nil, err
	}
	defer resp.Body.Close()

	// Parse API response
	var vtResponse models.VirusTotalResponse
	err = json.NewDecoder(resp.Body).Decode(&vtResponse)
	if err != nil {
		log.Printf("Error decoding API response for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully decoded API response for ID: %s", id)

	// Begin transaction
	tx, err := s.db.Beginx()
	if err != nil {
		log.Printf("Error beginning transaction for ID %s: %v", id, err)
		return nil, err
	}
	defer tx.Rollback()

	// Convert timestamps
	var creationDate, expirationDate, lastAnalysisDate, whoisDate *time.Time
	if vtResponse.Data.Attributes.CreationDate != 0 {
		t := time.Unix(vtResponse.Data.Attributes.CreationDate, 0)
		creationDate = &t
	}
	if vtResponse.Data.Attributes.ExpirationDate != 0 {
		t := time.Unix(vtResponse.Data.Attributes.ExpirationDate, 0)
		expirationDate = &t
	}
	if vtResponse.Data.Attributes.LastAnalysisDate != 0 {
		t := time.Unix(vtResponse.Data.Attributes.LastAnalysisDate, 0)
		lastAnalysisDate = &t
	}
	if vtResponse.Data.Attributes.WhoisDate != 0 {
		t := time.Unix(vtResponse.Data.Attributes.WhoisDate, 0)
		whoisDate = &t
	}

	// Get analysis stats
	harmless := vtResponse.Data.Attributes.LastAnalysisStats["harmless"]
	malicious := vtResponse.Data.Attributes.LastAnalysisStats["malicious"]
	suspicious := vtResponse.Data.Attributes.LastAnalysisStats["suspicious"]
	undetected := vtResponse.Data.Attributes.LastAnalysisStats["undetected"]
	timeout := vtResponse.Data.Attributes.LastAnalysisStats["timeout"]

	// Create domain object
	domain := &models.Domain{
		ID:               id,
		Type:             reportType,
		CreationDate:     creationDate,
		ExpirationDate:   expirationDate,
		LastAnalysisDate: lastAnalysisDate,
		Reputation:       &vtResponse.Data.Attributes.Reputation,
		Registrar:        &vtResponse.Data.Attributes.Registrar,
		TLD:              &vtResponse.Data.Attributes.TLD,
		WhoisDate:        whoisDate,
		HarmlessCount:    &harmless,
		MaliciousCount:   &malicious,
		SuspiciousCount:  &suspicious,
		UndetectedCount:  &undetected,
		TimeoutCount:     &timeout,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Save domain data
	if err := s.domainRepo.SaveDomain(domain); err != nil {
		log.Printf("Error saving domain data for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully saved domain data for ID: %s", id)

	// Save categories
	if err := s.domainRepo.SaveCategories(id, vtResponse.Data.Attributes.Categories); err != nil {
		log.Printf("Error saving categories for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully saved categories for ID: %s", id)

	// Save analysis results
	if err := s.domainRepo.SaveAnalysisResults(id, vtResponse.Data.Attributes.LastAnalysisResults); err != nil {
		log.Printf("Error saving analysis results for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully saved analysis results for ID: %s", id)

	// Save details
	dnsRecordsJSON, _ := json.Marshal(vtResponse.Data.Attributes.LastDNSRecords)
	certificateJSON, _ := json.Marshal(vtResponse.Data.Attributes.LastHTTPSCertificate)
	rdapJSON, _ := json.Marshal(vtResponse.Data.Attributes.RDAP)
	popularityJSON, _ := json.Marshal(vtResponse.Data.Attributes.PopularityRanks)
	votesJSON, _ := json.Marshal(vtResponse.Data.Attributes.TotalVotes)

	details := &models.DomainDetails{
		DomainID:             id,
		LastDNSRecords:       dnsRecordsJSON,
		LastHTTPSCertificate: certificateJSON,
		RDAP:                 rdapJSON,
		Whois:                vtResponse.Data.Attributes.Whois,
		PopularityRanks:      popularityJSON,
		TotalVotes:           votesJSON,
	}

	if err := s.domainRepo.SaveDetails(details); err != nil {
		log.Printf("Error saving domain details for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully saved domain details for ID: %s", id)

	// Save to cache
	if err := s.domainRepo.SaveCache(id, domain, 1*time.Hour); err != nil {
		log.Printf("Error saving to cache for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully saved to cache for ID: %s", id)

	// Commit transaction
	if err := tx.Commit(); err != nil {
		log.Printf("Error committing transaction for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully committed transaction for ID: %s", id)

	return domain, nil
}
