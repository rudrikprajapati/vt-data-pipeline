package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"vt-data-pipeline/config"
	"vt-data-pipeline/models"
	"vt-data-pipeline/redis"
	"vt-data-pipeline/repositories"

	"github.com/jmoiron/sqlx"
)

func FetchDomainVTReport(id, reportType string, db *sqlx.DB, redisClient *redis.Client, cfg *config.Config) (*models.Domain, error) {
	log.Printf("Starting FetchVTReport for ID: %s, Type: %s", id, reportType)

	// Check Redis cache first
	cacheKey := fmt.Sprintf("domain:%s", id)
	cachedData, err := redisClient.Get(context.Background(), cacheKey)
	if err == nil && cachedData != "" {
		log.Printf("Redis cache hit for ID: %s", id)
		var domain models.Domain
		if err := json.Unmarshal([]byte(cachedData), &domain); err != nil {
			log.Printf("Error unmarshaling cached data for ID %s: %v", id, err)
			return nil, err
		}
		return &domain, nil
	}
	log.Printf("Redis cache miss for ID: %s, proceeding with API call", id)

	// Fetch from VirusTotal API
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/%s/%s", reportType, id)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("x-apikey", cfg.VirusTotal.APIKey)

	client := &http.Client{}
	log.Printf("Making API request to VirusTotal for ID: %s", id)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error making API request for ID %s: %v", id, err)
		return nil, err
	}
	defer resp.Body.Close()

	// Parse API response
	var vtResponse models.VirusTotalDomainResponse
	err = json.NewDecoder(resp.Body).Decode(&vtResponse)
	if err != nil {
		log.Printf("Error decoding API response for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully decoded API response for ID: %s", id)

	// Begin transaction
	tx, err := db.Beginx()
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
	if err := repositories.SaveDomain(tx, domain); err != nil {
		log.Printf("Error saving domain data for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully saved domain data for ID: %s", id)

	// Save domain details
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

	if err := repositories.SaveDomainDetails(tx, details); err != nil {
		log.Printf("Error saving domain details for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully saved domain details for ID: %s", id)

	// go routine for insert categories and analysis
	errChan := make(chan error, 2)
	var wg sync.WaitGroup

	// Save categories
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := repositories.SaveDomainCategories(tx, id, vtResponse.Data.Attributes.Categories); err != nil {
			log.Printf("Error saving categories for ID %s: %v", id, err)
			errChan <- err
			return
		}
		log.Printf("Successfully saved categories for ID: %s", id)
	}()

	// Save analysis results
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := repositories.SaveDomainAnalysisResults(tx, id, vtResponse.Data.Attributes.LastAnalysisResults); err != nil {
			log.Printf("Error saving analysis results for ID %s: %v", id, err)
			errChan <- err
			return
		}
		log.Printf("Successfully saved analysis results for ID: %s", id)
	}()

	wg.Wait()
	close(errChan)

	// Check for any errors
	for err := range errChan {
		if err != nil {
			return nil, err
		}
	}

	// Save to Redis cache
	domainJSON, err := json.Marshal(domain)
	if err != nil {
		log.Printf("Error marshaling domain for cache: %v", err)
	} else {
		if err := redisClient.Set(context.Background(), cacheKey, domainJSON, time.Hour); err != nil {
			log.Printf("Error saving to Redis cache: %v", err)
		} else {
			log.Printf("Successfully saved to Redis cache for ID: %s", id)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		log.Printf("Error committing transaction for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully committed transaction for ID: %s", id)

	return domain, nil
}
