package services

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
	"vt-data-pipeline/models"
)

func (s *VTService) FetchIPReport(id, reportType string) (*models.IPAddress, error) {
	log.Printf("Starting FetchIPReport for ID: %s, Type: %s", id, reportType)

	// Check cache first
	cache, err := s.ipRepo.GetFromCache(id)
	if err == nil {
		log.Printf("Cache hit for ID: %s", id)
		var ip models.IPAddress
		if err := json.Unmarshal(cache.Data, &ip); err != nil {
			log.Printf("Error unmarshaling cached data for ID %s: %v", id, err)
			return nil, err
		}
		return &ip, nil
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
	var vtResponse models.VirusTotalIPResponse
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
	var lastAnalysisDate, whoisDate, lastModificationDate *time.Time
	if vtResponse.Data.Attributes.LastAnalysisDate != 0 {
		t := time.Unix(vtResponse.Data.Attributes.LastAnalysisDate, 0)
		lastAnalysisDate = &t
	}
	if vtResponse.Data.Attributes.WhoisDate != 0 {
		t := time.Unix(vtResponse.Data.Attributes.WhoisDate, 0)
		whoisDate = &t
	}
	if vtResponse.Data.Attributes.LastModificationDate != 0 {
		t := time.Unix(vtResponse.Data.Attributes.LastModificationDate, 0)
		lastModificationDate = &t
	}

	// Get analysis stats
	harmless := vtResponse.Data.Attributes.LastAnalysisStats["harmless"]
	malicious := vtResponse.Data.Attributes.LastAnalysisStats["malicious"]
	suspicious := vtResponse.Data.Attributes.LastAnalysisStats["suspicious"]
	undetected := vtResponse.Data.Attributes.LastAnalysisStats["undetected"]
	timeout := vtResponse.Data.Attributes.LastAnalysisStats["timeout"]

	// Create IP object
	ip := &models.IPAddress{
		ID:                       id,
		Type:                     reportType,
		LastAnalysisDate:         lastAnalysisDate,
		ASN:                      &vtResponse.Data.Attributes.ASN,
		Reputation:               &vtResponse.Data.Attributes.Reputation,
		Country:                  &vtResponse.Data.Attributes.Country,
		ASOwner:                  &vtResponse.Data.Attributes.ASOwner,
		RegionalInternetRegistry: &vtResponse.Data.Attributes.RegionalInternetRegistry,
		Network:                  &vtResponse.Data.Attributes.Network,
		WhoisDate:                whoisDate,
		LastModificationDate:     lastModificationDate,
		Continent:                &vtResponse.Data.Attributes.Continent,
		HarmlessCount:            &harmless,
		MaliciousCount:           &malicious,
		SuspiciousCount:          &suspicious,
		UndetectedCount:          &undetected,
		TimeoutCount:             &timeout,
		CreatedAt:                time.Now(),
		UpdatedAt:                time.Now(),
	}

	// Save IP data
	if err := s.ipRepo.SaveIPAddress(ip); err != nil {
		log.Printf("Error saving IP data for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully saved IP data for ID: %s", id)

	// Save IP details
	votesJSON, _ := json.Marshal(vtResponse.Data.Attributes.TotalVotes)
	details := &models.IPDetails{
		IPID:       id,
		Whois:      vtResponse.Data.Attributes.Whois,
		TotalVotes: votesJSON,
	}

	if err := s.ipRepo.SaveDetails(details); err != nil {
		log.Printf("Error saving IP details for ID %s: %v", id, err)
		return nil, err
	}
	log.Printf("Successfully saved IP details for ID: %s", id)

	// Go routine for insert tags and analysis
	errChan := make(chan error, 2)
	var wg sync.WaitGroup

	// Save tags
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.ipRepo.SaveTags(id, vtResponse.Data.Attributes.Tags); err != nil {
			log.Printf("Error saving tags for ID %s: %v", id, err)
			errChan <- err
			return
		}
		log.Printf("Successfully saved tags for ID: %s", id)
	}()

	// Save analysis results
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.ipRepo.SaveAnalysisResults(id, vtResponse.Data.Attributes.LastAnalysisResults); err != nil {
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

	// Save to cache
	if err := s.ipRepo.SaveCache(id, ip, 1*time.Hour); err != nil {
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

	return ip, nil
}
