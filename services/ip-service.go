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

func FetchIPReport(id, reportType string, db *sqlx.DB, redisClient *redis.Client, cfg *config.Config) (*models.IPAddress, error) {
	log.Printf("Starting FetchIPReport for ID: %s, Type: %s", id, reportType)

	// Check Redis cache first
	cacheKey := fmt.Sprintf("ip:%s", id)
	cachedData, err := redisClient.Get(context.Background(), cacheKey)
	if err == nil && cachedData != "" {
		log.Printf("Redis cache hit for ID: %s", id)
		var ip models.IPAddress
		if err := json.Unmarshal([]byte(cachedData), &ip); err != nil {
			log.Printf("Error unmarshaling cached data for ID %s: %v", id, err)
			return nil, err
		}
		return &ip, nil
	}
	log.Printf("Redis cache miss for ID: %s, proceeding with API call", id)

	// Check database for recent data (updated within last 24 hours)
	IPFromDB, err := repositories.GetIPAddress(id, db)
	if err == nil && IPFromDB != nil {
		if time.Since(IPFromDB.UpdatedAt) < 24*time.Hour {
			log.Printf("Found recent IP data in DB for ID: %s, updated at: %v", id, IPFromDB.UpdatedAt)
			ipJSON, err := json.Marshal(IPFromDB)
			if err != nil {
				log.Printf("Error marshaling IP for cache: %v", err)
			} else {
				if err := redisClient.Set(context.Background(), cacheKey, ipJSON, time.Hour); err != nil {
					log.Printf("Error saving to Redis cache: %v", err)
				} else {
					log.Printf("Successfully saved to Redis cache for ID: %s", id)
				}
			}
			return IPFromDB, nil
		}
		log.Printf("DB data for ID %s is stale (updated at: %v), proceeding with API call", id, IPFromDB.UpdatedAt)
	} else if err != nil {
		log.Printf("No IP data found in DB for ID %s or error: %v", id, err)
	}
	log.Printf("Proceeding with VirusTotal API call for ID: %s", id)

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
	var vtResponse models.VirusTotalIPResponse
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
	if err := repositories.SaveIPAddress(tx, ip); err != nil {
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

	if err := repositories.SaveIPDetails(tx, details); err != nil {
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
		if err := repositories.SaveIPTags(tx, id, vtResponse.Data.Attributes.Tags); err != nil {
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
		if err := repositories.SaveIPAnalysisResults(tx, id, vtResponse.Data.Attributes.LastAnalysisResults); err != nil {
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
	ipJSON, err := json.Marshal(ip)
	if err != nil {
		log.Printf("Error marshaling IP for cache: %v", err)
	} else {
		if err := redisClient.Set(context.Background(), cacheKey, ipJSON, time.Hour); err != nil {
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

	return ip, nil
}
