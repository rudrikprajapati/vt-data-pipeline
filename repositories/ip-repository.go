package repositories

import (
	"encoding/json"
	"log"
	"time"

	"vt-data-pipeline/models"

	"github.com/jmoiron/sqlx"
)

// GetFromCache retrieves IP data from cache (shared with domains)
func GetIPReportFromCache(id string, db *sqlx.DB) (*models.CacheEntry, error) {
	var cache models.CacheEntry
	err := db.Get(&cache, "SELECT id, data, cached_at, expires_at FROM domain_cache WHERE id=$1 AND expires_at > $2", id, time.Now())
	if err != nil {
		return nil, err
	}
	return &cache, nil
}

// GetIPAddress retrieves IP data from the main table
func GetIPAddress(id string, db *sqlx.DB) (*models.IPAddress, error) {
	var ip models.IPAddress
	err := db.Get(&ip, "SELECT * FROM ip_addresses WHERE id=$1", id)
	if err != nil {
		return nil, err
	}
	return &ip, nil
}

// SaveIPAddress saves or updates IP data
func SaveIPAddress(tx *sqlx.Tx, ip *models.IPAddress) error {
	_, err := tx.NamedExec(`INSERT INTO ip_addresses (id, type, last_analysis_date, asn, reputation, country, as_owner, regional_internet_registry, network, whois_date, last_modification_date, continent, harmless_count, malicious_count, suspicious_count, undetected_count, timeout_count, created_at, updated_at)
                          VALUES (:id, :type, :last_analysis_date, :asn, :reputation, :country, :as_owner, :regional_internet_registry, :network, :whois_date, :last_modification_date, :continent, :harmless_count, :malicious_count, :suspicious_count, :undetected_count, :timeout_count, :created_at, :updated_at)
                          ON CONFLICT (id) DO UPDATE SET
                          type = EXCLUDED.type,
                          last_analysis_date = EXCLUDED.last_analysis_date,
                          asn = EXCLUDED.asn,
                          reputation = EXCLUDED.reputation,
                          country = EXCLUDED.country,
                          as_owner = EXCLUDED.as_owner,
                          regional_internet_registry = EXCLUDED.regional_internet_registry,
                          network = EXCLUDED.network,
                          whois_date = EXCLUDED.whois_date,
                          last_modification_date = EXCLUDED.last_modification_date,
                          continent = EXCLUDED.continent,
                          harmless_count = EXCLUDED.harmless_count,
                          malicious_count = EXCLUDED.malicious_count,
                          suspicious_count = EXCLUDED.suspicious_count,
                          undetected_count = EXCLUDED.undetected_count,
                          timeout_count = EXCLUDED.timeout_count,
                          updated_at = EXCLUDED.updated_at`, ip)
	return err
}

// SaveTags saves IP tags
func SaveIPTags(tx *sqlx.Tx, ipID string, tags []string) error {
	// Clear existing tags
	_, err := tx.Exec("DELETE FROM ip_tags WHERE ip_id=$1", ipID)
	if err != nil {
		return err
	}

	// Prepare the insert statement
	stmt, err := tx.Prepare(`INSERT INTO ip_tags (ip_id, tag)
                          VALUES ($1, $2)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Insert new tags
	for _, tag := range tags {
		_, err = stmt.Exec(ipID, tag)
		if err != nil {
			return err
		}
	}
	return nil
}

// SaveAnalysisResults saves IP analysis results
func SaveIPAnalysisResults(tx *sqlx.Tx, ipID string, results map[string]struct {
	Category string `json:"category"`
	Result   string `json:"result"`
	Method   string `json:"method"`
}) error {
	// Clear existing results
	_, err := tx.Exec("DELETE FROM ip_analysis_results WHERE ip_id=$1", ipID)
	if err != nil {
		return err
	}

	// Prepare the insert statement
	stmt, err := tx.Prepare(`INSERT INTO ip_analysis_results (ip_id, engine_name, category, result, method)
                          VALUES ($1, $2, $3, $4, $5)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Insert new results
	for engine, result := range results {
		_, err = stmt.Exec(
			ipID,
			engine,
			result.Category,
			result.Result,
			result.Method)
		if err != nil {
			return err
		}
	}
	return nil
}

// SaveDetails saves IP details
func SaveIPDetails(tx *sqlx.Tx, details *models.IPDetails) error {
	_, err := tx.NamedExec(`INSERT INTO ip_details (ip_id, whois, total_votes)
                          VALUES (:ip_id, :whois, :total_votes)
                          ON CONFLICT (ip_id) DO UPDATE SET
                          whois = EXCLUDED.whois,
                          total_votes = EXCLUDED.total_votes`, details)
	return err
}

// SaveCache saves IP data to cache (shared with domains)
func SaveIPReportCache(tx *sqlx.Tx, id string, data any, expiration time.Duration) error {
	log.Printf("Starting cache save operation for ID: %s", id)

	cacheData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshaling cache data for ID %s: %v", id, err)
		return err
	}

	cacheEntry := models.CacheEntry{
		ID:        id,
		Data:      cacheData,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(expiration),
	}

	// Check current cache size
	var count int
	err = tx.Get(&count, "SELECT COUNT(*) FROM domain_cache")
	if err != nil {
		log.Printf("Error getting cache count for ID %s: %v", id, err)
		return err
	}
	log.Printf("Current cache size: %d entries", count)

	// If cache is full (5 entries), remove the oldest entry
	if count >= 5 {
		// Get the oldest entry details before deleting
		var oldestEntry struct {
			ID       string    `db:"id"`
			CachedAt time.Time `db:"cached_at"`
		}
		err = tx.Get(&oldestEntry, "SELECT id, cached_at FROM domain_cache ORDER BY cached_at ASC LIMIT 1")
		if err != nil {
			log.Printf("Error getting oldest cache entry for ID %s: %v", id, err)
			return err
		}

		log.Printf("Cache full (5 entries). Removing oldest entry - ID: %s, Cached at: %v",
			oldestEntry.ID, oldestEntry.CachedAt.Format(time.RFC3339))

		_, err = tx.Exec("DELETE FROM domain_cache WHERE id IN (SELECT id FROM domain_cache ORDER BY cached_at ASC LIMIT 1)")
		if err != nil {
			log.Printf("Error deleting oldest cache entry for ID %s: %v", id, err)
			return err
		}
		log.Printf("Successfully removed oldest cache entry")
	}

	// Insert new cache entry
	_, err = tx.NamedExec(`INSERT INTO domain_cache (id, data, cached_at, expires_at)
                          VALUES (:id, :data, :cached_at, :expires_at)
                          ON CONFLICT (id) DO UPDATE SET
                          data = EXCLUDED.data,
                          cached_at = EXCLUDED.cached_at,
                          expires_at = EXCLUDED.expires_at`, cacheEntry)
	if err != nil {
		log.Printf("Error inserting/updating cache entry for ID %s: %v", id, err)
		return err
	}
	log.Printf("Successfully saved cache entry for ID: %s, Expires at: %v",
		id, cacheEntry.ExpiresAt.Format(time.RFC3339))

	return nil
}
