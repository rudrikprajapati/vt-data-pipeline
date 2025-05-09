package repositories

import (
	"encoding/json"
	"time"

	"vt-data-pipeline/models"

	"github.com/jmoiron/sqlx"
)

type IPRepository struct {
	db *sqlx.DB
}

// NewIPRepository creates and returns a new instance of IPRepository.
// It takes a sqlx.DB connection as a parameter which will be used for all database operations.
func NewIPRepository(db *sqlx.DB) *IPRepository {
	return &IPRepository{db: db}
}

// GetFromCache retrieves IP data from cache (shared with domains)
func (r *IPRepository) GetFromCache(id string) (*models.CacheEntry, error) {
	var cache models.CacheEntry
	err := r.db.Get(&cache, "SELECT id, data, cached_at, expires_at FROM domain_cache WHERE id=$1 AND expires_at > $2", id, time.Now())
	if err != nil {
		return nil, err
	}
	return &cache, nil
}

// GetIPAddress retrieves IP data from the main table
func (r *IPRepository) GetIPAddress(id string) (*models.IPAddress, error) {
	var ip models.IPAddress
	err := r.db.Get(&ip, "SELECT * FROM ip_addresses WHERE id=$1", id)
	if err != nil {
		return nil, err
	}
	return &ip, nil
}

// SaveIPAddress saves or updates IP data
func (r *IPRepository) SaveIPAddress(ip *models.IPAddress) error {
	_, err := r.db.NamedExec(`INSERT INTO ip_addresses (id, type, last_analysis_date, asn, reputation, country, as_owner, regional_internet_registry, network, whois_date, last_modification_date, continent, harmless_count, malicious_count, suspicious_count, undetected_count, timeout_count, created_at, updated_at)
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
func (r *IPRepository) SaveTags(ipID string, tags []string) error {
	// Clear existing tags
	_, err := r.db.Exec("DELETE FROM ip_tags WHERE ip_id=$1", ipID)
	if err != nil {
		return err
	}

	// Prepare the insert statement
	stmt, err := r.db.Prepare(`INSERT INTO ip_tags (ip_id, tag)
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
func (r *IPRepository) SaveAnalysisResults(ipID string, results map[string]struct {
	Category string `json:"category"`
	Result   string `json:"result"`
	Method   string `json:"method"`
}) error {
	// Clear existing results
	_, err := r.db.Exec("DELETE FROM ip_analysis_results WHERE ip_id=$1", ipID)
	if err != nil {
		return err
	}

	// Prepare the insert statement
	stmt, err := r.db.Prepare(`INSERT INTO ip_analysis_results (ip_id, engine_name, category, result, method)
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
func (r *IPRepository) SaveDetails(details *models.IPDetails) error {
	_, err := r.db.NamedExec(`INSERT INTO ip_details (ip_id, whois, total_votes)
                          VALUES (:ip_id, :whois, :total_votes)
                          ON CONFLICT (ip_id) DO UPDATE SET
                          whois = EXCLUDED.whois,
                          total_votes = EXCLUDED.total_votes`, details)
	return err
}

// SaveCache saves IP data to cache (shared with domains)
func (r *IPRepository) SaveCache(id string, data interface{}, expiration time.Duration) error {
	cacheData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	cacheEntry := models.CacheEntry{
		ID:        id,
		Data:      cacheData,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(expiration),
	}

	_, err = r.db.NamedExec(`INSERT INTO domain_cache (id, data, cached_at, expires_at)
                          VALUES (:id, :data, :cached_at, :expires_at)
                          ON CONFLICT (id) DO UPDATE SET
                          data = EXCLUDED.data,
                          cached_at = EXCLUDED.cached_at,
                          expires_at = EXCLUDED.expires_at`, cacheEntry)
	return err
}
