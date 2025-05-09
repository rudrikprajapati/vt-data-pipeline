package repositories

import (
	"encoding/json"
	"time"

	"vt-data-pipeline/models"

	"github.com/jmoiron/sqlx"
)

type DomainRepository struct {
	db *sqlx.DB
}

func NewDomainRepository(db *sqlx.DB) *DomainRepository {
	return &DomainRepository{db: db}
}

// GetFromCache retrieves domain data from cache
func (r *DomainRepository) GetFromCache(id string) (*models.CacheEntry, error) {
	var cache models.CacheEntry
	err := r.db.Get(&cache, "SELECT id, data, cached_at, expires_at FROM domain_cache WHERE id=$1 AND expires_at > $2", id, time.Now())
	if err != nil {
		return nil, err
	}
	return &cache, nil
}

// GetDomain retrieves domain data from the main table
func (r *DomainRepository) GetDomain(id string) (*models.Domain, error) {
	var domain models.Domain
	err := r.db.Get(&domain, "SELECT * FROM domains WHERE id=$1", id)
	if err != nil {
		return nil, err
	}
	return &domain, nil
}

// SaveDomain saves or updates domain data
func (r *DomainRepository) SaveDomain(domain *models.Domain) error {
	_, err := r.db.NamedExec(`INSERT INTO domains (id, type, creation_date, expiration_date, last_analysis_date, reputation, registrar, tld, whois_date, harmless_count, malicious_count, suspicious_count, undetected_count, timeout_count, created_at, updated_at)
                          VALUES (:id, :type, :creation_date, :expiration_date, :last_analysis_date, :reputation, :registrar, :tld, :whois_date, :harmless_count, :malicious_count, :suspicious_count, :undetected_count, :timeout_count, :created_at, :updated_at)
                          ON CONFLICT (id) DO UPDATE SET
                          type = EXCLUDED.type,
                          creation_date = EXCLUDED.creation_date,
                          expiration_date = EXCLUDED.expiration_date,
                          last_analysis_date = EXCLUDED.last_analysis_date,
                          reputation = EXCLUDED.reputation,
                          registrar = EXCLUDED.registrar,
                          tld = EXCLUDED.tld,
                          whois_date = EXCLUDED.whois_date,
                          harmless_count = EXCLUDED.harmless_count,
                          malicious_count = EXCLUDED.malicious_count,
                          suspicious_count = EXCLUDED.suspicious_count,
                          undetected_count = EXCLUDED.undetected_count,
                          timeout_count = EXCLUDED.timeout_count,
                          updated_at = EXCLUDED.updated_at`, domain)
	return err
}

// SaveCategories saves domain categories
func (r *DomainRepository) SaveCategories(domainID string, categories map[string]string) error {
	// Clear existing categories
	_, err := r.db.Exec("DELETE FROM domain_categories WHERE domain_id=$1", domainID)
	if err != nil {
		return err
	}

	// Insert new categories
	for engine, category := range categories {
		_, err = r.db.Exec(`INSERT INTO domain_categories (domain_id, engine_name, category)
                          VALUES ($1, $2, $3)`,
			domainID,
			engine,
			category)
		if err != nil {
			return err
		}
	}
	return nil
}

// SaveAnalysisResults saves domain analysis results
func (r *DomainRepository) SaveAnalysisResults(domainID string, results map[string]struct {
	Category string `json:"category"`
	Result   string `json:"result"`
	Method   string `json:"method"`
}) error {
	// Clear existing results
	_, err := r.db.Exec("DELETE FROM domain_analysis_results WHERE domain_id=$1", domainID)
	if err != nil {
		return err
	}

	// Prepare the insert statement
	stmt, err := r.db.Prepare(`INSERT INTO domain_analysis_results (domain_id, engine_name, category, result, method)
                          VALUES ($1, $2, $3, $4, $5)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Insert new results
	for engine, result := range results {
		_, err = stmt.Exec(
			domainID,
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

// SaveDetails saves domain details
func (r *DomainRepository) SaveDetails(details *models.DomainDetails) error {
	_, err := r.db.NamedExec(`INSERT INTO domain_details (domain_id, last_dns_records, last_https_certificate, rdap, whois, popularity_ranks, total_votes)
                          VALUES (:domain_id, :last_dns_records, :last_https_certificate, :rdap, :whois, :popularity_ranks, :total_votes)
                          ON CONFLICT (domain_id) DO UPDATE SET
                          last_dns_records = EXCLUDED.last_dns_records,
                          last_https_certificate = EXCLUDED.last_https_certificate,
                          rdap = EXCLUDED.rdap,
                          whois = EXCLUDED.whois,
                          popularity_ranks = EXCLUDED.popularity_ranks,
                          total_votes = EXCLUDED.total_votes`, details)
	return err
}

// SaveCache saves domain data to cache
func (r *DomainRepository) SaveCache(id string, data interface{}, expiration time.Duration) error {
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
