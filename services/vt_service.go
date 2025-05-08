package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"vt-data-pipeline/config"
	"vt-data-pipeline/models"

	"github.com/jmoiron/sqlx"
)

type VTService struct {
	cfg *config.Config
	db  *sqlx.DB
}

func NewVTService(cfg *config.Config, db *sqlx.DB) *VTService {
	return &VTService{cfg: cfg, db: db}
}

func (s *VTService) FetchVTReport(id, reportType string) (*models.VTReport, error) {
	// Check cache first
	var cache models.CacheEntry
	err := s.db.Get(&cache, "SELECT * FROM cache WHERE id=$1 AND expires_at > $2", id, time.Now())
	if err == nil {
		report := &models.VTReport{ID: id, Type: reportType, Data: cache.Data}
		return report, nil
	}

	// Fetch from VirusTotal API
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/%s/%s", reportType, id)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-apikey", s.cfg.VirusTotal.APIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	dataJSON, _ := json.Marshal(data)

	// Store in database
	report := &models.VTReport{
		ID:        id,
		Type:      reportType,
		Data:      string(dataJSON),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_, err = s.db.NamedExec(`INSERT INTO vt_reports (id, type, data, created_at, updated_at)
                            VALUES (:id, :type, :data, :created_at, :updated_at)`, report)
	if err != nil {
		return nil, err
	}

	// Store in cache (e.g., 1-hour TTL)
	cacheEntry := &models.CacheEntry{
		ID:        id,
		Data:      string(dataJSON),
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	_, err = s.db.NamedExec(`INSERT INTO cache (id, data, cached_at, expires_at)
                            VALUES (:id, :data, :cached_at, :expires_at)`, cacheEntry)
	if err != nil {
		return nil, err
	}

	return report, nil
}
