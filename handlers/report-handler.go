package handlers

import (
	"net/http"

	"vt-data-pipeline/config"
	"vt-data-pipeline/redis"
	"vt-data-pipeline/services"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

// ReportHandler handles report requests for domains and IP addresses
type ReportHandler struct {
	db          *sqlx.DB
	redisClient *redis.Client
	cfg         *config.Config
}

// NewReportHandler creates a new ReportHandler instance
func NewReportHandler(db *sqlx.DB, redisClient *redis.Client, cfg *config.Config) *ReportHandler {
	return &ReportHandler{
		db:          db,
		redisClient: redisClient,
		cfg:         cfg,
	}
}

// GetReport handles the GET request for reports
func (h *ReportHandler) GetReport(c *gin.Context) {
	id := c.Param("id")
	reportType := c.Query("type")

	if reportType != "domains" && reportType != "ip_addresses" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only domains or ip_addresses supported"})
		return
	}

	var report any
	var err error

	switch reportType {
	case "domains":
		report, err = services.FetchDomainVTReport(id, reportType, h.db, h.redisClient, h.cfg)
	case "ip_addresses":
		report, err = services.FetchIPReport(id, reportType, h.db, h.redisClient, h.cfg)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, report)
}
