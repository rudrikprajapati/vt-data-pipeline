package handlers

import (
	"net/http"

	"vt-data-pipeline/services"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

func GetReport(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		reportType := c.Query("type") // domains, ip_addresses
		if reportType != "domains" && reportType != "ip_addresses" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "only domains or ip_addresses supported"})
			return
		}

		var report any
		var err error

		switch reportType {
		case "domains":
			report, err = services.FetchDomainVTReport(id, reportType, db)
		case "ip_addresses":
			report, err = services.FetchIPReport(id, reportType, db)
		}

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, report)
	}
}
