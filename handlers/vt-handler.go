package handlers

import (
	"net/http"

	"vt-data-pipeline/services"

	"github.com/gin-gonic/gin"
)

type VTHandler struct {
	vtService *services.VTService
}

func NewVTHandler(vtService *services.VTService) *VTHandler {
	return &VTHandler{vtService: vtService}
}

func (h *VTHandler) GetReport(c *gin.Context) {
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
		report, err = h.vtService.FetchDomainVTReport(id, reportType)
	case "ip_addresses":
		report, err = h.vtService.FetchIPReport(id, reportType)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, report)
}
