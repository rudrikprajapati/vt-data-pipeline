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
	reportType := c.Query("type") // e.g., domains, ip_addresses, files
	if reportType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type is required"})
		return
	}

	report, err := h.vtService.FetchVTReport(id, reportType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, report)
}

func (h *VTHandler) GetDomain(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain id is required"})
		return
	}

	domain, err := h.vtService.GetDomainData(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, domain)
}
