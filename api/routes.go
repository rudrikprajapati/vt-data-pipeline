package api

import (
	"vt-data-pipeline/handlers"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine, vtHandler *handlers.VTHandler) {
	r.GET("/report/:id", vtHandler.GetReport)
}
