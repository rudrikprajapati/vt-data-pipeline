package api

import (
	"vt-data-pipeline/handlers"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine, vtHandler *handlers.VTHandler) {
	// get report from vt and save to db
	r.GET("/report/:id", vtHandler.GetReport)

	// get domain data from db
	r.GET("/domain/:id", vtHandler.GetDomain)
}
