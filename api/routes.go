package api

import (
	"vt-data-pipeline/handlers"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

func SetupRoutes(r *gin.Engine, db *sqlx.DB) {
	reportHandler := handlers.NewReportHandler(db)
	r.GET("/report/:id", reportHandler.GetReport)
}
