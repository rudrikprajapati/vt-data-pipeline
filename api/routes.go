package api

import (
	"vt-data-pipeline/handlers"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

func SetupRoutes(r *gin.Engine, db *sqlx.DB) {
	// get report from vt and save to db
	r.GET("/report/:id", handlers.GetReport(db))
}
