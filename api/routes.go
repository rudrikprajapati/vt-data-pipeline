package api

import (
	"vt-data-pipeline/config"
	"vt-data-pipeline/handlers"
	"vt-data-pipeline/redis"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

func SetupRoutes(r *gin.Engine, db *sqlx.DB, redisClient *redis.Client, cfg *config.Config) {
	reportHandler := handlers.NewReportHandler(db, redisClient, cfg)
	r.GET("/report/:id", reportHandler.GetReport)
}
