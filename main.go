package main

import (
	"vt-data-pipeline/api"
	"vt-data-pipeline/config"
	"vt-data-pipeline/db"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		panic("Error loading .env file: " + err.Error())
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		panic("Failed to load config: " + err.Error())
	}

	dbConn := db.InitDB(cfg.Database.URL)
	r := gin.Default()
	api.SetupRoutes(r, dbConn)

	r.Run(":8080")
}
