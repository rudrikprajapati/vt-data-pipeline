package main

import (
	"vt-data-pipeline/api"
	"vt-data-pipeline/config"
	"vt-data-pipeline/db"
	"vt-data-pipeline/handlers"
	"vt-data-pipeline/services"

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
	vtService := services.NewVTService(cfg, dbConn)
	vtHandler := handlers.NewVTHandler(vtService)

	r := gin.Default()
	api.SetupRoutes(r, vtHandler)

	r.Run(":8080")
}
