package main

import (
	"log"
	"os"

	"github.com/CaioDeoli/iam-kit/internal/config"
	"github.com/CaioDeoli/iam-kit/internal/database"
	httph "github.com/CaioDeoli/iam-kit/internal/http"
)

func main() {
	// optional: load .env in dev (use your favorite loader)
	_ = os.Setenv("TZ", "UTC")

	cfg := config.FromEnv()
	db := database.Connect(cfg)
	router := httph.SetupRouter(cfg, db)

	addr := ":" + cfg.AppPort
	log.Printf("IAMKit listening on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatal(err)
	}
}
