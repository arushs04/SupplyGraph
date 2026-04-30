package main

import (
	"log"
	"net/http"
	"os"

	"supplygraph/internal/api"
	"supplygraph/internal/db"
)

func main() {
	database, err := db.Open()
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer database.Close()

	repo := db.NewRepository(database)
	server := api.NewServer(repo)

	addr := os.Getenv("API_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	log.Printf("starting api server on %s", addr)
	if err := http.ListenAndServe(addr, server); err != nil {
		log.Fatalf("serve http: %v", err)
	}
}
