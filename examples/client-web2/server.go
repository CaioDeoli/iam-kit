package main

import (
	"log"
	"net/http"
)

func main() {
	fs := http.FileServer(http.Dir("./")) // "./" é a pasta atual
	http.Handle("/", fs)

	log.Println("Servidor rodando na porta 8081...")
	err := http.ListenAndServe(":8081", nil)
	if err != nil {
		log.Fatal(err)
	}
}
