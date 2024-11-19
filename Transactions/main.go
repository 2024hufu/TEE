package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

type Request struct {
	ID string `json:"id"`
}

func main() {
	http.HandleFunc("/getfile", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req Request
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if req.ID == "" {
			http.Error(w, "ID is required", http.StatusBadRequest)
			return
		}

		fileName := fmt.Sprintf("wallet%s.txt", req.ID)
		if _, err := os.Stat(fileName); os.IsNotExist(err) {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		data, err := ioutil.ReadFile(fileName)
		if err != nil {
			http.Error(w, "Error reading file", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Write(data)
	})

	fmt.Println("Server started at :38080")
	http.ListenAndServe(":38080", nil)
}

