package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
)

type apiConfig struct {
    fileserverHits atomic.Int32
}
type ChirpRequest struct {
    Body string `json:"body"`
}
type ErrorRequest struct {
    Error string `json:"error"`
}
type ValidRequest struct {
    Valid string `json:"valid"`
}
type CleanedResponse struct {
    CleanedBody string `json:"cleaned_body"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        cfg.fileserverHits.Add(1)
        next.ServeHTTP(w, req)
    })
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
    dat, err := json.Marshal(payload)
    if err != nil { 
        log.Printf("Algo deu errado ao encodar a resposta JSON: %v", err)
        w.WriteHeader(500)
        return
    }
    
    w.Header().Add("Type-Content", "application/json")
    w.WriteHeader(code)
    w.Write(dat)
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
    if code > 499 {
        respondWithJSON(w, 500, "Erro no servidor!")
        return
    }
    
    respondWithJSON(w, code, ErrorRequest{
        Error: msg,
    })
}

func (cfg *apiConfig) requestNumber(w http.ResponseWriter, req *http.Request) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, `<html>
                        <body>
                            <h1>Fala tu, Ademiro!</h1>
                            <p>O site foi visitado %d vezes!</p>
                        </body>
                    </html>`, cfg.fileserverHits.Load())
}

func (cfg *apiConfig) resetNumber(w http.ResponseWriter, req *http.Request) {
    cfg.fileserverHits.Store(0)
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    w.WriteHeader(http.StatusOK)
}

func middlewareLog(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        log.Printf("%s %s", req.Method, req.URL.Path)
        next.ServeHTTP(w, req)
    })
}

func cleanedChirpBody(body string) string {
    pfWords := []string{
        "kerfuffle",
        "sharbert",
        "fornax",
    }

    words := strings.Fields(body)

    for i, word := range words {
        normWord := strings.ToLower(word)
        for _, profaneWord := range pfWords {
            if normWord == profaneWord {
                words[i] = "****"
            }
        }
    }

    return strings.Join(words, " ")
}

func validateChirpH(w http.ResponseWriter, req *http.Request) {
    var chirpReq ChirpRequest
    err := json.NewDecoder(req.Body).Decode(&chirpReq)
    if err != nil || chirpReq.Body == "" {
        respondWithError(w, http.StatusBadRequest, "Algo deu errado!")
        return
    }

    if len(chirpReq.Body) > 140 {
        respondWithError(w, http.StatusBadRequest, "Chirp é muito longo")
        return
    }

    //json.NewEncoder(w).Encode(ValidRequest{Valid: "true"})

    cleanedBody := cleanedChirpBody(chirpReq.Body)

    respondWithJSON(w, 200, CleanedResponse{CleanedBody: cleanedBody})
}

func main() {
    host := "localhost"
    port := "8080"

    mux := http.NewServeMux()
    server := &http.Server{
        Addr: ":" + port,
        Handler: mux,
    }

    apiCfg := apiConfig{}

    mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))
    mux.Handle("/assets/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir("/assets")))))
    mux.HandleFunc("GET /admin/metrics", apiCfg.requestNumber)
    mux.HandleFunc("POST /admin/reset", apiCfg.resetNumber)
    mux.HandleFunc("POST /api/validate_chirp", validateChirpH)
    

    mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, req *http.Request){
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK"))
    })

    log.Printf("Iniciando server em: http://%s%s", host, server.Addr)
    if err := server.ListenAndServe(); err != nil {
        log.Fatal(err)
    }
}