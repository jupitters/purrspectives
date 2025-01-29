package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/jupitters/chirpy/internal/database"
	_ "github.com/lib/pq"
)

type User struct {
    ID uuid.UUID `json:"id"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
    Email string `json:"email"`
}
type Chirp struct {
    ID uuid.UUID `json:"id"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
    Body string `json:"body"`
    User_ID uuid.UUID `json:"user_id"`
}
type apiConfig struct {
    fileserverHits atomic.Int32
    DB *database.Queries
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        cfg.fileserverHits.Add(1)
        log.Printf("%s %s %s", req.Method, req.URL.Path, req.Header)
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
    
    w.Header().Add("Content-Type", "application/json")
    w.WriteHeader(code)
    w.Write(dat)
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
    type ErrorRequest struct {
        Error string `json:"error"`
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

func (apiCfg *apiConfig) cleanAll(w http.ResponseWriter, req *http.Request) {
    apiCfg.fileserverHits.Store(0)
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")

    platform := os.Getenv("PLATFORM")
    if platform != "dev" {
        respondWithError(w, http.StatusForbidden, "Acesso proibido!")
        return
    }

    err := apiCfg.DB.DeleteAllUsers(req.Context())
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Não foi possivel resetar o banco de dados. %v", err))
        return
    }

    respondWithJSON(w, 200, map[string]string{"status": "ok"})
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

func (apiCfg *apiConfig) handlerChirp(w http.ResponseWriter, req *http.Request) {
    type ChirpRequest struct {
        Body string `json:"body"`
        User_ID uuid.UUID `json:"user_id"`
    }

    chirpReq := ChirpRequest{}
    err := json.NewDecoder(req.Body).Decode(&chirpReq)
    if err != nil || chirpReq.Body == ""  || chirpReq.User_ID == uuid.Nil{
        respondWithError(w, http.StatusBadRequest, fmt.Sprintf("Algo deu errado na requisição! %v", err))
        return
    }

    if len(chirpReq.Body) > 140 {
        respondWithError(w, http.StatusBadRequest, "Chirp é muito longo")
        return
    }

    chirpReq.Body = cleanedChirpBody(chirpReq.Body)

    chirp, err := apiCfg.DB.CreateChirp(req.Context(), database.CreateChirpParams{
        Body: chirpReq.Body,
        UserID: chirpReq.User_ID,
    })
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Não foi possivel criar o chirp: %v", err))
    }

    respondWithJSON(w, http.StatusCreated, Chirp{
        ID: chirp.ID,
        CreatedAt: chirp.CreatedAt,
        UpdatedAt: chirp.UpdatedAt,
        Body: chirp.Body,
        User_ID: chirp.UserID,
    })
}

func (apiCfg *apiConfig) handlerCreateUser(w http.ResponseWriter, req *http.Request) {
    type parameters struct {
        Email string `json:"email"`
    }

    params := parameters{}
    err := json.NewDecoder(req.Body).Decode(&params)
    if err != nil {
        respondWithError(w, 400, fmt.Sprintf("Erro no JSON: %v", err))
        return
    }
    if params.Email == ""{
        respondWithError(w, http.StatusBadRequest, "Email não pode ser vazio.")
        return
    }

    user, err := apiCfg.DB.CreateUser(req.Context(), params.Email)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Não foi possivel criar o usuario: %v", err))
        return
    }

    respondWithJSON(w, http.StatusCreated, User{
        ID: user.ID,
        CreatedAt: user.CreatedAt,
        UpdatedAt: user.UpdatedAt,
        Email: user.Email,
    })   
}

func main() {
    godotenv.Load()
    host := "localhost"
    port := os.Getenv("PORT")

    dbURL := os.Getenv("DB_URL")
    if dbURL == "" {
        log.Fatal("Não foi possivel acessar o banco de dados.")
    }

    db, err := sql.Open("postgres", dbURL)
    if err != nil {
        log.Fatal("Erro ao abrir o banco de dados", err)
    }

    apiCfg := apiConfig {
        DB: database.New(db),
    }
    
    mux := http.NewServeMux()
    server := &http.Server{
        Addr: ":" + port,
        Handler: mux,
    }

    mux.Handle("/app", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
    mux.Handle("/assets", apiCfg.middlewareMetricsInc(http.FileServer(http.Dir("/assets"))))
    mux.HandleFunc("GET /admin/metrics", apiCfg.requestNumber)
    mux.HandleFunc("POST /admin/reset", apiCfg.cleanAll)
    mux.HandleFunc("POST /api/users", apiCfg.handlerCreateUser)
    mux.HandleFunc("POST /api/chirps", apiCfg.handlerChirp)

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