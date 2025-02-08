package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/jupitters/chirpy/internal/auth"
	"github.com/jupitters/chirpy/internal/database"
	_ "github.com/lib/pq"
)

type User struct {
    ID uuid.UUID `json:"id"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
    Email string `json:"email"`
    IsChipryRed bool `json:"is_chirpy_red"`
    Token string `json:"token,omitempty"`
    RefreshToken string `json:"refresh_token,omitempty"`
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
    JWTSecret string
    PolkaKey string
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
    }

    token, err := auth.GetBearerToken(req.Header)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("%v", err))
        return
    }

    userID, err := auth.ValidateJWT(token, apiCfg.JWTSecret)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Não autorizado.")
        return
    }

    chirpReq := ChirpRequest{}
    err = json.NewDecoder(req.Body).Decode(&chirpReq)
    if err != nil || chirpReq.Body == "" {
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
        UserID: userID,
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

func (apiCfg *apiConfig) handlerGetChirps(w http.ResponseWriter, req *http.Request) {
    chirps := []Chirp{}
    s := req.URL.Query().Get("sort")
    q := req.URL.Query().Get("author_id")
    
    if q != "" {
        userID, err := uuid.Parse(q)
        if err != nil{
            respondWithError(w, http.StatusInternalServerError, "Erro ao recuperar id.")
            return
        }

        chirp, err := apiCfg.DB.GetChirpsByAuthor(req.Context(), userID)
        if err != nil {
            respondWithError(w, http.StatusInternalServerError, "Erro ao recuperar chirps.")
            return
        }

        for _, item := range chirp {
            chirps = append(chirps, Chirp{
                ID: item.ID,
                CreatedAt: item.CreatedAt,
                UpdatedAt: item.UpdatedAt,
                Body: item.Body,
                User_ID: item.UserID,
            })
        }
    }else {
        chirp, err := apiCfg.DB.GetChirps(req.Context())
        if err != nil {
            respondWithError(w, http.StatusInternalServerError, "Erro ao recuperar chirps!")
            return
        }

        for _, item := range chirp {
            chirps = append(chirps, Chirp{
                ID: item.ID,
                CreatedAt: item.CreatedAt,
                UpdatedAt: item.UpdatedAt,
                Body: item.Body,
                User_ID: item.UserID,
            })
        }

        if s == "asc" || s == "" {
            sort.Slice(chirps, func(i, j int) bool {
                return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
            })
        }
        if s == "desc" {
            sort.Slice(chirps, func(i, j int) bool {
                return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
            })
        }

        
    }

    respondWithJSON(w, http.StatusOK, chirps)
}

func (apiCfg *apiConfig) handlerGetChirpById(w http.ResponseWriter, req *http.Request) {
    chirpId, err := uuid.Parse(req.PathValue("chirpID"))
    if err != nil {
        respondWithError(w, http.StatusBadRequest, "ID inválido")
        return
    }

    chirp, err := apiCfg.DB.GetChirpByID(req.Context(), chirpId)
    if err != nil {
        respondWithError(w, http.StatusNotFound, "Chirp não encontrado")
        return
    }

    respondWithJSON(w, http.StatusOK, Chirp{
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
        Password string `json:"password"`
    }

    params := parameters{}
    err := json.NewDecoder(req.Body).Decode(&params)
    if err != nil {
        respondWithError(w, 400, fmt.Sprintf("Erro no JSON: %v", err))
        return
    }
    if params.Email == "" {
        respondWithError(w, http.StatusBadRequest, "Email não pode ser vazio.")
        return
    }
    if params.Password == "" {
        respondWithError(w, http.StatusBadRequest, "Senha não pode ser vazia.")
        return
    }

    params.Password, err = auth.HashPassword(params.Password)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Erro ao criar o hash da senha.")
        return
    }

    user, err := apiCfg.DB.CreateUser(req.Context(), database.CreateUserParams{
        Email: params.Email,
        HashedPassword: params.Password,
    })
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Não foi possivel criar o usuario: %v", err))
        return
    }

    respondWithJSON(w, http.StatusCreated, User{
        ID: user.ID,
        CreatedAt: user.CreatedAt,
        UpdatedAt: user.UpdatedAt,
        Email: user.Email,
        IsChipryRed: user.IsChirpyRed,
    })   
}

func (apiCfg *apiConfig) handlerLogin(w http.ResponseWriter, req *http.Request) {
    type parameters struct {
        Email string `json:"email"`
        Password string `json:"password"`
    }

    login := parameters{}
    err := json.NewDecoder(req.Body).Decode(&login)
    if err != nil {
        respondWithError(w, http.StatusBadRequest, fmt.Sprintf("Erro no JSON: %v", err))
        return
    }

    user, err := apiCfg.DB.GetUserByEmail(req.Context(), login.Email)
    if err != nil {
        respondWithError(w, http.StatusNotFound, "Email não encontrado")
        return
    }

    err = auth.CheckPasswordHash(login.Password, user.HashedPassword)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Email ou senha incorretos.")
        return
    }

    expiresIn := time.Hour
    token, err := auth.MakeJWT(user.ID, apiCfg.JWTSecret, expiresIn)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Falha ao criar JWT.")
        return
    }

    refresh_token, err := auth.MakeRefreshToken()
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Falha ao criar refresh token.")
        return
    }

    expiresAt := time.Now().Add(time.Hour * 24 * 60)
    _, err = apiCfg.DB.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{
        Token: refresh_token,
        UserID: user.ID,
        ExpiresAt: expiresAt,
    })
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Falha ao salvar refresh token.")
        return
    }

    respondWithJSON(w, http.StatusOK, User{
        ID: user.ID,
        CreatedAt: user.CreatedAt,
        UpdatedAt: user.UpdatedAt,
        Email: user.Email,
        IsChipryRed: user.IsChirpyRed,
        Token: token,
        RefreshToken: refresh_token,
    })
}

func (apiCfg *apiConfig) handlerRefresh (w http.ResponseWriter, req *http.Request) {
    if req.ContentLength > 0 {
        respondWithError(w, http.StatusBadRequest, "Requisição não aceita corpo.")
        return
    }

    refreshToken, err := auth.GetBearerToken(req.Header)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Token invalido")
        return
    }

    refreshTokenDat, err := apiCfg.DB.GetRefreshToken(req.Context(), refreshToken)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Token não encontrado ou expirado")
        return
    }
    if refreshTokenDat.ExpiresAt.Before(time.Now()) || refreshTokenDat.RevokedAt.Valid {
        respondWithError(w, http.StatusUnauthorized, "Token não encontrado ou expirado")
        return
    }

    newToken, err := auth.MakeJWT(refreshTokenDat.UserID, apiCfg.JWTSecret, time.Hour)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Não foi possivel gerar novo token de acesso")
        return
    }

    respondWithJSON(w, http.StatusOK, struct{Token string `json:"token"`}{Token: newToken})
}

func (apiCfg *apiConfig) handlerRevoke (w http.ResponseWriter, req *http.Request) {
    if req.ContentLength > 0 {
        respondWithError(w, http.StatusBadRequest, "Requisição não aceita corpo.")
        return
    }

    refreshToken, err := auth.GetBearerToken(req.Header)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Token invalido")
        return
    }

    err = apiCfg.DB.RevokeRefreshToken(req.Context(), refreshToken)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Não foi possivel revogar o refresh token.")
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

func (apiCfg *apiConfig) handlerUpdateUser (w http.ResponseWriter, req *http.Request) {
    type parameters struct {
        Email string `json:"email"`
        Password string `json:"password"`
    }
    params := parameters{}
    
    accessToken, err := auth.GetBearerToken(req.Header)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Token invalido")
        return
    }

    userID, err := auth.ValidateJWT(accessToken, apiCfg.JWTSecret)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Token de acesso invalido")
        return
    }

    err = json.NewDecoder(req.Body).Decode(&params)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Erro no json: %v", err))
        return
    }
    if params.Email == "" {
        respondWithError(w, http.StatusBadRequest, "Email não pode ser vazio.")
        return
    }
    if params.Password == "" {
        respondWithError(w, http.StatusBadRequest, "Senha não pode ser vazia.")
        return
    }

    hashedPass, err := auth.HashPassword(params.Password)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Erro interno no servidor")
        return
    }

    err = apiCfg.DB.UpdateUser(req.Context(), database.UpdateUserParams{
        Email: params.Email,
        HashedPassword: hashedPass,
        ID: userID,
    })
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Não foi possivel atualizar o usuario")
        return
    }

    respondWithJSON(w, http.StatusOK, struct{
        ID uuid.UUID `json:"id"`
        Email string `json:"email"`}{
        ID: userID,
        Email: params.Email,
    })

}

func (apiCfg *apiConfig) handlerDeleteChirpById (w http.ResponseWriter, req *http.Request) {
    accessToken, err := auth.GetBearerToken(req.Header)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Token invalido")
        return
    }

    userID, err := auth.ValidateJWT(accessToken, apiCfg.JWTSecret)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Token de acesso invalido")
        return
    }
    
    chirpID, err := uuid.Parse(req.PathValue("chirpID"))
    if err != nil {
        respondWithError(w, http.StatusBadRequest, "ID invalido")
        return
    }

    chirp, err := apiCfg.DB.GetChirpByID(req.Context(), chirpID)
    if err != nil {
        respondWithError(w, http.StatusNotFound, "erro ao recuperar chirp")
        return
    }

    if chirp.UserID != userID {
        respondWithError(w, http.StatusForbidden, "Não permitido deleção de chirps de outra pessoa")
        return
    }

    err = apiCfg.DB.DeleteChirpByID(req.Context(), chirpID)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Não foi possivel deletar chirp")
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

func (apiCfg *apiConfig) handlerUpgradeRed (w http.ResponseWriter, req *http.Request) {
    key, err := auth.GetAPIKey(req.Header)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("%v", err))
        return
    }
    if key != apiCfg.PolkaKey {
        respondWithError(w, http.StatusUnauthorized, "Não autorizado.")
        return
    }
    
    type webhook struct{
        Event string `json:"event"`
        Data struct {
            UserID uuid.UUID `json:"user_id"`
        } `json:"data"`
    }

    params := webhook{}
    err = json.NewDecoder(req.Body).Decode(&params)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "erro no json")
        return
    }

    if params.Event != "user.upgraded" {
        w.WriteHeader(http.StatusNoContent)
        return
    }

    user, err := apiCfg.DB.GetUserByID(req.Context(), params.Data.UserID)
    if user.ID == uuid.Nil || err != nil {
        respondWithError(w, http.StatusNotFound, "Não foi possivel localizar usuario")
        return
    }

    err = apiCfg.DB.UpgradeToRed(req.Context(), params.Data.UserID)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Erro ao converter usuario para Red")
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

func main() {
    godotenv.Load()
    host := "localhost"
    port := os.Getenv("PORT")
    jwtSecret := os.Getenv("JWT_SECRET")
    polkaKey := os.Getenv("POLKA_KEY")

    if polkaKey == "" {
        log.Fatal("Não foi possivel localizar POLKA_KEY em .env")
    }

    if jwtSecret == "" {
        log.Fatal("Não foi possivel localizar JWT_SECRET em .env")
    }

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
        JWTSecret: jwtSecret,
        PolkaKey: polkaKey,
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
    mux.HandleFunc("POST /api/login", apiCfg.handlerLogin)
    mux.HandleFunc("POST /api/refresh", apiCfg.handlerRefresh)
    mux.HandleFunc("POST /api/revoke", apiCfg.handlerRevoke)
    mux.HandleFunc("PUT /api/users", apiCfg.handlerUpdateUser)
    mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handlerUpgradeRed)

    mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handlerDeleteChirpById)
    mux.HandleFunc("POST /api/chirps", apiCfg.handlerChirp)
    mux.HandleFunc("GET /api/chirps", apiCfg.handlerGetChirps)
    mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handlerGetChirpById)
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