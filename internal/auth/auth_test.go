package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHash(t *testing.T) {
	password := "senha123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Erro na função HashPassword: %v",err)
	}

	err = CheckPasswordHash(password, hash)
	if err != nil {
		t.Fatalf("Erro na função CheckPassword: %v", err)
	}
}

func TestCheck(t *testing.T) {
	pass := "senha123"
	errada := "errada"

	hash, _ := HashPassword(pass)

	err := CheckPasswordHash(pass, hash)
	if err != nil {
		t.Fatalf("Erro ao checar senha certa: %v", err)
	}

	err = CheckPasswordHash(errada, hash)
	if err == nil {
		t.Fatalf("Deveria retornar erro ao checar senha errada: %v", err)
	}
}

func TestMakeValidadeJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "segredo"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
    if err != nil {
        t.Fatalf("MakeJWT failed: %v", err)
    }

	validoUser, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Fatalf("Falha ao validar JWT: %v", err)
	}
	if validoUser != userID {
		t.Fatalf("Esperado user %s no lugar de %v", userID, validoUser)
	}
	
	expitedT, err := MakeJWT(userID, tokenSecret, -time.Hour)
	if err != nil {
		t.Fatalf("Falha ao criar JWT: %v", err)
	}

	_, err = ValidateJWT(expitedT, tokenSecret)
	if err == nil {
		t.Fatalf("Deveria ter falhado pelo token expirado")
	}
	_, err = ValidateJWT(token, "errado")
	if err == nil {
		t.Fatalf("Deveria ter falhado pelo token ser assinado com secret errado.")
	}

}

func TestBearerToken(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer tokenbearer")

	token, err := GetBearerToken(headers)
	if err != nil {
		t.Fatalf("Não pode trazer o header: %v", err)
	}
	if token != "tokenbearer" {
		t.Fatalf("Token esperado: 'tokenbearer': %v", err)
	}

	headers = http.Header{}
	_, err = GetBearerToken(headers)
	if err == nil {
		t.Fatalf("Esperado erro por falta do header: %v", err)
	}

	headers.Set("Authorization", "faltaparte")
	_, err = GetBearerToken(headers)
	if err == nil {
		t.Fatalf("Esperado erro por má formação do token: %v", err)
	}
}