package auth

import (
	"testing"
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