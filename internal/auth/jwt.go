package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTMaker struct {
	Secret     []byte
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

type AccessClaims struct {
	UserID uint     `json:"uid"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

func NewJWTMaker(secret string, accessTTL, refreshTTL time.Duration) *JWTMaker {
	return &JWTMaker{
		Secret:     []byte(secret),
		AccessTTL:  accessTTL,
		RefreshTTL: refreshTTL,
	}
}

func (m *JWTMaker) CreateAccessToken(userID uint, roles []string) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(m.AccessTTL)
	claims := AccessClaims{
		UserID: userID,
		Roles:  roles,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := token.SignedString(m.Secret)
	return s, exp, err
}

// Refresh tokens will be random strings (not JWTs) stored hashed in DB
func GenerateRefreshToken() (plain string, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	plain = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(plain))
	hash = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

func VerifyRefreshTokenHash(storedHash, providedPlain string) bool {
	h := sha256.Sum256([]byte(providedPlain))
	providedHash := base64.RawURLEncoding.EncodeToString(h[:])
	// constant-time compare
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(providedHash)) == 1
}
