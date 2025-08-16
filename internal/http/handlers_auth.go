package http

import (
	"net/http"
	"strings"
	"time"

	"github.com/CaioDeoli/iam-kit/internal/auth"
	"github.com/CaioDeoli/iam-kit/internal/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AuthHandlers struct {
	DB  *gorm.DB
	JWT *auth.JWTMaker
}

// DTOs
type registerDTO struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	Role     string `json:"role"` // optional: default "customer"
}

type loginDTO struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandlers) Register(c *gin.Context) {
	var req registerDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Role == "" {
		req.Role = "customer"
	}

	var exists int64
	h.DB.Model(&models.User{}).Where("email = ?", req.Email).Count(&exists)
	if exists > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "email_in_use"})
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash_failed"})
		return
	}
	u := &models.User{
		Email:        req.Email,
		PasswordHash: hash,
	}
	if err := h.DB.Create(u).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	// attach default role
	var role models.Role
	if err := h.DB.Where("name = ?", req.Role).First(&role).Error; err == nil {
		_ = h.DB.Create(&models.UserRole{UserID: u.ID, RoleID: role.ID}).Error
	}

	// Audit
	_ = h.DB.Create(&models.AuditLog{UserID: &u.ID, Action: "register", IP: c.ClientIP()}).Error

	c.JSON(http.StatusCreated, gin.H{
		"user": gin.H{"uuid": u.UUID, "email": u.Email, "emailVerified": u.IsEmailVerified},
	})
}

func (h *AuthHandlers) Login(c *gin.Context) {
	var req loginDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	var u models.User
	if err := h.DB.Where("email = ?", req.Email).First(&u).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
		return
	}
	if !auth.CheckPassword(u.PasswordHash, req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
		return
	}

	// fetch roles
	var roles []string
	h.DB.Table("roles").
		Select("roles.name").
		Joins("JOIN user_roles ur ON ur.role_id = roles.id").
		Where("ur.user_id = ?", u.ID).
		Scan(&roles)

	access, accessExp, err := h.JWT.CreateAccessToken(u.ID, roles)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token_failed"})
		return
	}
	plainRefresh, refreshHash, err := auth.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token_failed"})
		return
	}
	rt := &models.RefreshToken{
		UserID:    u.ID,
		TokenHash: refreshHash,
		ExpiresAt: time.Now().UTC().Add(h.JWT.RefreshTTL),
	}
	if err := h.DB.Create(rt).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}

	_ = h.DB.Create(&models.AuditLog{UserID: &u.ID, Action: "login", IP: c.ClientIP()}).Error

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  access,
		"accessExp":    accessExp.UTC(),
		"refreshToken": plainRefresh,
		"user":         gin.H{"uuid": u.UUID, "email": u.Email, "roles": roles},
	})
}

type refreshDTO struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

func (h *AuthHandlers) Refresh(c *gin.Context) {
	var req refreshDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
		return
	}

	var rt models.RefreshToken
	if err := h.DB.Where("revoked_at IS NULL AND expires_at > ?",
		time.Now().UTC()).First(&rt).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	if !auth.VerifyRefreshTokenHash(rt.TokenHash, req.RefreshToken) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	// rotate: revoke old and issue new
	now := time.Now().UTC()
	rt.RevokedAt = &now
	if err := h.DB.Save(&rt).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}

	var u models.User
	if err := h.DB.First(&u, rt.UserID).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	var roles []string
	h.DB.Table("roles").
		Select("roles.name").
		Joins("JOIN user_roles ur ON ur.role_id = roles.id").
		Where("ur.user_id = ?", u.ID).
		Scan(&roles)

	access, accessExp, err := h.JWT.CreateAccessToken(u.ID, roles)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token_failed"})
		return
	}
	plainRefresh, refreshHash, err := auth.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token_failed"})
		return
	}
	newRT := &models.RefreshToken{
		UserID:    u.ID,
		TokenHash: refreshHash,
		ExpiresAt: time.Now().UTC().Add(h.JWT.RefreshTTL),
	}
	if err := h.DB.Create(newRT).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	rt.ReplacedByID = &newRT.ID
	_ = h.DB.Save(&rt).Error

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  access,
		"accessExp":    accessExp.UTC(),
		"refreshToken": plainRefresh,
	})
}

func (h *AuthHandlers) Logout(c *gin.Context) {
	var req refreshDTO
	if err := c.ShouldBindJSON(&req); err == nil && req.RefreshToken != "" {
		// best-effort revoke provided refresh token
		var rt models.RefreshToken
		if err := h.DB.Where("expires_at > ? AND revoked_at IS NULL", time.Now().UTC()).
			Order("id DESC").First(&rt).Error; err == nil {
			if auth.VerifyRefreshTokenHash(rt.TokenHash, req.RefreshToken) {
				now := time.Now().UTC()
				rt.RevokedAt = &now
				_ = h.DB.Save(&rt)
			}
		}
	}
	_ = h.DB.Create(&models.AuditLog{Action: "logout", IP: c.ClientIP()}).Error
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
