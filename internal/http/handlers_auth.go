package http

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/CaioDeoli/iam-kit/internal/auth"
	"github.com/CaioDeoli/iam-kit/internal/config"
	"github.com/CaioDeoli/iam-kit/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type MailSender interface {
	Send(to string, subject string, body string) error
}

type AuthHandlers struct {
	DB     *gorm.DB
	JWT    *auth.JWTMaker
	Cfg    *config.Config
	Mailer MailSender
}

// Dynamic DTOs (all optional, validated against DB config)
type registerDynamicDTO struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	PhoneNumber  string `json:"phone_number"`
	Username     string `json:"username"`
	CPF          string `json:"cpf"`
	CNPJ         string `json:"cnpj"`
	DateOfBirth  string `json:"date_of_birth"`
	Role         string `json:"role"`
	Provider     string `json:"provider"`
	ProviderUser string `json:"provider_user_id"`
}

type loginDynamicDTO struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	PhoneNumber string `json:"phone_number"`
	Username    string `json:"username"`
	CPF         string `json:"cpf"`
	CNPJ        string `json:"cnpj"`
	DateOfBirth string `json:"date_of_birth"`
}

type oauthLoginDTO struct {
	Provider     string `json:"provider"`         // required
	ProviderUser string `json:"provider_user_id"` // required
}

// Password recovery

type recoverDTO struct {
	Email       string `json:"email"`
	PhoneNumber string `json:"phone_number"`
}

func (h *AuthHandlers) PasswordRecover(c *gin.Context) {
	var req recoverDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
		return
	}
	// Normalize
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.PhoneNumber = digitsOnly(req.PhoneNumber)
	if req.Email == "" && req.PhoneNumber == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_identifier"})
		return
	}

	// Find user by email or phone
	var u models.User
	var err error
	if req.Email != "" {
		err = h.DB.Where("email = ?", req.Email).First(&u).Error
	} else {
		err = h.DB.Where("phone_number = ?", req.PhoneNumber).First(&u).Error
	}
	// Do not reveal existence. Continue flow only if user found.
	if err != nil {
		// Return generic OK
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
		return
	}

	// Generate reset token (plain + hashed)
	plain, hash, genErr := auth.GenerateRefreshToken()
	if genErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token_failed"})
		return
	}
	exp := time.Now().UTC().Add(time.Duration(h.Cfg.ResetTTLMins) * time.Minute)
	t := &models.PasswordResetToken{UserID: u.ID, TokenHash: hash, ExpiresAt: exp}
	if err := h.DB.Create(t).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}

	// Build link and either send email in prod or return debug link in non-prod
	link := fmt.Sprintf("%s/reset-password?token=%s", strings.TrimRight(h.Cfg.AppBaseURL, "/"), url.QueryEscape(plain))
	_ = h.DB.Create(&models.AuditLog{UserID: &u.ID, Action: "password_reset_request", IP: c.ClientIP(), Meta: link}).Error

	if strings.ToLower(h.Cfg.AppEnv) == "prod" && h.Mailer != nil && strings.TrimSpace(u.Email) != "" {
		_ = h.Mailer.Send(u.Email, "Password reset", "Use the link below to reset your password:\n\n"+link+"\n\nThis link expires at: "+exp.UTC().Format(time.RFC3339))
		c.JSON(http.StatusOK, gin.H{
			"status":    "ok",
			"expiresAt": exp,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":         "ok",
		"debugResetLink": link,
		"expiresAt":      exp,
	})
}

type passwordResetDTO struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (h *AuthHandlers) PasswordReset(c *gin.Context) {
	var req passwordResetDTO
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Token) == "" || strings.TrimSpace(req.NewPassword) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
		return
	}
	// Compute hash of provided token
	sum := sha256.Sum256([]byte(req.Token))
	providedHash := base64.RawURLEncoding.EncodeToString(sum[:])
	// Find token
	var prt models.PasswordResetToken
	if err := h.DB.Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", providedHash, time.Now().UTC()).
		Order("id DESC").First(&prt).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	// Load user
	var u models.User
	if err := h.DB.First(&u, prt.UserID).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	// Update password
	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash_failed"})
		return
	}
	u.PasswordHash = newHash
	if err := h.DB.Save(&u).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	now := time.Now().UTC()
	prt.UsedAt = &now
	_ = h.DB.Save(&prt)
	_ = h.DB.Create(&models.AuditLog{UserID: &u.ID, Action: "password_reset", IP: c.ClientIP()}).Error
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *AuthHandlers) Register(c *gin.Context) {
	var req registerDynamicDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
		return
	}

	// Normalize inputs
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Username = strings.TrimSpace(req.Username)
	req.PhoneNumber = digitsOnly(req.PhoneNumber)
	req.CPF = digitsOnly(req.CPF)
	req.CNPJ = digitsOnly(req.CNPJ)
	if req.Role == "" {
		req.Role = "customer"
	}

	// Load register config
	var regs []models.RegisterConfig
	if err := h.DB.Find(&regs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	required := make(map[string]bool)
	for _, r := range regs {
		if r.Required {
			required[r.FieldName] = true
		}
	}
	// Validate required fields
	if required["email"] && req.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_email"})
		return
	}
	if required["password"] && req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_password"})
		return
	}
	if required["phone_number"] && req.PhoneNumber == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_phone_number"})
		return
	}
	if required["username"] && req.Username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_username"})
		return
	}
	if required["cpf"] && req.CPF == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_cpf"})
		return
	}
	if required["cnpj"] && req.CNPJ == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_cnpj"})
		return
	}
	var dobPtr *time.Time
	if req.DateOfBirth != "" {
		parsed, err := parseDOB(req.DateOfBirth)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_date_of_birth"})
			return
		}
		dobPtr = &parsed
	}
	if required["date_of_birth"] && dobPtr == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_date_of_birth"})
		return
	}

	// Hash password if present or required; if not required and empty but creating user, set random secret hash
	passwordHash := ""
	if req.Password != "" {
		h, err := auth.HashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "hash_failed"})
			return
		}
		passwordHash = h
	} else {
		// If password isn't provided but required is false, set random hash to satisfy not-null constraint
		if !required["password"] {
			random := uuid.New().String()
			h, err := auth.HashPassword(random)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "hash_failed"})
				return
			}
			passwordHash = h
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing_password"})
			return
		}
	}

	u := &models.User{
		Email:           req.Email,
		PasswordHash:    passwordHash,
		IsEmailVerified: false,
	}
	if req.PhoneNumber != "" {
		u.PhoneNumber = &req.PhoneNumber
	}
	if req.Username != "" {
		u.Username = &req.Username
	}
	if req.CPF != "" {
		u.CPF = &req.CPF
	}
	if req.CNPJ != "" {
		u.CNPJ = &req.CNPJ
	}
	if dobPtr != nil {
		u.DateOfBirth = dobPtr
	}

	if err := h.DB.Create(u).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "user_conflict_or_db_error"})
		return
	}

	// attach default role
	var role models.Role
	if err := h.DB.Where("name = ?", req.Role).First(&role).Error; err == nil {
		_ = h.DB.Create(&models.UserRole{UserID: u.ID, RoleID: role.ID}).Error
	}

	// If OAuth provider supplied, link it
	if strings.TrimSpace(req.Provider) != "" || strings.TrimSpace(req.ProviderUser) != "" {
		if req.Provider == "" || req.ProviderUser == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_oauth_link"})
			return
		}
		link := &models.UserOAuthProvider{UserID: u.ID, Provider: strings.ToLower(req.Provider), ProviderUserID: req.ProviderUser}
		if err := h.DB.Create(link).Error; err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "oauth_link_conflict"})
			return
		}
	}

	// Audit
	_ = h.DB.Create(&models.AuditLog{UserID: &u.ID, Action: "register", IP: c.ClientIP()}).Error

	c.JSON(http.StatusCreated, gin.H{
		"user": gin.H{"uuid": u.UUID, "email": u.Email, "emailVerified": u.IsEmailVerified},
	})
}

func (h *AuthHandlers) Login(c *gin.Context) {
	var req loginDynamicDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
		return
	}

	// Normalize inputs
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Username = strings.TrimSpace(req.Username)
	req.PhoneNumber = digitsOnly(req.PhoneNumber)
	req.CPF = digitsOnly(req.CPF)
	req.CNPJ = digitsOnly(req.CNPJ)

	// Determine provided identifier fields
	provided := identifiersProvided(req.Email, req.PhoneNumber, req.Username, req.CPF, req.CNPJ)
	if len(provided) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_login_fields"})
		return
	}

	// Load login configs and find a matching combination
	var combos []models.LoginConfig
	if err := h.DB.Find(&combos).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}

	var matched *models.LoginConfig
	for i := range combos {
		cf := configFieldsSet(&combos[i])
		if equalStringSets(cf, provided) {
			// check required extras
			if combos[i].RequiresPassword && strings.TrimSpace(req.Password) == "" {
				continue
			}
			if combos[i].RequiresDateOfBirth && strings.TrimSpace(req.DateOfBirth) == "" {
				continue
			}
			matched = &combos[i]
			break
		}
	}
	if matched == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
		return
	}

	// Build query to fetch user
	q := h.DB.Model(&models.User{})
	if contains(provided, "email") {
		q = q.Where("email = ?", req.Email)
	}
	if contains(provided, "phone_number") {
		q = q.Where("phone_number = ?", req.PhoneNumber)
	}
	if contains(provided, "username") {
		q = q.Where("username = ?", req.Username)
	}
	if contains(provided, "cpf") {
		q = q.Where("cpf = ?", req.CPF)
	}
	if contains(provided, "cnpj") {
		q = q.Where("cnpj = ?", req.CNPJ)
	}
	var dob time.Time
	if matched.RequiresDateOfBirth {
		parsed, err := parseDOB(req.DateOfBirth)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
			return
		}
		dob = parsed
		q = q.Where("date_of_birth = ?", dob)
	}
	var u models.User
	if err := q.First(&u).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
		return
	}

	if matched.RequiresPassword {
		if !auth.CheckPassword(u.PasswordHash, req.Password) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
			return
		}
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

// OAuth endpoints
func (h *AuthHandlers) OAuthLogin(c *gin.Context) {
	var req oauthLoginDTO
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Provider) == "" || strings.TrimSpace(req.ProviderUser) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
		return
	}

	var link models.UserOAuthProvider
	if err := h.DB.Where("provider = ? AND provider_user_id = ?", strings.ToLower(req.Provider), req.ProviderUser).First(&link).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
		return
	}
	var u models.User
	if err := h.DB.First(&u, link.UserID).Error; err != nil {
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

	_ = h.DB.Create(&models.AuditLog{UserID: &u.ID, Action: "login_oauth", IP: c.ClientIP()}).Error

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  access,
		"accessExp":    accessExp.UTC(),
		"refreshToken": plainRefresh,
		"user":         gin.H{"uuid": u.UUID, "email": u.Email, "roles": roles},
	})
}

func (h *AuthHandlers) OAuthRegister(c *gin.Context) {
	var req registerDynamicDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
		return
	}
	if strings.TrimSpace(req.Provider) == "" || strings.TrimSpace(req.ProviderUser) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_oauth_link"})
		return
	}
	// Delegate to Register for field checks and creation; then link provider
	// We simulate by calling Register logic without responding, but to keep it simple, re-run the core steps

	// Normalize
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Username = strings.TrimSpace(req.Username)
	req.PhoneNumber = digitsOnly(req.PhoneNumber)
	req.CPF = digitsOnly(req.CPF)
	req.CNPJ = digitsOnly(req.CNPJ)
	if req.Role == "" {
		req.Role = "customer"
	}

	var regs []models.RegisterConfig
	if err := h.DB.Find(&regs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	required := make(map[string]bool)
	for _, r := range regs {
		if r.Required {
			required[r.FieldName] = true
		}
	}

	if required["email"] && req.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_email"})
		return
	}
	if required["password"] && req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_password"})
		return
	}
	if required["phone_number"] && req.PhoneNumber == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_phone_number"})
		return
	}
	if required["username"] && req.Username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_username"})
		return
	}
	if required["cpf"] && req.CPF == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_cpf"})
		return
	}
	if required["cnpj"] && req.CNPJ == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_cnpj"})
		return
	}
	var dobPtr *time.Time
	if req.DateOfBirth != "" {
		parsed, err := parseDOB(req.DateOfBirth)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_date_of_birth"})
			return
		}
		dobPtr = &parsed
	}
	if required["date_of_birth"] && dobPtr == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_date_of_birth"})
		return
	}

	passwordHash := ""
	if req.Password != "" {
		h, err := auth.HashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "hash_failed"})
			return
		}
		passwordHash = h
	} else if !required["password"] {
		random := uuid.New().String()
		h, err := auth.HashPassword(random)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "hash_failed"})
			return
		}
		passwordHash = h
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_password"})
		return
	}

	u := &models.User{Email: req.Email, PasswordHash: passwordHash}
	if req.PhoneNumber != "" {
		u.PhoneNumber = &req.PhoneNumber
	}
	if req.Username != "" {
		u.Username = &req.Username
	}
	if req.CPF != "" {
		u.CPF = &req.CPF
	}
	if req.CNPJ != "" {
		u.CNPJ = &req.CNPJ
	}
	if dobPtr != nil {
		u.DateOfBirth = dobPtr
	}

	if err := h.DB.Create(u).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "user_conflict_or_db_error"})
		return
	}

	var role models.Role
	if err := h.DB.Where("name = ?", req.Role).First(&role).Error; err == nil {
		_ = h.DB.Create(&models.UserRole{UserID: u.ID, RoleID: role.ID}).Error
	}

	link := &models.UserOAuthProvider{UserID: u.ID, Provider: strings.ToLower(req.Provider), ProviderUserID: req.ProviderUser}
	if err := h.DB.Create(link).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "oauth_link_conflict"})
		return
	}

	_ = h.DB.Create(&models.AuditLog{UserID: &u.ID, Action: "register_oauth", IP: c.ClientIP()}).Error

	c.JSON(http.StatusCreated, gin.H{"user": gin.H{"uuid": u.UUID, "email": u.Email, "emailVerified": u.IsEmailVerified}})
}

// Helpers
func digitsOnly(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	b := strings.Builder{}
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func parseDOB(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	// expect YYYY-MM-DD
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, err
	}
	// normalize to UTC midnight
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC), nil
}

func identifiersProvided(email, phone, username, cpf, cnpj string) []string {
	set := make([]string, 0, 3)
	if email != "" {
		set = append(set, "email")
	}
	if phone != "" {
		set = append(set, "phone_number")
	}
	if username != "" {
		set = append(set, "username")
	}
	if cpf != "" {
		set = append(set, "cpf")
	}
	if cnpj != "" {
		set = append(set, "cnpj")
	}
	sort.Strings(set)
	return set
}

func configFieldsSet(c *models.LoginConfig) []string {
	arr := []string{c.Field1}
	if c.Field2 != nil && *c.Field2 != "" {
		arr = append(arr, *c.Field2)
	}
	if c.Field3 != nil && *c.Field3 != "" {
		arr = append(arr, *c.Field3)
	}
	sort.Strings(arr)
	return arr
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(a []string, v string) bool {
	for _, x := range a {
		if x == v {
			return true
		}
	}
	return false
}
