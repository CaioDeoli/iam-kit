package http

import (
	"net/http"

	"github.com/CaioDeoli/iam-kit/internal/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type DebugHandlers struct {
	DB *gorm.DB
}

func (h *DebugHandlers) LoginConfigs(c *gin.Context) {
	var items []models.LoginConfig
	if err := h.DB.Limit(500).Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *DebugHandlers) RegisterConfigs(c *gin.Context) {
	var items []models.RegisterConfig
	if err := h.DB.Limit(500).Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *DebugHandlers) OAuthProviders(c *gin.Context) {
	var items []models.UserOAuthProvider
	if err := h.DB.Limit(500).Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *DebugHandlers) Users(c *gin.Context) {
	type outUser struct {
		ID          uint    `json:"id"`
		UUID        string  `json:"uuid"`
		Email       string  `json:"email"`
		PhoneNumber *string `json:"phone_number"`
		Username    *string `json:"username"`
		CPF         *string `json:"cpf"`
		CNPJ        *string `json:"cnpj"`
	}
	var users []models.User
	if err := h.DB.Limit(200).Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	resp := make([]outUser, 0, len(users))
	for _, u := range users {
		resp = append(resp, outUser{ID: u.ID, UUID: u.UUID, Email: u.Email, PhoneNumber: u.PhoneNumber, Username: u.Username, CPF: u.CPF, CNPJ: u.CNPJ})
	}
	c.JSON(http.StatusOK, gin.H{"items": resp})
}

func (h *DebugHandlers) Roles(c *gin.Context) {
	var items []models.Role
	if err := h.DB.Limit(200).Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *DebugHandlers) UserRoles(c *gin.Context) {
	var items []models.UserRole
	if err := h.DB.Limit(500).Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}
