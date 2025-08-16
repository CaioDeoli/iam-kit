package http

import (
	"net/http"

	"github.com/CaioDeoli/iam-kit/internal/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type UserHandlers struct {
	DB *gorm.DB
}

func (h *UserHandlers) Me(c *gin.Context) {
	val, _ := c.Get("auth")
	auth := val.(*AuthContext)
	var u models.User
	if err := h.DB.First(&u, auth.UserID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}
	var roles []string
	h.DB.Table("roles").
		Select("roles.name").
		Joins("JOIN user_roles ur ON ur.role_id = roles.id").
		Where("ur.user_id = ?", u.ID).
		Scan(&roles)
	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"uuid":          u.UUID,
			"email":         u.Email,
			"emailVerified": u.IsEmailVerified,
			"roles":         roles,
		},
	})
}

func (h *UserHandlers) List(c *gin.Context) {
	var users []models.User
	if err := h.DB.Limit(100).Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	out := make([]gin.H, 0, len(users))
	for _, u := range users {
		out = append(out, gin.H{"uuid": u.UUID, "email": u.Email, "emailVerified": u.IsEmailVerified})
	}
	c.JSON(http.StatusOK, gin.H{"items": out})
}
