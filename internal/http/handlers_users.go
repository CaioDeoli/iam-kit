package http

import (
	"net/http"
	"strings"

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

type adminUserUpdateDTO struct {
	Email       *string `json:"email"`
	PhoneNumber *string `json:"phone_number"`
	Username    *string `json:"username"`
	CPF         *string `json:"cpf"`
	CNPJ        *string `json:"cnpj"`
}

// AdminUpdate allows admins to update selected user identity fields by UUID
func (h *UserHandlers) AdminUpdate(c *gin.Context) {
	uid := strings.TrimSpace(c.Param("uuid"))
	if uid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_uuid"})
		return
	}

	var u models.User
	if err := h.DB.Where("uuid = ?", uid).First(&u).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}

	var req adminUserUpdateDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
		return
	}

	// Prepare updates and uniqueness checks
	if req.Email != nil {
		email := strings.ToLower(strings.TrimSpace(*req.Email))
		if email == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_email"})
			return
		}
		// conflict check
		var cnt int64
		h.DB.Model(&models.User{}).Where("email = ? AND id <> ?", email, u.ID).Count(&cnt)
		if cnt > 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "email_conflict"})
			return
		}
		u.Email = email
	}

	if req.PhoneNumber != nil {
		v := digitsOnly(*req.PhoneNumber)
		if v == "" {
			u.PhoneNumber = nil
		} else {
			var cnt int64
			h.DB.Model(&models.User{}).Where("phone_number = ? AND id <> ?", v, u.ID).Count(&cnt)
			if cnt > 0 {
				c.JSON(http.StatusConflict, gin.H{"error": "phone_conflict"})
				return
			}
			u.PhoneNumber = &v
		}
	}

	if req.Username != nil {
		v := strings.TrimSpace(*req.Username)
		if v == "" {
			u.Username = nil
		} else {
			var cnt int64
			h.DB.Model(&models.User{}).Where("username = ? AND id <> ?", v, u.ID).Count(&cnt)
			if cnt > 0 {
				c.JSON(http.StatusConflict, gin.H{"error": "username_conflict"})
				return
			}
			u.Username = &v
		}
	}

	if req.CPF != nil {
		v := digitsOnly(*req.CPF)
		if v == "" {
			u.CPF = nil
		} else {
			var cnt int64
			h.DB.Model(&models.User{}).Where("cpf = ? AND id <> ?", v, u.ID).Count(&cnt)
			if cnt > 0 {
				c.JSON(http.StatusConflict, gin.H{"error": "cpf_conflict"})
				return
			}
			u.CPF = &v
		}
	}

	if req.CNPJ != nil {
		v := digitsOnly(*req.CNPJ)
		if v == "" {
			u.CNPJ = nil
		} else {
			var cnt int64
			h.DB.Model(&models.User{}).Where("cnpj = ? AND id <> ?", v, u.ID).Count(&cnt)
			if cnt > 0 {
				c.JSON(http.StatusConflict, gin.H{"error": "cnpj_conflict"})
				return
			}
			u.CNPJ = &v
		}
	}

	if err := h.DB.Save(&u).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"uuid":          u.UUID,
			"email":         u.Email,
			"phone_number":  u.PhoneNumber,
			"username":      u.Username,
			"cpf":           u.CPF,
			"cnpj":          u.CNPJ,
			"emailVerified": u.IsEmailVerified,
		},
	})
}
