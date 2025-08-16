package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID              uint   `gorm:"primaryKey"`
	UUID            string `gorm:"uniqueIndex;size:36"`
	Email           string `gorm:"uniqueIndex;size:255;not null"`
	PasswordHash    string `gorm:"size:255;not null"`
	IsEmailVerified bool   `gorm:"default:false"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       gorm.DeletedAt `gorm:"index"`
	UserRoles       []UserRole
}

func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	if u.UUID == "" {
		u.UUID = uuid.New().String()
	}
	return nil
}

type Role struct {
	ID        uint   `gorm:"primaryKey"`
	Name      string `gorm:"uniqueIndex;size:64;not null"` // e.g., "admin", "customer", "receptionist", "professional"
	CreatedAt time.Time
	UpdatedAt time.Time
}

type UserRole struct {
	ID        uint `gorm:"primaryKey"`
	UserID    uint `gorm:"index"`
	RoleID    uint `gorm:"index"`
	CreatedAt time.Time
}

type RefreshToken struct {
	ID           uint      `gorm:"primaryKey"`
	UserID       uint      `gorm:"index"`
	TokenHash    string    `gorm:"size:255;index"`
	ExpiresAt    time.Time `gorm:"index"`
	RevokedAt    *time.Time
	ReplacedByID *uint
	CreatedAt    time.Time
}

type AuditLog struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    *uint  `gorm:"index"`
	Action    string `gorm:"size:64;index"` // e.g., "login", "logout", "register", "password_reset_request"
	IP        string `gorm:"size:64"`
	Meta      string `gorm:"type:text"`
	CreatedAt time.Time
}

func SeedBaseRoles(db *gorm.DB) {
	base := []string{"admin", "customer", "receptionist", "professional"}
	for _, r := range base {
		db.FirstOrCreate(&Role{}, Role{Name: r})
	}
}
