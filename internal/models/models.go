package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID              uint       `gorm:"primaryKey"`
	UUID            string     `gorm:"uniqueIndex;size:36"`
	Email           string     `gorm:"uniqueIndex;size:255;not null"`
	PasswordHash    string     `gorm:"size:255;not null"`
	PhoneNumber     *string    `gorm:"uniqueIndex;size:32"`
	Username        *string    `gorm:"uniqueIndex;size:64"`
	CPF             *string    `gorm:"uniqueIndex;size:14"`
	CNPJ            *string    `gorm:"uniqueIndex;size:18"`
	DateOfBirth     *time.Time `gorm:"index"`
	IsEmailVerified bool       `gorm:"default:false"`
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

type PasswordResetToken struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    uint      `gorm:"index"`
	TokenHash string    `gorm:"size:255;index"`
	ExpiresAt time.Time `gorm:"index"`
	UsedAt    *time.Time
	CreatedAt time.Time
}

type AuditLog struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    *uint  `gorm:"index"`
	Action    string `gorm:"size:64;index"` // e.g., "login", "logout", "register", "password_reset_request"
	IP        string `gorm:"size:64"`
	Meta      string `gorm:"type:text"`
	CreatedAt time.Time
}

type LoginConfig struct {
	ID                  uint    `gorm:"primaryKey"`
	Field1              string  `gorm:"size:50;not null;uniqueIndex:uniq_login_combo"`
	Field2              *string `gorm:"size:50;uniqueIndex:uniq_login_combo"`
	Field3              *string `gorm:"size:50;uniqueIndex:uniq_login_combo"`
	RequiresPassword    bool    `gorm:"not null;default:true;uniqueIndex:uniq_login_combo"`
	RequiresDateOfBirth bool    `gorm:"not null;default:false;uniqueIndex:uniq_login_combo"`
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

func (LoginConfig) TableName() string { return "login_config" }

type RegisterConfig struct {
	ID        uint   `gorm:"primaryKey"`
	FieldName string `gorm:"size:50;not null;uniqueIndex"`
	Required  bool   `gorm:"not null;default:true"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (RegisterConfig) TableName() string { return "register_config" }

type UserOAuthProvider struct {
	ID             uint   `gorm:"primaryKey"`
	UserID         uint   `gorm:"not null;uniqueIndex:uniq_user_provider"`
	Provider       string `gorm:"size:32;not null;uniqueIndex:uniq_user_provider;uniqueIndex:uniq_provider_user"`
	ProviderUserID string `gorm:"size:128;not null;uniqueIndex:uniq_provider_user"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (UserOAuthProvider) TableName() string { return "user_oauth_providers" }

func SeedBaseRoles(db *gorm.DB) {
	base := []string{"admin", "customer", "receptionist", "professional"}
	for _, r := range base {
		db.FirstOrCreate(&Role{}, Role{Name: r})
	}
}

func SeedDefaultAuthConfig(db *gorm.DB) {
	var count int64
	db.Model(&LoginConfig{}).Count(&count)
	if count == 0 {
		sp := func(s string) *string { return &s }
		combos := []LoginConfig{
			// field + password
			{Field1: "email", RequiresPassword: true},
			{Field1: "phone_number", RequiresPassword: true},
			{Field1: "username", RequiresPassword: true},
			{Field1: "cpf", RequiresPassword: true},
			{Field1: "cnpj", RequiresPassword: true},

			// 2 fields (no password)
			{Field1: "email", Field2: sp("phone_number"), RequiresPassword: false},
			{Field1: "email", Field2: sp("username"), RequiresPassword: false},
			{Field1: "email", Field2: sp("cpf"), RequiresPassword: false},
			{Field1: "email", Field2: sp("cnpj"), RequiresPassword: false},
			{Field1: "phone_number", Field2: sp("username"), RequiresPassword: false},
			{Field1: "phone_number", Field2: sp("cpf"), RequiresPassword: false},
			{Field1: "phone_number", Field2: sp("cnpj"), RequiresPassword: false},
			{Field1: "username", Field2: sp("cpf"), RequiresPassword: false},
			{Field1: "username", Field2: sp("cnpj"), RequiresPassword: false},
			{Field1: "cpf", Field2: sp("cnpj"), RequiresPassword: false},

			// field + date_of_birth (no password)
			{Field1: "email", RequiresPassword: false, RequiresDateOfBirth: true},
			{Field1: "phone_number", RequiresPassword: false, RequiresDateOfBirth: true},
			{Field1: "username", RequiresPassword: false, RequiresDateOfBirth: true},
			{Field1: "cpf", RequiresPassword: false, RequiresDateOfBirth: true},
			{Field1: "cnpj", RequiresPassword: false, RequiresDateOfBirth: true},

			// 2 fields + date_of_birth (no password)
			{Field1: "email", Field2: sp("phone_number"), RequiresPassword: false, RequiresDateOfBirth: true},
			{Field1: "email", Field2: sp("username"), RequiresPassword: false, RequiresDateOfBirth: true},
			{Field1: "email", Field2: sp("cpf"), RequiresPassword: false, RequiresDateOfBirth: true},
			{Field1: "email", Field2: sp("cnpj"), RequiresPassword: false, RequiresDateOfBirth: true},
			{Field1: "phone_number", Field2: sp("username"), RequiresPassword: false, RequiresDateOfBirth: true},
			{Field1: "phone_number", Field2: sp("cpf"), RequiresPassword: false, RequiresDateOfBirth: true},
			{Field1: "phone_number", Field2: sp("cnpj"), RequiresPassword: false, RequiresDateOfBirth: true},
			{Field1: "username", Field2: sp("cpf"), RequiresPassword: false, RequiresDateOfBirth: true},
			{Field1: "username", Field2: sp("cnpj"), RequiresPassword: false, RequiresDateOfBirth: true},
			{Field1: "cpf", Field2: sp("cnpj"), RequiresPassword: false, RequiresDateOfBirth: true},

			// only 1 field (no password)
			{Field1: "email", RequiresPassword: false},
			{Field1: "phone_number", RequiresPassword: false},
			{Field1: "username", RequiresPassword: false},
			{Field1: "cpf", RequiresPassword: false},
			{Field1: "cnpj", RequiresPassword: false},
		}
		for _, c := range combos {
			db.FirstOrCreate(&LoginConfig{}, c)
		}
	}

	db.Model(&RegisterConfig{}).Count(&count)
	if count == 0 {
		fields := []RegisterConfig{
			{FieldName: "email", Required: true},
			{FieldName: "password", Required: true},
			{FieldName: "phone_number", Required: false},
			{FieldName: "username", Required: false},
			{FieldName: "cpf", Required: false},
			{FieldName: "cnpj", Required: false},
			{FieldName: "date_of_birth", Required: false},
		}
		for _, f := range fields {
			db.Where(RegisterConfig{FieldName: f.FieldName}).
				Attrs(RegisterConfig{Required: f.Required}).
				FirstOrCreate(&RegisterConfig{})
		}
	}
}
