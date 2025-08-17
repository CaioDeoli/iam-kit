package http

import (
	"time"

	"github.com/CaioDeoli/iam-kit/internal/auth"
	"github.com/CaioDeoli/iam-kit/internal/config"
	"github.com/CaioDeoli/iam-kit/internal/mailer"

	// "github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func SetupRouter(cfg *config.Config, db *gorm.DB) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(RequestLogger())
	r.Use(SecurityHeaders())
	// r.Use(cors.Default())
	r.Use(CORSMiddleware())

	jwt := auth.NewJWTMaker(cfg.JWTSecret, time.Duration(cfg.AccessTTLMin)*time.Minute, time.Duration(cfg.RefreshTTLH)*time.Hour)

	ah := &AuthHandlers{DB: db, JWT: jwt, Cfg: cfg}
	uh := &UserHandlers{DB: db}
	dh := &DebugHandlers{DB: db}

	// Initialize SMTP mailer when configured
	if cfg.SMTPHost != "" {
		ah.Mailer = &mailer.SMTPMailer{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			Username: cfg.SMTPUser,
			Password: cfg.SMTPPass,
			From:     cfg.SMTPUser,
		}
	}

	r.GET("/healthz", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })

	v1 := r.Group("/v1")
	{
		authGroup := v1.Group("/auth")
		authGroup.POST("/register", ah.Register)
		authGroup.POST("/login", ah.Login)
		authGroup.POST("/login/oauth", ah.OAuthLogin)
		authGroup.POST("/register/oauth", ah.OAuthRegister)
		authGroup.POST("/refresh", ah.Refresh)
		authGroup.POST("/logout", ah.Logout)
		// password recovery
		authGroup.POST("/password/recover", ah.PasswordRecover)
		// password reset confirmation
		authGroup.POST("/password/reset", ah.PasswordReset)

		userGroup := v1.Group("/users")
		userGroup.Use(AuthMiddleware([]byte(cfg.JWTSecret)))
		userGroup.GET("/me", RequireAuth(), uh.Me)
		userGroup.GET("", RequireAuth(), RequireRoles("admin"), uh.List)
		userGroup.PATCH(":uuid", RequireAuth(), RequireRoles("admin"), uh.AdminUpdate)

		debugGroup := v1.Group("/debug")
		{
			debugGroup.GET("/login-configs", dh.LoginConfigs)
			debugGroup.GET("/register-configs", dh.RegisterConfigs)
			debugGroup.GET("/oauth-providers", dh.OAuthProviders)
			debugGroup.GET("/users", dh.Users)
			debugGroup.GET("/roles", dh.Roles)
			debugGroup.GET("/user-roles", dh.UserRoles)
		}
	}

	return r
}
