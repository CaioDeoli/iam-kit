package http

import (
	"time"

	"github.com/CaioDeoli/iam-kit/internal/auth"
	"github.com/CaioDeoli/iam-kit/internal/config"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func SetupRouter(cfg *config.Config, db *gorm.DB) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(RequestLogger())
	r.Use(SecurityHeaders())
	r.Use(cors.Default())
	r.Use(CORSMiddleware())

	jwt := auth.NewJWTMaker(cfg.JWTSecret, time.Duration(cfg.AccessTTLMin)*time.Minute, time.Duration(cfg.RefreshTTLH)*time.Hour)

	ah := &AuthHandlers{DB: db, JWT: jwt}
	uh := &UserHandlers{DB: db}

	r.GET("/healthz", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })

	v1 := r.Group("/v1")
	{
		authGroup := v1.Group("/auth")
		authGroup.POST("/register", ah.Register)
		authGroup.POST("/login", ah.Login)
		authGroup.POST("/refresh", ah.Refresh)
		authGroup.POST("/logout", ah.Logout)

		userGroup := v1.Group("/users")
		userGroup.Use(AuthMiddleware([]byte(cfg.JWTSecret)))
		userGroup.GET("/me", RequireAuth(), uh.Me)
		userGroup.GET("", RequireAuth(), RequireRoles("admin"), uh.List)
	}

	return r
}
