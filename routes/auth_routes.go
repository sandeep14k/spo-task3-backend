package routes

import (
	"auth/controller"
	"auth/middleware"

	"github.com/gin-gonic/gin"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("/signup", controller.Signup())
	incomingRoutes.POST("/login", controller.Login())
	incomingRoutes.Use(middleware.AuthenticateUser())
	incomingRoutes.Use(middleware.CheckUserTokenValid())
	incomingRoutes.GET("/home", controller.Home())
}
