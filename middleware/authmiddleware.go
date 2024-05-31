package middleware

import (
	"auth/database"
	"auth/helper"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var adminCollection *mongo.Collection = database.OpenCollection(database.Client, "user_data")

func AuthenticateUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientToken := c.Request.Header.Get("token")
		if clientToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No Authorization header provided"})
			c.Abort()
			return
		}
		fmt.Println("Admin token received:", clientToken)
		claims, err := helper.ValidateToken(clientToken)
		if err != "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err})
			c.Abort()
			return
		}
		c.Set("email", claims.Email)
		c.Set("uid", claims.Uid)
		c.Next()
	}
}

func CheckUserTokenValid() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		uid, ok := ctx.Get("uid")
		if !ok {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "the token is invalid"})
			ctx.Abort()
			return
		}
		fmt.Println("Admin UID from token:", uid)
		c, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		count, err := adminCollection.CountDocuments(c, bson.M{"user_id": uid})

		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			ctx.Abort()
			return
		}
		if count < 1 {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "user with this token does not exist"})
			ctx.Abort()
			return
		}
		ctx.Next()
	}
}
