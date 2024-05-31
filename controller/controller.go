package controller

import (
	"auth/database"
	"auth/encryption"
	"auth/helper"
	"auth/model"
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user_data")
var validate = validator.New()

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}
func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = fmt.Sprintf("email of password is incorrect")
		check = false
	}
	return check, msg
}
func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user model.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}

		// Hash the email for checking uniqueness
		hashedEmail := encryption.Hash(*user.Email)

		count, err := userCollection.CountDocuments(ctx, bson.M{"emailhash": hashedEmail})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while checking for the email"})
			return
		}

		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email already exists"})
			return
		}

		password := HashPassword(*user.Password)
		user.Password = &password

		// Encrypt the email before storing
		encryptedEmail, err := encryption.Encrypt(*user.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while encrypting the email"})
			return
		}
		user.Email = &encryptedEmail
		user.EmailHash = hashedEmail // store the hash for uniqueness check

		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()
		token, refreshToken, _ := helper.GenerateAllTokens(*user.Email, user.User_id)

		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := "User item was not created"
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		fmt.Printf("resultInsertionNumber =%v", resultInsertionNumber)
		c.JSON(http.StatusOK, gin.H{"token": token, "refreshtoken": refreshToken})
	}
}
func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user model.User
		var foundUser model.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Hash the email for lookup
		hashedEmail := encryption.Hash(*user.Email)

		err := userCollection.FindOne(ctx, bson.M{"emailhash": hashedEmail}).Decode(&foundUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "email or password is incorrect"})
			return
		}

		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		if !passwordIsValid {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
			return
		}

		// Decrypt the email for token generation
		decryptedEmail, err := encryption.Decrypt(*foundUser.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while decrypting the email"})
			return
		}

		token, refreshToken, _ := helper.GenerateAllTokens(decryptedEmail, foundUser.User_id)
		err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		fmt.Printf("%v", foundUser)
		c.JSON(http.StatusOK, gin.H{"token": token, "refreshtoken": refreshToken})
	}
}
func Home() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"msg": "welcome to Home page"})
	}

}
