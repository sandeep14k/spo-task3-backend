package helper

import (
	"auth/database"
	"auth/model"
	"context"
	"errors"
	"log"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var adminCollection *mongo.Collection = database.OpenCollection(database.Client, "user_data")

var SECRET_KEY string = os.Getenv("SECRET_KEY")
var jwtKey = []byte(SECRET_KEY)

func GenerateAllTokens(email string, uid string) (signedToken string, signedRefreshToken string, err error) {
	claims := &model.SignedUserDetails{
		Email: email,
		Uid:   uid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
		},
	}

	refreshClaims := &model.SignedUserDetails{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(168)).Unix(),
		},
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(SECRET_KEY))
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(SECRET_KEY))

	if err != nil {
		log.Panic(err)
		return
	}

	return token, refreshToken, err
}
func ValidateToken(signedToken string) (*model.SignedUserDetails, string) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&model.SignedUserDetails{},
		func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		},
	)
	if err != nil {
		return nil, err.Error()
	}
	claims, ok := token.Claims.(*model.SignedUserDetails)
	if !ok {
		return nil, errors.New("couldn't parse claims").Error()
	}
	if claims.ExpiresAt < time.Now().Local().Unix() {
		return nil, errors.New("token expired").Error()
	}
	return claims, ""
}
func UpdateUserTokens(signedToken string, signedRefreshToken string, userId string) {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	var updateObj primitive.D

	updateObj = append(updateObj, bson.E{"token", signedToken})
	updateObj = append(updateObj, bson.E{"refresh_token", signedRefreshToken})

	Updated_at, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	updateObj = append(updateObj, bson.E{"updated_at", Updated_at})

	upsert := true
	filter := bson.M{"user_id": userId}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}

	_, err := adminCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{"$set", updateObj},
		},
		&opt,
	)

	defer cancel()

	if err != nil {
		log.Panic(err)
		return
	}
	return
}
