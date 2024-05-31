package model

import (
	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type SignedUserDetails struct {
	Email string
	Uid   string
	jwt.StandardClaims
}
type User struct {
	ID        primitive.ObjectID `bson:"_id"`
	Password  *string            `json:"Password" validate:"required,min=6"`
	Email     *string            `json:"email" validate:"email,required"`
	User_id   string             `json:"user_id"`
	EmailHash string             `json:"emailhash"`
}
