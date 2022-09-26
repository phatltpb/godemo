package middleware

import (
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/phatltpb/golang_api/helper"
	"github.com/phatltpb/golang_api/service"
)

func AuthorizateJWT(jwtService service.JWTService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("authorization")
		if authHeader == "" {
			response := helper.BuildErrorResponse("failed to process request","no found token",nil)
			c.AbortWithStatusJSON(http.StatusUnauthorized,response)
			return
		}
		token,err := jwtService.ValidateToken(authHeader)
		if  token.Valid {
			Claims :=token.Claims.(jwt.MapClaims)
			log.Println("claim[user_id]:",Claims["user_id"])
			log.Println("claim[issuer]:",Claims["issuer"])
		}else{
			log.Println(err)
			response:= helper.BuildErrorResponse("Token is not valid",err.Error(), nil)
			c.AbortWithStatusJSON(http.StatusUnauthorized, response)
		}
	}
}