package middleware

import (
	"a21hc3NpZ25tZW50/model"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie("session_token")
		if err != nil {
			if c.GetHeader("Content-Type") == "application/json" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			} else {
				c.Redirect(http.StatusSeeOther, "/login")
			}
			return
		}

		token, err := jwt.ParseWithClaims(cookie, &model.Claims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(model.JwtKey), nil // Ganti dengan secret key yang sesuai
		})
		if err != nil {
			// Parsing token gagal, kembalikan respon HTTP dengan status code 401 atau 400
			if err == jwt.ErrSignatureInvalid {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			} else {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Bad Request"})
			}
			return
		}

		if !token.Valid {
			// Token tidak valid, kembalikan respon HTTP dengan status code 401
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
			}

		if claims, ok := token.Claims.(*model.Claims); ok && token.Valid {
			c.Set("email", claims.Email)
		}

		c.Next()
	}
}
