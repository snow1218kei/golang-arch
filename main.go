package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type UserClaims struct {
		jwt.StandardClaims
		SessionID int64
}

func (u *UserClaims) Valid() error {
		if !u.VerifyExpiresAt(time.Now().Unix(), true) {
				return fmt.Errorf("Token has expired")
		}

		if u.SessionID == 0 {
				return fmt.Errorf("Invalid session ID")
		}
		return nil
}

var key = []byte{}

func main() {
		for i := 1; i <= 64; i++ {
				key = append(key, byte(i))
		}

		password := "123456"
		hashedPassword, err := hashPassword(password)
		if err != nil {
				panic(err)
		}

		err = comparePassword(password, hashedPassword)
		if err != nil {
				log.Fatalln("Not logged in")
		}
		fmt.Println("Logged in")
}

func hashPassword(password string) ([]byte, error) {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
				return nil, fmt.Errorf("Error while generationg bcrypt hash from password: %w", err)
		}
		return hashedPassword, nil
}

func comparePassword(password string, hashedPassword []byte) error {
		err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
		if err !=nil {
				return fmt.Errorf("Invalid password: %w", err)
		}
		return nil
}

func signMessage(msg []byte) ([]byte, error) {
		h := hmac.New(sha512.New, key)
		_, err := h.Write(msg)
		if err != nil {
				return nil, fmt.Errorf("Error in signMessage while hashing message: %w", err)
		}
		signature := h.Sum(nil)
		return signature, nil
}

func checkSig(msg, sig []byte) (bool, error) {
		newSig, err := signMessage(msg)
		if err != nil {
				return false, fmt.Errorf("Error in checkSig while getting signature of message: %w", err)
		}

	  same := hmac.Equal(newSig, sig)
		return same, nil
}

func createToken(c *UserClaims) (string, error) {
		t := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
		signedToken, err := t.SignedString(key)
		if err != nil {
				return "", fmt.Errorf("Error in createToken while signing token: %w", err)
		}
		return signedToken, nil
}

func parseToken(signedToken string) (*UserClaims, error) {
		t, err := jwt.ParseWithClaims(signedToken, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
				if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
						return nil, fmt.Errorf("Invalid signing algorithm")
				}

				return key, nil
		})
		if err != nil {
				return nil, fmt.Errorf("Error in parseToken while parsing token: %w", err)
		}

		if !t.Valid {
				return nil, fmt.Errorf("Error in parseToken, token is not valid: %w", err)
		}

		return t.Claims.(*UserClaims), nil
}
