package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
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
