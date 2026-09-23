package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("--- DevVault Runtime Injection Test ---")

	apiKey := os.Getenv("API_KEY")
	if apiKey != "" {
		fmt.Println("API_KEY:     PRESENT (Decrypted & Injected)")
	} else {
		fmt.Println("API_KEY:     ABSENT")
	}

	dbPass := os.Getenv("DB_PASSWORD")
	if dbPass != "" {
		fmt.Println("DB_PASSWORD: PRESENT (Decrypted & Injected)")
	} else {
		fmt.Println("DB_PASSWORD: ABSENT")
	}

	fmt.Println("---------------------------------------")
}
