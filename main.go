package main

import (
	"bufio"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"os"
	"strings"
)

// Entry stores password info
type Entry struct {
	Site     string
	Username string
	Password string
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	hashFile := "masterHash.txt"

	// Check if master hash file exists
	_, err := os.Stat(hashFile)
	if os.IsNotExist(err) {
		// File does not exist, setup master password
		setupMasterPassword(scanner, hashFile)
		fmt.Println("Master password set! Please restart the program.")
		return
	} else if err != nil {
		fmt.Println("Error checking master hash file:", err)
		return
	}

	// Verify master password on subsequent runs
	if !verifyMasterPassword(scanner, hashFile) {
		fmt.Println("Access denied. Exiting.")
		return
	}

	// If password verified, continue to CLI menu
	for {
		fmt.Println("\nPassword Manager")
		fmt.Println("1. Add Entry")
		fmt.Println("2. Get Entry")
		fmt.Println("3. Delete Entry")
		fmt.Println("4. Exit")
		fmt.Print("Select an option: ")

		if !scanner.Scan() {
			break
		}

		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		case "1":
			fmt.Println("Add Entry selected (functionality coming soon)")
		case "2":
			fmt.Println("Get Entry selected (functionality coming soon)")
		case "3":
			fmt.Println("Delete Entry selected (functionality coming soon)")
		case "4":
			fmt.Println("Exiting... Goodbye!")
			return
		default:
			fmt.Println("Invalid choice, please enter 1-4")
		}
	}
}

func setupMasterPassword(scanner *bufio.Scanner, filename string) {
	fmt.Println("Create a Master Password:")
	fmt.Print("Enter password: ")
	var p1 string
	fmt.Scanln(&p1)
	fmt.Print("Re-enter password: ")
	var p2 string
	fmt.Scanln(&p2)

	if p1 != p2 {
		fmt.Println("Passwords do not match. Try again.")
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(p1), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Error hashing password:", err)
		return
	}

	err = os.WriteFile(filename, hashed, 0600)
	if err != nil {
		fmt.Println("Error saving password hash:", err)
		return
	}
}

func verifyMasterPassword(scanner *bufio.Scanner, filename string) bool {
	hashed, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading password hash:", err)
		return false
	}

	for attempts := 0; attempts < 3; attempts++ {
		fmt.Print("Enter master password: ")
		var input string
		fmt.Scanln(&input)

		err := bcrypt.CompareHashAndPassword(hashed, []byte(input))
		if err == nil {
			fmt.Println("Access granted!")
			return true
		}
		fmt.Println("Incorrect password. Try again.")
	}
	return false
}
