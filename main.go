package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

type Entry struct {
	Site     string `json:"site"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type StoredData struct {
	Entries []Entry `json:"entries"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	hashFile := "masterHash.txt"
	dataFile := "passwords.json"
	var masterPassword string

	//mastar password setup
	_, err := os.Stat(hashFile)
	if os.IsNotExist(err) {
		// if file not exist
		setupMasterPassword(scanner, hashFile)
		fmt.Println("Master password set! Please restart the program.")
		return
	} else if err != nil {
		fmt.Println("Error checking master hash file:", err)
		return
	}

	// Verify the passqword
	masterPassword, verified := verifyMasterPasswordWithReturn(scanner, hashFile)
	if !verified {
		fmt.Println("Access denied. Exiting.")
		return
	}

	// If password verifesd
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
			addEntryUI(scanner, masterPassword, dataFile)
		case "2":
			getEntryUI(scanner, masterPassword, dataFile)
		case "3":
			deleteEntryUI(scanner, masterPassword, dataFile)
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

func verifyMasterPasswordWithReturn(scanner *bufio.Scanner, filename string) (string, bool) {
	hashed, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading password hash:", err)
		return "", false
	}

	for attempts := 0; attempts < 3; attempts++ {
		fmt.Print("Enter master password: ")
		var input string
		fmt.Scanln(&input)

		err := bcrypt.CompareHashAndPassword(hashed, []byte(input))
		if err == nil {
			fmt.Println("Access granted!")
			return input, true
		}
		fmt.Println("Incorrect password. Try again.")
	}
	return "", false
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("error generating nonce: %v", err)
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(encryptedData []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %v", err)
	}
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}
	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// loadEntries loads and decrypts entries from the password file
func loadEntries(masterPassword, filename string) ([]Entry, error) {
	// Generate salt and key
	salt := []byte("fixed-salt-32-bytes-for-demo")
	key := deriveKey(masterPassword, salt)

	// Check if file exists
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return []Entry{}, nil // Return empty list if file doesn't exist
		}
		return nil, err
	}

	// Decode from base64
	encryptedBytes, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	// Decrypt
	decryptedData, err := decrypt(encryptedBytes, key)
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON
	var stored StoredData
	err = json.Unmarshal(decryptedData, &stored)
	if err != nil {
		return nil, err
	}

	return stored.Entries, nil
}

// saveEntries encrypts and saves entries to the password file
func saveEntries(masterPassword, filename string, entries []Entry) error {
	// Generate salt and key
	salt := []byte("fixed-salt-32-bytes-for-demo")
	key := deriveKey(masterPassword, salt)

	// Marshal to JSON
	stored := StoredData{Entries: entries}
	jsonData, err := json.Marshal(stored)
	if err != nil {
		return err
	}

	// Encrypt
	encryptedBytes, err := encrypt(jsonData, key)
	if err != nil {
		return err
	}

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString(encryptedBytes)

	// Write to file
	err = os.WriteFile(filename, []byte(encoded), 0600)
	if err != nil {
		return err
	}

	return nil
}

// addEntryUI handles the UI for adding a new entry
func addEntryUI(scanner *bufio.Scanner, masterPassword, dataFile string) {
	fmt.Print("Enter site name: ")
	var site string
	fmt.Scanln(&site)

	fmt.Print("Enter username: ")
	var username string
	fmt.Scanln(&username)

	fmt.Print("Enter password: ")
	var password string
	fmt.Scanln(&password)

	// Load existing entries
	entries, err := loadEntries(masterPassword, dataFile)
	if err != nil {
		fmt.Println("Error loading entries:", err)
		return
	}

	// Add new entry
	newEntry := Entry{Site: site, Username: username, Password: password}
	entries = append(entries, newEntry)

	// Save entries
	err = saveEntries(masterPassword, dataFile, entries)
	if err != nil {
		fmt.Println("Error saving entry:", err)
		return
	}

	fmt.Println("Entry added successfully!")
}

// getEntryUI handles the UI for retrieving an entry
func getEntryUI(scanner *bufio.Scanner, masterPassword, dataFile string) {
	fmt.Print("Enter site name to retrieve: ")
	var site string
	fmt.Scanln(&site)

	// Load entries
	entries, err := loadEntries(masterPassword, dataFile)
	if err != nil {
		fmt.Println("Error loading entries:", err)
		return
	}

	// Find entry
	for _, entry := range entries {
		if entry.Site == site {
			fmt.Printf("Site: %s\n", entry.Site)
			fmt.Printf("Username: %s\n", entry.Username)
			fmt.Printf("Password: %s\n", entry.Password)
			return
		}
	}

	fmt.Println("Entry not found.")
}

// deleteEntryUI handles the UI for deleting an entry
func deleteEntryUI(scanner *bufio.Scanner, masterPassword, dataFile string) {
	fmt.Print("Enter site name to delete: ")
	var site string
	fmt.Scanln(&site)

	// Load entries
	entries, err := loadEntries(masterPassword, dataFile)
	if err != nil {
		fmt.Println("Error loading entries:", err)
		return
	}

	// Find and remove entry
	for i, entry := range entries {
		if entry.Site == site {
			entries = append(entries[:i], entries[i+1:]...)
			// Save updated entries
			err = saveEntries(masterPassword, dataFile, entries)
			if err != nil {
				fmt.Println("Error saving entries:", err)
				return
			}
			fmt.Println("Entry deleted successfully!")
			return
		}
	}

	fmt.Println("Entry not found.")
}
