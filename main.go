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
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

type Entry struct {
	Site         string    `json:"site"`
	Username     string    `json:"username"`
	Password     string    `json:"password"`
	LastModified time.Time `json:"last_modified"`
}

type StoredData struct {
	Entries    []Entry   `json:"entries"`
	LastBackup time.Time `json:"last_backup"`
	AppVersion string    `json:"version"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	hashFile := "masterHash.txt"
	dataFile := "passwords.json"
	var masterPassword string

	_, err := os.Stat(hashFile)
	if os.IsNotExist(err) {
		setupMasterPassword(scanner, hashFile)
		fmt.Println("Master password set! Please restart the program.")
		return
	} else if err != nil {
		fmt.Println("Error checking master hash file:", err)
		return
	}

	masterPassword, verified := verifyMasterPasswordWithReturn(scanner, hashFile)
	if !verified {
		fmt.Println("Access denied. Exiting.")
		return
	}

	for {
		fmt.Println("\n--- Password Manager Pro ---")
		fmt.Println("1. Add Entry")
		fmt.Println("2. Get Entry")
		fmt.Println("3. Update Entry")
		fmt.Println("4. Delete Entry")
		fmt.Println("5. Search Entries")
		fmt.Println("6. Generate Password")
		fmt.Println("7. List All Sites")
		fmt.Println("8. Backup Vault")
		fmt.Println("9. Exit")
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
			updateEntryUI(scanner, masterPassword, dataFile)
		case "4":
			deleteEntryUI(scanner, masterPassword, dataFile)
		case "5":
			searchEntriesUI(scanner, masterPassword, dataFile)
		case "6":
			generatePasswordUI()
		case "7":
			listAllSitesUI(masterPassword, dataFile)
		case "8":
			backupVault(dataFile)
		case "9":
			fmt.Println("Exiting... Goodbye!")
			return
		default:
			fmt.Println("Invalid choice, please enter 1-9")
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
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(encryptedData []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func loadEntries(masterPassword, filename string) ([]Entry, error) {
	salt := []byte("fixed-salt-32-bytes-for-demo-prod")
	key := deriveKey(masterPassword, salt)

	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return []Entry{}, nil
		}
		return nil, err
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	decryptedData, err := decrypt(encryptedBytes, key)
	if err != nil {
		return nil, err
	}

	var stored StoredData
	if err := json.Unmarshal(decryptedData, &stored); err != nil {
		return nil, err
	}

	return stored.Entries, nil
}

func saveEntries(masterPassword, filename string, entries []Entry) error {
	salt := []byte("fixed-salt-32-bytes-for-demo-prod")
	key := deriveKey(masterPassword, salt)

	stored := StoredData{
		Entries:    entries,
		LastBackup: time.Now(),
		AppVersion: "1.2.0",
	}
	jsonData, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}

	encryptedBytes, err := encrypt(jsonData, key)
	if err != nil {
		return err
	}

	encoded := base64.StdEncoding.EncodeToString(encryptedBytes)
	return os.WriteFile(filename, []byte(encoded), 0600)
}

func addEntryUI(scanner *bufio.Scanner, masterPassword, dataFile string) {
	fmt.Print("Site: ")
	var site string
	fmt.Scanln(&site)
	fmt.Print("Username: ")
	var user string
	fmt.Scanln(&user)
	fmt.Print("Password: ")
	var pass string
	fmt.Scanln(&pass)

	entries, _ := loadEntries(masterPassword, dataFile)
	entries = append(entries, Entry{Site: site, Username: user, Password: pass, LastModified: time.Now()})

	if err := saveEntries(masterPassword, dataFile, entries); err == nil {
		fmt.Println("Success!")
	}
}

func getEntryUI(scanner *bufio.Scanner, masterPassword, dataFile string) {
	fmt.Print("Site name: ")
	var site string
	fmt.Scanln(&site)

	entries, _ := loadEntries(masterPassword, dataFile)
	for _, e := range entries {
		if strings.EqualFold(e.Site, site) {
			fmt.Printf("\n[ %s ]\nUser: %s\nPass: %s\nModified: %s\n", e.Site, e.Username, e.Password, e.LastModified.Format("2006-01-02"))
			return
		}
	}
	fmt.Println("Not found.")
}

func updateEntryUI(scanner *bufio.Scanner, masterPassword, dataFile string) {
	fmt.Print("Site to update: ")
	var site string
	fmt.Scanln(&site)

	entries, _ := loadEntries(masterPassword, dataFile)
	found := false
	for i, e := range entries {
		if strings.EqualFold(e.Site, site) {
			fmt.Printf("New password for %s: ", e.Site)
			var newPass string
			fmt.Scanln(&newPass)
			entries[i].Password = newPass
			entries[i].LastModified = time.Now()
			found = true
			break
		}
	}

	if found {
		saveEntries(masterPassword, dataFile, entries)
		fmt.Println("Updated successfully.")
	} else {
		fmt.Println("Site not found.")
	}
}

func deleteEntryUI(scanner *bufio.Scanner, masterPassword, dataFile string) {
	fmt.Print("Site to delete: ")
	var site string
	fmt.Scanln(&site)

	entries, _ := loadEntries(masterPassword, dataFile)
	for i, e := range entries {
		if strings.EqualFold(e.Site, site) {
			entries = append(entries[:i], entries[i+1:]...)
			saveEntries(masterPassword, dataFile, entries)
			fmt.Println("Deleted.")
			return
		}
	}
}

func generatePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
	res := make([]byte, length)
	rand.Read(res)
	for i, b := range res {
		res[i] = charset[b%byte(len(charset))]
	}
	return string(res)
}

func generatePasswordUI() {
	fmt.Print("Length (8-64): ")
	var l int
	fmt.Scanln(&l)
	if l < 8 {
		l = 16
	}
	p := generatePassword(l)
	fmt.Printf("Generated: %s\nStrength: High\n", p)
}

func searchEntriesUI(scanner *bufio.Scanner, masterPassword, dataFile string) {
	fmt.Print("Keyword: ")
	scanner.Scan()
	q := strings.ToLower(scanner.Text())
	entries, _ := loadEntries(masterPassword, dataFile)
	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.Site), q) {
			fmt.Printf("- %s (User: %s)\n", e.Site, e.Username)
		}
	}
}

func listAllSitesUI(masterPassword, dataFile string) {
	entries, _ := loadEntries(masterPassword, dataFile)
	if len(entries) == 0 {
		fmt.Println("Vault empty.")
		return
	}
	fmt.Println("\nVault Inventory:")
	for i, e := range entries {
		fmt.Printf("[%d] %-15s | Last Updated: %s\n", i+1, e.Site, e.LastModified.Format("2006-01-02"))
	}
}

func backupVault(dataFile string) {
	src, _ := os.Open(dataFile)
	defer src.Close()
	dstName := fmt.Sprintf("backup_%d.json", time.Now().Unix())
	dst, _ := os.Create(dstName)
	defer dst.Close()
	io.Copy(dst, src)
	fmt.Printf("Backup saved to %s\n", dstName)
}
