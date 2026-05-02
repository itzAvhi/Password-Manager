# Password-Manager-Pro
---
A secure, command-line based vault written in Go for managing your digital credentials. This application uses industry-standared encryption and hashing algorithms to ensure your data remanins private and protected.
---

### Security Features
- Master Password Hashing: Uses `bcrypt` to securely store hash of your master password.

- Key Derivation: This tool uses `argon2id` (the winner ofthe password hashing compedition ) to derrive a strong encryption key from your master password.

- Vault Encryption: Uses AES-256-GCM(Advance Encryption Standard with Galois/Counter Mode) to provide both convidentility and intregated (authenticated encryption).

- Randomness: uses `crypto/rand` for generation nouncs ands ecure passwords.

---
## Installation & Setup (from Releases)

Since this is a standalone tool, you do not need to install Go or any external libraries.

### 1. Download the App
1. Go to the [Releases](../../releases) page of this repository.
2. Under the **Assets** section of the latest version, download the file for your system:
   - **Windows:** `passmanager.exe`
   - **Linux/macOS:** `passmanager`

### 2. Create a Vault Folder
The app creates security files in its own directory. To keep things clean:
1. Create a new folder (e.g., `MyPasswordVault`).
2. Move the downloaded binary into that folder.

### 3. Run and Authorize
#### **Windows**
* Double-click `passmanager.exe`.
* If prompted by Windows SmartScreen, click **More info** -> **Run anyway**.

#### **macOS / Linux**
1. Open your **Terminal**.
2. Navigate to your folder: `cd path/to/MyPasswordVault`
3. Make it executable: `chmod +x passmanager`
4. Run it: `./passmanager`
   * *Note: On macOS, you may need to go to System Settings > Privacy & Security to "Allow Anyway" if the developer is unverified.*

---

*For reviewers: Hey! i'm Avhi. Acctually i created this repository 3 months ago and spent 2 hours coding i didnt participate for any ysws at that time and after 3 months(currently) i continued this project. Its your choice that you want to me those 2 hours or deduct it. Thanks!*
