#Password-Manager-Pro
---
A secure, command-line based vault written in Go for managing your digital credentials. This application uses industry-standared encryption and hashing algorithms to ensure your data remanins private and protected.
---

###Security Features
-Master Password Hashing: Uses `bcrypt` to securely store hash of your master password.

-Key Derivation: This tool uses `argon2id` (the winner ofthe password hashing compedition ) to derrive a strong encryption key from your master password.

-Vault Encryption: Uses AES-256-GCM(Advance Encryption Standard with Galois/Counter Mode) to provide both convidentility and intregated (authenticated encryption).

-Randomness: uses `crypto/rand` for generation nouncs ands ecure passwords.

---
#Installation

Go to the releases section to install
*Make sure to choose for your specific os*

