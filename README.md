

```md
# 🔐 Secure Cloud Vault

A secure web-based file vault built using **Java + Spring Boot**, implementing **AES–RSA hybrid encryption**, **time-locked access**, and **cloud deployment using Docker**.

---

## 🌐 Live Application

🔗 **Live Website**  
https://secure-cloudvault.onrender.com/login.html

---

## ⬇️ Download Page

🔗 **Download Interface**  
https://secure-cloudvault.onrender.com/download.html

> Any user with a valid **File ID** can download the file **after the unlock time**, similar to secure link-based sharing systems.

---

## 📌 Project Overview

Secure Cloud Vault allows users to upload files securely, lock them until a future time, and download them only after the unlock time.  
Files are encrypted before storage and decrypted only when access conditions are satisfied.

---

## ✨ Features

- 🔐 AES–RSA Hybrid Encryption  
- ⏳ Time-Locked File Access  
- 🆔 Unique File ID per upload  
- 🌐 Web-based Upload & Download  
- 🔑 Session-based Authentication (Upload)  
- ☁️ Cloud Deployment (Render + Docker)  

---

## 🔒 Security Model

| Layer | Description |
|------|------------|
| Encryption | AES for file data, RSA for key encryption |
| Time Lock | Enforced server-side using UTC |
| Access Control | File ID acts as a secure access token |
| Authentication | Required for upload |

---

## ⏱️ Time Handling

- User input assumed in **IST**
- Converted and stored in **UTC**
- Ensures correct behavior on cloud servers

---

## 🧪 How to Use

### Login
```

/login.html

```
Credentials:
```

Username: admin
Password: admin123

```

### Upload
```

/upload.html

```
- Select file
- Choose unlock time
- Receive File ID

### Download
```

/download.html

```
- Enter File ID
- Download allowed after unlock time

---

## ☁️ Deployment Details

- Platform: Render (Free Tier)
- Deployment Type: Docker
- Java Version: 17
- HTTPS Enabled

> Note: Free cloud tier uses ephemeral storage. Persistent storage is required for production use.

---

## 🛠️ Technologies Used

- Java 17
- Spring Boot
- AES / RSA Cryptography
- HTML / CSS
- Docker
- Render Cloud
- GitHub

---

## 📂 Source Code

🔗 **GitHub Repository**  
https://github.com/S-lokesh4432/Secure_cloudvault

---

## 🎓 Academic Note

This project demonstrates practical implementation of:
- Hybrid cryptography
- Time-based authorization
- Secure file sharing
- Cloud-native deployment challenges

---

## 👤 Author

**Sai Lokesh**  
Secure Cloud Vault – Academic Project
```


