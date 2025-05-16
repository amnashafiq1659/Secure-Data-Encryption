# 🔐 VaultGuard: Your Encrypted Data Locker

---

## 🚀 Overview

VaultGuard is a secure, multi-user encryption system built with Streamlit and Python. It allows users to create accounts, encrypt sensitive data using strong cryptographic techniques (PBKDF2 + Fernet), and safely store and retrieve it.

---

## 🚀 Features

* ✅ **User Registration and Login**
* 🔐 **Passphrase-based Encryption (PBKDF2 + Fernet)**
* 🧠 **Encrypted Data Storage and Retrieval**
* 🔄 **Login Attempt Protection**
* 📂 **Persistent Local Storage via JSON**
* 🎨 **Custom UI Styling with CSS**
* 📱 **Streamlit UI with Sidebar Navigation**

---

## 💠 Technologies Used

* Python 🐍
* Streamlit 📈
* Cryptography (PBKDF2HMAC, Fernet) 🔐
* JSON File Handling 📂
* Custom CSS 🎨

---

## 🔐 Security Details

* **Encryption**: Data is encrypted using Fernet (symmetric encryption).
* **Key Derivation**: Passwords/passphrases are turned into keys using PBKDF2HMAC with a random salt.
* **Salts & Keys**: Stored per-user to ensure unique encryption.
* **Brute-force Protection**: Login attempts are limited to 3 tries per session.

---

## 🌍 Live Demo

Check out the app here: https://secure-data-encryption-1659.streamlit.app/

---

## 🧑‍💻 Author

**Amna Shafiq**
[GitHub](https://github.com/amnashafiq1659) • [LinkedIn](https://www.linkedin.com/in/amna-shafiq-0a76b0312/)

---
