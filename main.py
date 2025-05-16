import streamlit as st
import json
import time
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# -------------------- Streamlit Configuration -------------------- #
st.set_page_config(page_title="VaultGuard", page_icon="🔐", layout="wide")

# -------------------- CSS -------------------- #

with open("style.css") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# -------------------- Data Handling -------------------- #

data_storage = {"users": {}}


def load_data():
    global data_storage
    try:
        with open("data.json", "r") as f:
            data_storage = json.load(f)
    except FileNotFoundError:
        save_data()


def save_data():
    with open("data.json", "w") as f:
        json.dump(data_storage, f, indent=4)


# -------------------- Encryption Logic -------------------- #


def generate_key_pbkdf2(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def encrypt_data(data, passphrase):
    salt = os.urandom(16)
    key = generate_key_pbkdf2(passphrase, salt)
    encrypted_text = Fernet(key).encrypt(data.encode()).decode()
    return encrypted_text, base64.b64encode(salt).decode()


def decrypt_data(encrypted_data, passphrase, salt_str):
    salt = base64.b64decode(salt_str)
    key = generate_key_pbkdf2(passphrase, salt)
    return Fernet(key).decrypt(encrypted_data.encode()).decode()


# -------------------- Page Functions -------------------- #


def home_page():
    st.title("🔐 Welcome to VaultGuard: Your Encrypted Data Locker")
    st.subheader("🔎 Description:")
    st.write(
        "Securely encrypt, store, and retrieve your private data with military-grade protection."
    )
    st.subheader("🛠️ Features:")
    st.write(" • Set up and manage your secure user account")
    st.write(" • Encrypt and save confidential information securely")
    st.write(" • Safely decrypt and view your stored data")
    st.write(" • Brute-force protection with limited login attempts")
    st.markdown("---")
    st.write("Select an option from the sidebar to get started.")


def signup_page():
    st.header("📝 Create a New Secure Account")
    username = st.text_input("Choose a Username", key="register_username")
    passphrase = st.text_input(
        "Create a Secure Passphrase", type="password", key="register_passphrase"
    )

    if st.button("Create Account"):
        if username in data_storage["users"]:
            st.warning(
                "⚠️ An account with this username already exists. Redirecting to Sign In..."
            )
            time.sleep(1.5)
            st.session_state["current_page"] = "Sign In"
            st.rerun()
        else:
            salt = os.urandom(16)
            key = generate_key_pbkdf2(passphrase, salt)
            data_storage["users"][username] = {
                "password": key.decode(),
                "salt": base64.b64encode(salt).decode(),
                "failed_attempts": 0,
            }
            save_data()
            st.success("✅ Your account has been successfully created. Please sign in.")
            time.sleep(1.5)
            st.session_state["current_page"] = "Sign In"
            st.rerun()


def signin_page():
    st.header("🔑 Sign In to Your Account")
    username = st.text_input("Enter Your Username", key="login_username")
    passphrase = st.text_input(
        "Enter Your Passphrase", type="password", key="login_passphrase"
    )

    if st.button("Sign In"):
        if username not in data_storage["users"]:
            st.warning(
                "⚠️ No account found with this username. Redirecting to Sign Up..."
            )
            time.sleep(1.5)
            st.session_state["current_page"] = "Sign Up"
            st.rerun()
        else:
            user = data_storage["users"][username]
            salt = base64.b64decode(user["salt"])
            key = generate_key_pbkdf2(passphrase, salt).decode()

            if key == user["password"]:
                st.session_state["login_success"] = True
                user["failed_attempts"] = 0
                save_data()
                st.success("✅ Welcome back! You’ve successfully logged in.")
                time.sleep(1.5)
                st.session_state["current_page"] = "Home"
                st.rerun()
            else:
                user["failed_attempts"] += 1
                save_data()
                if user["failed_attempts"] >= 3:
                    st.error(
                        "❌ You’ve exceeded the allowed login attempts. Your account has been temporarily locked."
                    )
                else:
                    st.error("❌ Incorrect passphrase.")
                    st.warning(f"Sign In attempt {user['failed_attempts']} of 3.")


def encrypt_and_save_page():
    st.header("📥 Encrypt & Save →")
    username = st.text_input("Enter Your Username", key="insert_username")
    passphrase = st.text_input(
        "Enter Your Passphrase", type="password", key="insert_passphrase"
    )
    text = st.text_area(
        "Enter the data you’d like to encrypt and securely store", key="insert_text"
    )

    if st.button("Encrypt & Save"):
        if username not in data_storage["users"]:
            st.warning(
                "⚠️ No user found. Please create an account to proceed. Redirecting to Sign Up..."
            )
            time.sleep(1.5)
            st.session_state["current_page"] = "Sign Up"
            st.rerun()
        else:
            encrypted, salt = encrypt_data(text, passphrase)
            data_storage["users"][username]["data"] = {
                "entry": {"encrypted_text": encrypted, "salt": salt}
            }
            save_data()
            st.success("✅ Success! Your data is now securely encrypted and stored!")


def decrypt_and_view_page():
    st.header("📤 Decrypt & View →")
    username = st.text_input("Enter Your Username", key="retrieve_username")
    passphrase = st.text_input(
        "Enter Your Passphrase", type="password", key="retrieve_passphrase"
    )

    if st.button("Decrypt & View"):
        if username not in data_storage["users"]:
            st.warning(
                "⚠️ No encrypted data found for this user. Redirecting to Signup..."
            )
            time.sleep(1.5)
            st.session_state["current_page"] = "Sign Up"
            st.rerun()
        else:
            try:
                user_data = data_storage["users"][username]["data"]["entry"]
                decrypted = decrypt_data(
                    user_data["encrypted_text"], passphrase, user_data["salt"]
                )
                st.success(f"🔓 Here’s your Decrypted Data: {decrypted}")
            except KeyError:
                st.error("❌ No encrypted data found for this user.")
            except Exception:
                st.error(
                    "❌ Unable to decrypt. Please check your passphrase and try again."
                )


# -------------------- Main App Logic -------------------- #


def main():
    load_data()

    st.sidebar.subheader("Choose an action:")

    pages = {
        "Home": home_page,
        "Sign Up": signup_page,
        "Sign In": signin_page,
        "Encrypt Data": encrypt_and_save_page,
        "Decrypt Data": decrypt_and_view_page,
    }

    # Set default page
    if "current_page" not in st.session_state:
        st.session_state["current_page"] = "Home"

    # Sidebar selection — only updates page if user clicks
    selected = st.sidebar.radio(
        "Choose action",
        list(pages.keys()),
        index=list(pages.keys()).index(st.session_state["current_page"]),
        label_visibility="collapsed",
    )
    if selected != st.session_state["current_page"]:
        st.session_state["current_page"] = selected
        st.rerun()

    # Handle login requirement for sensitive pages
    protected_pages = ["Encrypt Data", "Decrypt Data"]
    if st.session_state["current_page"] in protected_pages and not st.session_state.get(
        "login_success", False
    ):
        st.warning(
            "⚠️ You must be signned in to use this feature. Please sign in to continue."
        )
        st.session_state["current_page"] = "Sign In"
        time.sleep(1)
        st.rerun()

    # Call the correct page function
    pages[st.session_state["current_page"]]()


main()
