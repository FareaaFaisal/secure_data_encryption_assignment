import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os

# Constants
DATA_FILE = "data_store.json"

# Load data from JSON file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save data to JSON file
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = False  # Initially set to False
if "stored_data" not in st.session_state:
    st.session_state.stored_data = load_data()  # Load from JSON file

# If no key exists, generate and store it
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
cipher = Fernet(st.session_state.fernet_key)

# Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt the user's text
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Attempt decryption
def decrypt_data(title, passkey):
    if title in st.session_state.stored_data:
        entry = st.session_state.stored_data[title]
        if hash_passkey(passkey) == entry["passkey"]:
            st.session_state.failed_attempts = 0
            # Ensure we're using the correct key
            return cipher.decrypt(entry["encrypted_text"].encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# UI Navigation
st.title("🔐 Secure Data Encryption System")
st.markdown("---")

menu = ["🏠 Home", "💾 Store Data", "🔓 Retrieve Data", "🔑 Login"]
choice = st.sidebar.selectbox("Choose a page", menu)

# Home Page
if choice == "🏠 Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.write("Make sure to remember your passkey for later use!")

# Store Data Page
elif choice == "💾 Store Data":
    if not st.session_state.authorized:
        st.warning("🔒 You must log in first.")
        st.stop()

    st.subheader("📂 Store Data Securely")
    title = st.text_input("🔖 Enter Title (Unique):")
    user_data = st.text_area("📝 Enter Data:")
    passkey = st.text_input("🔑 Enter Passkey:", type="password")

    if st.button("🔐 Encrypt & Store"):
        if title and user_data and passkey:
            encrypted = encrypt_data(user_data)
            hashed = hash_passkey(passkey)
            st.session_state.stored_data[title] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            save_data(st.session_state.stored_data)  # Save to file!
            st.success("✅ Data stored securely!")
            st.code(encrypted)
        else:
            st.error("❗ All fields are required.")

# Retrieve Data Page
elif choice == "🔓 Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔒 You must login first.")
        st.stop()

    st.subheader("🔍 Retrieve Your Data")
    title = st.text_input("🔖 Enter Title:")
    passkey = st.text_input("🔑 Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if title and passkey:
            result = decrypt_data(title, passkey)
            if result:
                st.success(f"✅ Decrypted Data: {result}")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Wrong passkey. Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
                    st.warning("🔒 Too many failed attempts. Redirecting to Login...")
                    st.session_state.failed_attempts = 0  # Reset the failed attempts
                    st.session_state.page = "login"  # Trigger page navigation using session state
                    st.stop()  # Prevent further code execution in this block
        else:
            st.error("❗ Both fields are required.")

# Login Page
elif choice == "🔑 Login":
    st.subheader("🔑 Reauthorization Required")
    master_pass = st.text_input("Enter Master Password:", type="password")
    if st.button("Login"):
        if master_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Reauthorized successfully!")
            st.session_state.page = "home"  # Redirect to Home page using session state
            st.stop()  # Prevent further code execution
        else:
            st.error("❌ Incorrect master password.")
