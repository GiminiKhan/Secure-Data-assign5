# 🔐 Develop a streamlit-based Secure Data Storage and Retrieval System

import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# 📁 File & Security Constants
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# 🔐 Session State Initialization
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# 📥 Load & Save User Data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# 🔑 Key Generation & Password Hashing
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# 🔐 Encrypt / Decrypt Functions
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# 🔄 Load Data at Start
stored_data = load_data()

# 📌 Navigation Menu
st.title("🔒 Secure Data Encryption System")
menu = ["🏠 Home", "📝 Register", "🔑 Login", "💾 Store Data", "📂 Retrieve Data"]
choice = st.sidebar.selectbox("📍 Navigation", menu)

# 🏠 Home Page
if choice == "🏠 Home":
    st.subheader("📢 Welcome to My Data Encryption System Using Streamlit!")
    st.markdown("""
        ✔️ Users can **store data with a unique passkey**  
        ❌ Multiple failed attempts lead to login lockout  
        🧠 All data stored in local file memory (no external database)  
    """)

# 📝 Register Page
elif choice == "📝 Register":
    st.subheader("👤 Register New User")
    username = st.text_input("👤 Choose Username")
    password = st.text_input("🔑 Choose Password", type="password")

    if st.button("✅ Register"):
        if username in stored_data:
            st.warning("⚠️ User already exists.")
        else:
            stored_data[username] = {"password": hash_password(password), "data": []}
            save_data(stored_data)
            st.success("🎉 User registered successfully!")

# 🔑 Login Page
elif choice == "🔑 Login":
    st.subheader("🔐 Login to Your Account")
    username = st.text_input("👤 Username")
    password = st.text_input("🔑 Password", type="password")

    current_time = time.time()
    if st.session_state.lockout_time > current_time:
        remaining = int(st.session_state.lockout_time - current_time)
        st.error(f"⏳ Too many failed attempts. Try again in {remaining} seconds.")
    else:
        if st.button("🔓 Login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success("✅ Logged in successfully.")
            else:
                st.session_state.failed_attempts += 1
                st.error("❌ Invalid credentials.")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = current_time + LOCKOUT_DURATION
                    st.warning("🚫 Too many failed attempts. Locked out for 60 seconds.")

# 💾 Store Data Page
elif choice == "💾 Store Data":
    st.subheader("🧾 Store Encrypted Data")
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please login first to store data.")
    else:
        data_to_store = st.text_area("📝 Enter data to store securely")
        passkey = st.text_input("🔐 Enter passkey", type="password")

        if st.button("📥 Encrypt & Store"):
            if data_to_store and passkey:
                encrypted_data = encrypt_text(data_to_store, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted_data)
                save_data(stored_data)
                st.success("✅ Data encrypted and stored successfully.")
            else:
                st.warning("⚠️ Please provide both data and passkey.")

# 📂 Retrieve Data Page
elif choice == "📂 Retrieve Data":
    st.subheader("🔎 Retrieve Your Encrypted Data")
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please login first to retrieve data.")
    else:
        passkey = st.text_input("🔐 Enter your passkey", type="password")

        if st.button("🔍 Retrieve Data"):
            if passkey:
                encrypted_items = stored_data[st.session_state.authenticated_user]["data"]
                for i, item in enumerate(encrypted_items, 1):
                    decrypted = decrypt_text(item, passkey)
                    if decrypted:
                        st.write(f"**{i}.** 🔓 {decrypted}")
                    else:
                        st.write(f"**{i}.** ❌ Incorrect passkey or failed decryption.")
            else:
                st.warning("⚠️ Enter your passkey first.")

