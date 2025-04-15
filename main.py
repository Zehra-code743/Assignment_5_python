
import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import time

# Set page config
st.set_page_config(page_title="Secure Vault", layout="centered", page_icon="🔐")

# --- Session State Setup ---
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

if 'selected_option' not in st.session_state:
    st.session_state.selected_option = 'Home'

if 'theme' not in st.session_state:
    st.session_state.theme = "Light"  # Default theme

# --- Background Setter ---
def set_bg(image_file):
    st.markdown(f"""
        <style>
        .stApp {{
            background-image: url("{image_file}");
            background-size: cover;
            background-repeat: no-repeat;
            background-attachment: fixed;
            background-position: center;
        }}
        </style>
    """, unsafe_allow_html=True)

# --- Theme Styles ---
def apply_theme_styles():
    if st.session_state.theme == "Light":
        st.markdown("""
            <style>
                .main {
                    background-color: rgba(255, 255, 255, 0.8);
                    color: black;
                    border-radius: 12px;
                    padding: 20px;
                    margin-bottom: 20px;
                }
                .stButton button {
                    background-color: #0072ff;
                    color: white;
                    border-radius: 10px;
                    padding: 10px 20px;
                    font-weight: bold;
                }
                .stTextInput > div > div > input,
                .stTextArea > div > textarea {
                    border-radius: 10px;
                    padding: 10px;
                }
            </style>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
            <style>
                .main {
                    background-color: rgba(0, 0, 0, 0.6);
                    color: white;
                    border-radius: 12px;
                    padding: 20px;
                    margin-bottom: 20px;
                }
                .stButton button {
                    background-color: #00c6ff;
                    color: black;
                    border-radius: 10px;
                    padding: 10px 20px;
                    font-weight: bold;
                }
                .stTextInput > div > div > input,
                .stTextArea > div > textarea {
                    border-radius: 10px;
                    padding: 10px;
                }
            </style>
        """, unsafe_allow_html=True)

# --- Utility Functions ---
def hash_pass(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_text(text, fernet):
    return fernet.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, fernet):
    try:
        return fernet.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        st.error(f"❌ Decryption failed: {str(e)}")
        return None

# --- Login Page ---
def login():
    set_bg("https://www.shutterstock.com/image-photo/access-system-login-by-username-600nw-2230192833.jpg")  # Use local file or URL
    apply_theme_styles()
    st.title("🔐 Secure Vault Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    login_btn = st.button("Login")

    if login_btn:
        if username == "admin" and hash_pass(password) == hash_pass("admin123"):
            st.success("✅ Login successful!")
            st.session_state.authenticated = True
            time.sleep(1)
            st.rerun()
        else:
            st.session_state.failed_attempts += 1
            st.error("❌ Invalid credentials!")
            if st.session_state.failed_attempts >= 3:
                st.warning("⚠️ Too many failed attempts!")

# --- Secure Vault App ---
def secure_vault():
    set_bg("https://www.kraftcpas.com/production/site/web/assets/2020/07/cyber-security-header-768x320.jpg")  # Use local file or URL
    st.sidebar.title("🔐 Secure Vault")

    # Theme toggle
    theme_choice = st.sidebar.radio("Choose Theme", ["Light", "Dark"])
    st.session_state.theme = theme_choice
    apply_theme_styles()

    menu = ["Home", "Encrypt", "Decrypt", "Logout"]
    choice = st.sidebar.radio("Navigate", menu)

    if choice:
        st.session_state.selected_option = choice

    if st.session_state.selected_option == "Home":
        st.markdown("<div class='main'><h2>Welcome to Secure Vault 🔐</h2><p>This app helps you encrypt and decrypt your sensitive data securely.</p></div>", unsafe_allow_html=True)

    elif st.session_state.selected_option == "Encrypt":
        st.subheader("🔒 Encrypt Text")
        raw_text = st.text_area("Enter text to encrypt")
        password = st.text_input("Set a password", type="password")
        if st.button("Encrypt"):
            if raw_text and password:
                key = Fernet.generate_key()
                fernet = Fernet(key)
                encrypted = encrypt_text(raw_text, fernet)
                hashed_pass = hash_pass(password)
                st.session_state.stored_data[encrypted] = {
                    'encrepted_text': encrypted,
                    'hashed_passkey': hashed_pass,
                    'key': key
                }
                st.success("✅ Text encrypted successfully!")
                st.code(encrypted)
            else:
                st.warning("⚠️ Please enter both text and password!")

    elif st.session_state.selected_option == "Decrypt":
        st.subheader("🔓 Decrypt Text")
        encrypted_input = st.text_area("Paste the encrypted text")
        password_input = st.text_input("Enter password", type="password")
        if st.button("Decrypt"):
            if encrypted_input and password_input:
                entry = st.session_state.stored_data.get(encrypted_input)
                if entry:
                    try:
                        fernet = Fernet(entry['key'])
                        if hash_pass(password_input) == entry['hashed_passkey']:
                            decrypted = decrypt_text(encrypted_input, fernet)
                            if decrypted:
                                st.success("✅ Decrypted text:")
                                st.code(decrypted)
                        else:
                            st.error("❌ Wrong password.")
                    except Exception as e:
                        st.error(f"❌ Decryption failed: {str(e)}")
                else:
                    st.error("❌ Encrypted text not found.")
            else:
                st.warning("⚠️ Please provide both fields.")

    elif st.session_state.selected_option == "Logout":
        st.session_state.authenticated = False
        st.session_state.failed_attempts = 0
        st.rerun()

# --- Run App ---
if not st.session_state.authenticated:
    login()
else:
    secure_vault()