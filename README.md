# Commonroom

A Python chat system with browser-side **End-to-End Encryption (E2EE)**, unique 8-character user IDs, 1-on-1 and group conversations, and encrypted image sharing (up to 8 MB). 

All messages, attachments, and private keys are encrypted directly inside the browser using the native **Web Crypto API** (`RSA-OAEP`, `AES-256-GCM`, `PBKDF2`). The server and database operate under zero knowledge and never have access to plaintext messages or private keys.

---

## Live Deployment

* **Frontend (GitHub Pages)**: [https://rajdohar2-stack.github.io/encripted-chat-system/](https://rajdohar2-stack.github.io/encripted-chat-system/)
* **Backend API (Render)**: `https://encripted-chat-system.onrender.com`
* **Health Check**: [https://encripted-chat-system.onrender.com/api/health](https://encripted-chat-system.onrender.com/api/health)

---

## Key Features & Recent Improvements

1. **Full Cloud Persistence (Render Free Tier Friendly)**:
   * **Messages**: Stored in Firebase Realtime Database under `/conversations/{id}/messages/`.
   * **Accounts & Conversations**: User profiles, conversations, and membership relations are automatically backed up to Firebase under `/accounts/users/`, `/accounts/conversations/`, and `/accounts/members/`.
   * **Auto-Restore on Startup**: When Render containers sleep or redeploy, `server.py` automatically pulls existing users and conversations from Firebase back into SQLite on boot.
   * **On-Demand Login Sync**: If an account exists in Firebase but hasn't reached the local container yet, `login()` automatically imports the user and authenticates without error.
2. **Simplified Cloud Authentication (`FIREBASE_CREDENTIALS_JSON`)**:
   * Credentials can be passed directly as an environment variable (`FIREBASE_CREDENTIALS_JSON`) containing the raw service-account JSON, or via file path (`GOOGLE_APPLICATION_CREDENTIALS`).
3. **Diagnostic Health Check**:
   * Visiting `/api/health` reports status, message store, credential availability (`firebase_cred_exists`), and credential source (`env_json` vs `file`).
4. **Transparent JSON Error Handling**:
   * Server exceptions return clear JSON error descriptions (`{"error": "Server error: ..."}`) and log full tracebacks to stdout/stderr, replacing opaque generic failure messages.

---

## How It Works (Cryptographic Architecture)

* **Key Generation**: 2048-bit **RSA-OAEP** key pair (SHA-256) generated in the browser on registration. Public key is uploaded as JWK; private key never leaves the client in plaintext.
* **Local Password Vault**: RSA private key is encrypted locally using **AES-256-GCM** with a key derived via **PBKDF2** (310,000 SHA-256 iterations) and stored in browser `localStorage`.
* **Per-Message Hybrid Encryption**: For every message or image:
  1. A fresh 256-bit **AES-256-GCM** key and 12-byte IV are generated.
  2. The message/image bytes are encrypted with this AES key.
  3. The AES key is wrapped separately for each conversation member using their RSA-OAEP public key, creating an `envelopes` map.
  4. Only ciphertext, IV, and envelopes are transmitted to the server.
* **Decryption**: Recipient unwraps their key envelope using their private RSA key, then decrypts the ciphertext using AES-GCM.

---

## Local Setup & Development (Windows)

### 1. Install Dependencies
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Run the Server
```powershell
python server.py
```
* Runs locally at `https://127.0.0.1:5000` (and prints your Wi-Fi LAN address for local network testing).
* On first run, it generates a local Certificate Authority (`%USERPROFILE%\.commonroom\lan-root-ca.crt`). Install this certificate into **Current User > Trusted Root Certification Authorities** to avoid browser HTTPS warnings.

---

## Internet Deployment (GitHub Pages + Render)

### Backend Deployment (Render)
1. Create a new **Web Service** on [Render](https://dashboard.render.com/) pointing to this repository.
2. Set build and start commands:
   * **Build Command**: `pip install -r requirements.txt`
   * **Start Command**: `gunicorn server:app --bind 0.0.0.0:$PORT --workers 1 --timeout 120`
3. Add Environment Variables:
   * `COMMONROOM_HOSTED`: `true`
   * `COMMONROOM_ALLOWED_ORIGINS`: `https://rajdohar2-stack.github.io`
   * `FIREBASE_DATABASE_URL`: `https://your-project-id-default-rtdb.<region>.firebasedatabase.app`
   * `FIREBASE_CREDENTIALS_JSON`: *(Paste the entire contents of your Firebase service-account JSON file)*
   * `PYTHON_VERSION`: `3.13.4`

### Frontend Deployment (GitHub Pages)
1. In `config.js`, set your Render API base URL:
   ```javascript
   window.COMMONROOM_API_URL = "https://encripted-chat-system.onrender.com";
   ```
2. In GitHub repository **Settings > Pages**, enable Pages using the `main` branch and `/ (root)`.

---

## Using the Chat & Managing Private Keys

* **Registration & Login**: Create an account with a username and password (minimum 10 characters). Share your 8-character chat ID to let others start a conversation with you.
* **New Devices & Incognito Tabs (Key Backup)**:
  * Because private keys stay on your device, logging into a new browser or Incognito tab requires importing your private key backup.
  * In your active browser, click **Backup** (bottom-left) to download `commonroom-key-<ID>.json`.
  * On the new device / Incognito window, click **Import backup** on the sign-in screen, select the file, and enter your password.
* **Auditing & Viewing Encrypted Payloads**:
  1. **In-Chat Toggle**: Click **"Show encrypted"** in the top chat header bar to view the raw JSON ciphertext payload of any message.
  2. **My Encrypted Records**: Open `/my-encrypted.html` on any device to inspect raw encrypted message records for your conversations.
  3. **Localhost Admin Dashboard**: When running locally, visit `https://127.0.0.1:5000/encrypted-messages.html` (`database.html`) to inspect ciphertext, IVs, and envelopes across all conversations (blocked on public hosting for security).
  4. **Firebase Console**: Realtime Database inspectable live in the Firebase console under `/conversations` and `/accounts`.
