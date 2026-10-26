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

## Use a temporary link from another network

For occasional access when devices are not on the same Wi-Fi, install Cloudflare Tunnel once with `winget install --id Cloudflare.cloudflared`. In VS Code, start **Run encrypted chat API**, then start **Share chat with a temporary secure link**. Enter the email address that should be allowed to open the link. Cloudflare sends that address a one-time PIN; other addresses are blocked. The task prints a temporary `trycloudflare.com` URL. Open that URL on each device and sign in to the chat there.

Keep both tasks and this PC online while using the link. Stop the tunnel task with **Ctrl+C** when finished; the URL expires and changes the next time it starts. This shares the chat website and API together, so do not use the GitHub Pages URL for this temporary setup. The existing encrypted-record administrator viewer remains local-only and is blocked through the tunnel. Quick Tunnels are for testing, have no uptime guarantee, and are not a production hosting service. Use test data and do not share the link.

## Use the GitHub Pages site from anywhere

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

### Automatic GitHub Sync
When this folder is opened in VS Code, the **Auto-sync changes to GitHub** task starts. After project changes have been quiet for five seconds, it stages Git-visible changes, commits them, and pushes the current branch to `origin`. Git's ignore rules still apply, so keep credentials, local databases, and other private files out of Git. GitHub authentication must already be configured. If a push fails, the task reports the error in its terminal; it never force-pushes. Stop the task from **Terminal > Terminate Task** to pause automatic syncing.

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
* When the frontend is opened on `localhost` or `127.0.0.1` (including VS Code Live Server), it automatically uses this local API. Start **Run encrypted chat API** and trust its certificate before signing in. The deployed GitHub Pages frontend continues to use the hosted Render API.

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
