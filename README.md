# Commonroom

A Python chat prototype with browser-side end-to-end encryption, user IDs, group conversations, and encrypted image sharing. Messages are written to Firebase Realtime Database when configured, or to local SQLite otherwise.

## Start it in VS Code

1. Install the dependencies once: `python -m pip install -r requirements.txt` (use the workspace interpreter; `.venv` is already created here).
2. Configure Firebase as described below to store messages in the cloud.
3. Start the API from **Terminal > Run Task > Run encrypted chat API**.
4. Open the HTTPS address printed by the task. The API serves the chat and records viewer as well as handling messages.

The app runs at `https://127.0.0.1:5000` on this PC and at the printed Wi-Fi address for other devices. Keep the API task running while chatting. The local certificate must be trusted by the browser for encryption to work. On this PC, install `%USERPROFILE%\.commonroom\lan-root-ca.crt` as a trusted CA certificate (**Current User > Trusted Root Certification Authorities**) and restart the browser tab. The root CA stays the same when your Wi-Fi IP changes; only the server certificate is renewed.

## Use another device on the same Wi-Fi

1. Start **Run encrypted chat API** on this PC. It prints the current HTTPS address and certificate location. Open the exact `https://<Wi-Fi-IP>:5000/` address printed by the task on devices connected to the same Wi-Fi. The Wi-Fi IP may change after reconnecting.
2. On the PC, find `%USERPROFILE%\.commonroom\lan-root-ca.crt` and transfer that public certificate to the other device using USB or another trusted method. Never transfer `lan-root-ca.key` or `lan-server.key`.
3. Install `lan-root-ca.crt` as a trusted CA certificate on the other device (Android: **Settings > Security > Encryption & credentials > Install a certificate > CA certificate**; iPhone/iPad: install the certificate profile, then enable trust under **Settings > General > About > Certificate Trust Settings**; Windows: open the `.crt` file, choose **Install Certificate > Current User > Place all certificates in Trusted Root Certification Authorities**).
4. Open the HTTPS address printed by the server. If Windows Firewall asks whether Python can accept local-network connections, allow it on **Private networks only**.
5. Sign in with your existing account. Import your encrypted key backup on that device before signing in if it needs to decrypt your old messages.

The PC must stay on, connected to the same Wi-Fi, and running the API task. This setup is for a trusted home/local network, not access from the public internet. The database and accounts are on that PC unless Firebase is separately configured.

## Use

Create an account with a username and a password of at least 10 characters. Share your generated chat ID with people you want to find. Search for their username or ID to start a one-to-one conversation or add several people to a group. Starting a private chat with someone you have already chatted with opens the existing conversation; duplicate private chats are consolidated while preserving their messages. Messages and images up to 8 MiB are encrypted in the browser before upload.

Use **Backup** to download an encrypted copy of the private key. On another browser, import that file before signing in with the same account password. Without the private key backup, messages for that account cannot be decrypted on another device. Keep the backup private.

Open `https://127.0.0.1:5000/encrypted-messages.html` on the server PC to inspect encrypted message records in a separate viewer (`/database.html` remains an alias). No admin key is required: both the page and its admin APIs reject connections that do not originate from this PC or from another website. Do not use the server's Wi-Fi IP or share this viewer URL; access is intentionally limited to localhost and is not tied to a specific Windows account. The viewer can inspect ciphertext, IVs, encrypted key envelopes, and metadata across all conversations; it does not decrypt message text.

For a ciphertext-only view limited to conversations your chat account belongs to, open `/my-encrypted.html` and sign in with your chat account. It works independently of the localhost-only administrator viewer and cannot show conversations the account is not a member of. Other members can also access ciphertext for their shared conversations; readable message text still requires a participant's private key.

Account profiles, public keys, login sessions, and conversation membership are stored in `%USERPROFILE%\.commonroom\chat.db` on Windows. Local encrypted message records are kept separately in `%USERPROFILE%\.commonroom\encrypted_messages.db`; existing records are migrated on API startup. When Firebase is configured, new encrypted messages are stored under `conversations/{conversation_id}/messages/{push_id}` in Realtime Database instead. Message contents and private keys are never uploaded in plaintext.

## Firebase setup

1. Create a Firebase project and enable **Realtime Database**.
2. Create a service account for the server in Firebase project settings and download its JSON key outside this workspace. Do not commit or share that key.
3. Copy `.env.example` to `.env` and set `FIREBASE_DATABASE_URL` to the database URL shown in Firebase, and `GOOGLE_APPLICATION_CREDENTIALS` to the full path of the downloaded service-account JSON file.
4. Install dependencies again using `python -m pip install -r requirements.txt`, then restart **Run encrypted chat API**.
5. Open `https://127.0.0.1:5000/api/health`; `message_store` should say `firebase`. If it says `local`, Firebase isn't configured and messages are still stored locally.

The server uses Firebase Admin credentials, which bypass client database rules. Keep the service-account JSON private and never add it to the frontend. This prototype keeps account and conversation membership data local to the host PC, so Firebase only synchronizes messages for users/conversations known to this API's SQLite database.

## Security scope

RSA-OAEP with SHA-256 wraps a fresh AES-256-GCM key per message; AES-GCM encrypts text and image bytes. The private RSA key is encrypted locally with a password-derived key and is not uploaded. This is a development prototype: the API is exposed to the local network, does not verify public-key fingerprints, and is not hardened for internet deployment. Do not port-forward it to the public internet; remote access needs a production HTTPS host, shared account/conversation storage, key verification, abuse controls, and an audited server.
