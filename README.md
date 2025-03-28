# Emergency Access System

A secure emergency information access system using YubiKey authentication. This application allows authorized users to access critical emergency information stored in Markdown format.

## Features

- YubiKey authentication for secure access
- Markdown rendering with syntax highlighting
- Webhook for remote updates of emergency information
- Mobile-friendly interface
- Hidden passwords that reveal when clicked

## Setup

1. Clone this repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Create a `.env` file based on `.env.example`:
   ```
   cp .env.example .env
   ```
4. Edit the `.env` file with your settings

### YubiKey Configuration

1. Get your YubiKey API credentials from https://upgrade.yubico.com/getapikey/
2. Add your client ID and secret key to the `.env` file
3. Determine your YubiKey ID (first 12 characters of any OTP generated by your YubiKey)
4. Add the YubiKey ID to the `.env` file

### Webhook Secret Generation

The webhook requires a strong secret to secure remote updates. Use one of these methods to generate a secure secret:

#### Option 1: Using Python

```python
import secrets
print(secrets.token_hex(32))  # Generates a 64-character hex string
```

#### Option 2: Using OpenSSL

```bash
openssl rand -hex 32
```

#### Option 3: Using /dev/urandom (Linux/Mac)

```bash
head -c 32 /dev/urandom | xxd -p -c 32
```

Add the generated secret to your `.env` file:
