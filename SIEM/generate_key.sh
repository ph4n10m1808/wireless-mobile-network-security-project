#!/bin/bash

# Generate a secure 32-byte (64 characters) random hex string
NEW_KEY=$(openssl rand -hex 32)

echo "[*] Generated new ENCRYPTION_KEY: $NEW_KEY"

# Ensure we are in the directory with the .env file
if [ ! -f ".env" ]; then
    echo "[!] Error: .env file not found in the current directory."
    echo "Please run this script from the SIEM/ directory."
    exit 1
fi

# If ENCRYPTION_KEY already exists, replace it. Otherwise, append it.
if grep -q "^ENCRYPTION_KEY=" .env; then
    # Cross-platform sed for Linux/macOS
    sed -i.bak "s/^ENCRYPTION_KEY=.*/ENCRYPTION_KEY=$NEW_KEY/" .env
    rm -f .env.bak
    echo "[*] Successfully updated existing ENCRYPTION_KEY in .env file."
else
    echo -e "\n# Kibana Encryption Key (32+ bytes) for production sessions and saved objects" >> .env
    echo "ENCRYPTION_KEY=$NEW_KEY" >> .env
    echo "[*] Successfully appended new ENCRYPTION_KEY to .env file."
fi