#!/usr/bin/env python3
"""
Example script to update emergency.md content via webhook.

Usage:
    python webhook_example.py <webhook_url> <webhook_secret> <markdown_file>

Example:
    python webhook_example.py https://emergency.example.com mysecret ./new_emergency.md
"""

import sys
import hmac
import hashlib
import requests
import json

def update_emergency_content(webhook_url, webhook_secret, content_file):
    # Read the content from the file
    with open(content_file, 'r') as f:
        content = f.read()
    
    # Prepare the payload
    payload = json.dumps({"content": content})
    
    # Calculate the signature
    signature = hmac.new(
        webhook_secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Set headers
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Signature": signature
    }
    
    # Send the request
    response = requests.post(f"{webhook_url}/webhook/update", data=payload, headers=headers)
    
    # Print the result
    print(f"Status code: {response.status_code}")
    print(f"Response: {response.text}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <webhook_url> <webhook_secret> <markdown_file>")
        sys.exit(1)
    
    webhook_url = sys.argv[1]
    webhook_secret = sys.argv[2]
    content_file = sys.argv[3]
    
    update_emergency_content(webhook_url, webhook_secret, content_file)
