#!/bin/bash

# Script to install SOR as a system-wide tool on Kali Linux

# --- Configuration ---
TOOL_NAME="sro"
INSTALL_DIR="/usr/local/bin"
PYTHON_SCRIPT="sro.py"
REQUIREMENTS_FILE="requirements.txt"

echo "--- SRO OSINT Tool Installation ---"

# 1. Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)." 
   exit 1
fi

# 2. Install Python dependencies
echo "[*] Installing Python dependencies from $REQUIREMENTS_FILE..."
if command -v uv &> /dev/null; then
    # Use uv if available
    sudo uv pip install --system -r $REQUIREMENTS_FILE
else
    # Fallback to pip3
    sudo pip3 install -r $REQUIREMENTS_FILE
fi

if [ $? -ne 0 ]; then
    echo "[!] Error installing Python dependencies. Aborting."
    exit 1
fi
echo "[+] Python dependencies installed successfully."

# 3. Install the main script
echo "[*] Installing $PYTHON_SCRIPT to $INSTALL_DIR/$TOOL_NAME..."
cp $PYTHON_SCRIPT $INSTALL_DIR/$TOOL_NAME

# 4. Make the script executable
echo "[*] Setting executable permissions..."
chmod +x $INSTALL_DIR/$TOOL_NAME

# 5. Add Python shebang to the script
echo "[*] Adding Python shebang to the script..."
sed -i '1i#!/usr/bin/env python3' $INSTALL_DIR/$TOOL_NAME

# 6. Final check
if command -v $TOOL_NAME &> /dev/null; then
    echo "-----------------------------------"
    echo "[+] SRO v2.0 installed successfully!"
    echo "[+] You can now run the tool from any terminal by typing: $TOOL_NAME"
    echo "[!] Initial data will be stored in ~/.sro_data/"
    echo "-----------------------------------"
else
    echo "[!] Installation failed. $TOOL_NAME command not found."
fi

exit 0
