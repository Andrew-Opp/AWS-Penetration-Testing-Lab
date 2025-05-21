#!/bin/bash

# ================================
# CTF Privilege Escalation Setup
# ================================

# 1. World-Writable SUID Binary
echo "[+] Creating World-Writable SUID Binary..."
echo -e '#!/bin/bash\n/bin/bash' > /tmp/rootme
chmod +x /tmp/rootme
cp /tmp/rootme /usr/local/bin/rootme
chown root:root /usr/local/bin/rootme
chmod 4777 /usr/local/bin/rootme
echo "[+] SUID Binary Created: /usr/local/bin/rootme"

# 2. Cronjob Privilege Escalation
echo "[+] Setting up Cronjob-based Privilege Escalation..."
echo -e '#!/bin/bash\nchmod +s /bin/bash' > /tmp/pwn.sh
chmod +x /tmp/pwn.sh
if ! grep -q "/tmp/pwn.sh" /etc/crontab; then
    echo "*/1 * * * * root /tmp/pwn.sh" >> /etc/crontab
    echo "[+] Cronjob added to /etc/crontab"
else
    echo "[!] Cronjob already exists. Skipping..."
fi

# 3. Dangerous SUID Binary (vim)
echo "[+] Creating Dangerous SUID Binary (vim)..."
if [ -f /usr/bin/vim ]; then
    cp /usr/bin/vim /usr/local/bin/vimroot
    chown root:root /usr/local/bin/vimroot
    chmod 4755 /usr/local/bin/vimroot
    echo "[+] SUID Vim created at /usr/local/bin/vimroot"
else
    echo "[!] Vim binary not found. Skipping..."
fi

echo "[✔] Vulnerable configurations injected. Exploit responsibly."
