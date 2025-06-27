## 🔧 Automated Network Setup Script (WSL Ubuntu Compatible)

This script automates the setup and configuration of:

* 🕸️ Apache (HTTP)
* 📁 FTP Server (vsftpd)
* 🌐 DNS Server (bind9)
* 🧭 DHCP Server (optional, WSL-safe)
* 🔁 Port Forwarding using `iptables` (with fallback to UFW)
* 🧪 Service Health Tests
* 🗂️ Logging to `~/setup_log.txt`

> ✅ Designed with **OOP principles** in Python.
> ✅ Supports **WSL Ubuntu (22.04/24.04)**.
> ✅ Automatically maps HTTP and FTP to ports based on your USN.

---

### 📦 Prerequisites

* Python 3
* WSL Ubuntu (recommended 22.04+)
* `sudo` privileges

---

### 🚀 How to Use

#### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
```

#### 2. Make the script executable

```bash
chmod +x script.py
```

#### 3. Run the Script

```bash
sudo python3 script.py
```

> 📝 **Note**: When prompted, enter the **last 3 digits** of your USN.
> For example: `SCA24MCA032` → input `032`.

* If valid, HTTP → `8800 + USN`, FTP → `8700 + USN`.
* If invalid, defaults to HTTP `8832` and FTP `8732`.

---

### 🧪 What the Script Does

1. Installs and starts Apache, vsftpd, bind9, isc-dhcp-server.
2. Sets up port forwarding using `iptables`.
3. Ensures DNS works by mapping `www.mylocal.db` to `127.0.0.1`.
4. Logs every step to: `~/setup_log.txt`
5. Verifies:

   * Apache → `curl localhost:<your_http_port>`
   * FTP → `ftp 127.0.0.1 <your_ftp_port>`
   * DNS → `dig @localhost www.mylocal.db +short`

---

### 🔎 Log File

If something fails, check:

```bash
cat ~/setup_log.txt
```

---

### 🧯 Troubleshooting

* 💡 Run using `sudo` to ensure permissions are correct.
* ❌ If `netfilter-persistent` is not found, the script installs it.
* ⚠️ DHCP setup is **skipped on WSL** (not fully supported).
* 🔐 If UFW is not active, the script attempts to enable and configure it.

---

### 🧰 Sample Output (Ports from USN 032)

```txt
[HTTP] Apache reachable on port 8832
[FTP] FTP reachable on port 8732
[DNS] DNS resolution for www.mylocal.db successful
```

---

### 📤 Share Your Result

Use the output log to show your working setup to instructors or evaluators.
