#!/usr/bin/env python3

import subprocess
import os
import time
import platform
from datetime import datetime

LOG_FILE = os.path.expanduser("~/setup_log.txt")

def log(message):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    with open(LOG_FILE, 'a') as f:
        f.write(f"{timestamp} {message}\n")
    print(f"{timestamp} {message}")

def run_cmd(command, retries=1):
    for attempt in range(retries):
        try:
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            log(f"[SUCCESS] {command}\n{result.stdout}")
            return result.stdout
        except subprocess.CalledProcessError as e:
            log(f"[ERROR] {command}\n{e.stderr}")
            time.sleep(2)
    return None

def is_wsl():
    with open("/proc/version", "r") as f:
        return "microsoft" in f.read().lower()

def replace_or_append(filepath, key, value, sep="="):
    updated = False
    with open(filepath, 'r') as f:
        lines = f.readlines()
    with open(filepath, 'w') as f:
        for line in lines:
            if line.strip().startswith(f"{key}{sep}"):
                f.write(f"{key}{sep}{value}\n")
                updated = True
            else:
                f.write(line)
        if not updated:
            f.write(f"{key}{sep}{value}\n")

class PortConfig:
    def __init__(self, usn_suffix):
        try:
            self.suffix = int(usn_suffix)
            if self.suffix == 0 or self.suffix > 999:
                raise ValueError
            self.http_port = 8800 + self.suffix
            self.ftp_port = 8700 + self.suffix
        except Exception:
            log("Invalid USN suffix.")
            exit(1)

class Service:
    def __init__(self, name):
        self.name = name

    def install(self):
        log(f"Installing {self.name}...")
        run_cmd(f"apt install -y {self.name}", retries=3)

    def start_and_enable(self):
        run_cmd(f"systemctl start {self.name}", retries=3)
        run_cmd(f"systemctl enable {self.name}")

class ApacheService(Service):
    def __init__(self, port):
        super().__init__("apache2")
        self.port = port

    def configure(self):
        config_path = "/etc/apache2/ports.conf"
        default_conf = "/etc/apache2/sites-available/000-default.conf"
        run_cmd(f"sed -i '/^Listen /d' {config_path}")
        run_cmd(f"echo 'Listen {self.port}' >> {config_path}")
        run_cmd(f"sed -i 's/<VirtualHost .*>/<VirtualHost *:{self.port}>/' {default_conf}")
        run_cmd("systemctl restart apache2")

    def test(self):
        result = run_cmd(f"curl -s http://localhost:{self.port}")
        if result:
            log(f"[HTTP] Apache reachable on port {self.port}")
        else:
            log(f"[HTTP] Apache NOT reachable on port {self.port}")

class FTPService(Service):
    def __init__(self, port):
        super().__init__("vsftpd")
        self.port = port

    def configure(self):
        run_cmd("apt install -y ftp")
        vsftpd_conf = "/etc/vsftpd.conf"
        replace_or_append(vsftpd_conf, "listen", "YES")
        replace_or_append(vsftpd_conf, "listen_ipv6", "NO")
        replace_or_append(vsftpd_conf, "local_enable", "YES")
        replace_or_append(vsftpd_conf, "write_enable", "YES")
        run_cmd("systemctl restart vsftpd")

    def test(self):
        result = run_cmd(f"echo 'bye' | ftp -inv 127.0.0.1 {self.port}", retries=1)
        if result:
            log(f"[FTP] FTP reachable on port {self.port}")
        else:
            log(f"[FTP] FTP NOT reachable on port {self.port}")

class DNSService(Service):
    def __init__(self):
        super().__init__("bind9")

    def configure(self):
        run_cmd("apt install -y dnsutils")
        log("Configuring DNS zone for mylocal.db")
        named_conf_local = "/etc/bind/named.conf.local"
        zone_entry = '''
zone "mylocal.db" {
    type master;
    file "/etc/bind/db.mylocal";
};'''
        with open(named_conf_local, 'r') as f:
            content = f.read()
        if 'zone "mylocal.db"' not in content:
            run_cmd(f"echo '{zone_entry}' >> {named_conf_local}")

        named_conf_options = "/etc/bind/named.conf.options"
        with open(named_conf_options, 'r') as f:
            options = f.read()
        if "listen-on port 53" not in options:
            updated = options.replace(
                "options {",
                "options {\n    directory \"/var/cache/bind\";\n    listen-on port 53 { 127.0.0.1; };\n    allow-query { any; };"
            )
            with open(named_conf_options, 'w') as f:
                f.write(updated)

        zone_file = '''$TTL 604800
@   IN  SOA ns.mylocal.db. root.mylocal.db. (
                2     ; Serial
                604800     ; Refresh
                86400      ; Retry
                2419200    ; Expire
                604800 )   ; Negative Cache TTL
;
@       IN      NS      ns
ns      IN      A       127.0.0.1
www     IN      A       127.0.0.1
'''
        with open("/etc/bind/db.mylocal", "w") as f:
            f.write(zone_file)
        run_cmd("systemctl restart bind9")

    def test(self):
        result = run_cmd("dig @localhost www.mylocal.db +short")
        if result and "127.0.0.1" in result:
            log("[DNS] DNS resolution for www.mylocal.db successful")
        else:
            log("[DNS] DNS resolution failed")

class DHCPService(Service):
    def __init__(self):
        super().__init__("isc-dhcp-server")

    def configure(self):
        if is_wsl():
            log("[WARNING] Skipping DHCP setup on WSL (not fully supported)")
            return
        dhcp_conf = '''default-lease-time 600;
max-lease-time 7200;
subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.100 192.168.1.200;
    option routers 192.168.1.1;
    option domain-name-servers 8.8.8.8;
}
'''
        with open("/etc/dhcp/dhcpd.conf", "w") as f:
            f.write(dhcp_conf)
        run_cmd("systemctl restart isc-dhcp-server")

class PortForwarder:
    def __init__(self, from_port, to_port):
        self.from_port = from_port
        self.to_port = to_port

    def try_iptables(self):
        log(f"Attempting iptables forwarding: {self.from_port} -> {self.to_port}")
        rules = [
            f"iptables -t nat -A PREROUTING -p tcp --dport {self.from_port} -j REDIRECT --to-port {self.to_port}",
            f"iptables -t nat -A OUTPUT -p tcp -o lo --dport {self.from_port} -j REDIRECT --to-port {self.to_port}"
        ]
        for rule in rules:
            run_cmd(rule)
        run_cmd("apt install -y netfilter-persistent")
        run_cmd("netfilter-persistent save")

class SetupManager:
    def __init__(self):
        self.usn_suffix = input("Enter last 3 digits of your USN (e.g., for SCA24MCA032 enter 032): ")
        self.ports = PortConfig(self.usn_suffix)
        self.apache = ApacheService(self.ports.http_port)
        self.ftp = FTPService(self.ports.ftp_port)
        self.dns = DNSService()
        self.dhcp = DHCPService()

    def enable_ip_forwarding(self):
        log("Enabling IP forwarding...")
        run_cmd("sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf")
        run_cmd("sysctl -p")

    def setup_ufw_fallback(self):
        log("Setting up fallback UFW port forwarding")
        before_rules = "/etc/ufw/before.rules"
        with open(before_rules, 'r') as f:
            content = f.read()
        if '*nat' not in content:
            nat_block = f"""*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport {self.ports.http_port} -j REDIRECT --to-port 80
-A PREROUTING -p tcp --dport {self.ports.ftp_port} -j REDIRECT --to-port 21
COMMIT
"""
            with open(before_rules, 'a') as f:
                f.write(nat_block)
            run_cmd("ufw reload")

    def run(self):
        log("\n=== STARTING SYSTEM SETUP ===\n")
        for svc in [self.apache, self.ftp, self.dns, self.dhcp]:
            svc.install()
            svc.start_and_enable()
            svc.configure()

        self.enable_ip_forwarding()
        try:
            PortForwarder(self.ports.http_port, 80).try_iptables()
            PortForwarder(self.ports.ftp_port, 21).try_iptables()
        except Exception:
            self.setup_ufw_fallback()

        self.apache.test()
        self.ftp.test()
        self.dns.test()

        log("\n=== SETUP COMPLETE ===")
        log(f"USN Provided: {self.usn_suffix}")
        log(f"HTTP Port: {self.ports.http_port}, FTP Port: {self.ports.ftp_port}")
        log("Logs saved to ~/setup_log.txt")

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("Please run this script as root (use sudo).")
        exit(1)
    SetupManager().run()
