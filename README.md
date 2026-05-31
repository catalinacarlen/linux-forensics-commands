# Linux Forensics Commands

A practical command reference for **digital forensics and incident response (DFIR) on Linux** — what to collect, in what order, and the commands that get it. Built as a study aid and field reference.

> Referencia práctica de comandos para **forense digital y respuesta a incidentes (DFIR) en Linux**: qué recolectar, en qué orden y con qué comandos. Pensada como ayuda de estudio y referencia de campo.

> ⚠️ For use on systems you own or are authorized to investigate. Forensic work should preserve evidence — prefer read-only actions and document everything.

---

## 0. Golden rules

- **Order of volatility:** collect the most volatile data first — RAM, network connections, running processes — *then* disk. Once you power off, volatile data is gone.
- **Don't contaminate:** work on **copies/images**, note timestamps, and record every command you run (`script` logs a whole session).
- **Document the chain of custody:** who, what, when, where, hashes of every artifact.

```bash
script -a /evidence/session_$(date +%F_%T).log   # record the whole terminal session
sha256sum artifact.img > artifact.img.sha256      # hash every artifact you collect
```

---

## 1. System & host context

| Command | What it tells you |
|---------|-------------------|
| `uname -a` | kernel, architecture, hostname |
| `cat /etc/os-release` | distro and version |
| `hostnamectl` | host identity, boot ID |
| `uptime` | how long the system has been up |
| `date` / `timedatectl` | current time & timezone (critical for timelines) |
| `w` / `who` | who is logged in **right now** |
| `last -a` | login history (`/var/log/wtmp`) |
| `lastb` | failed login attempts (`/var/log/btmp`) |

---

## 2. Users & authentication

| Command | Purpose |
|---------|---------|
| `cat /etc/passwd` | all accounts (look for UID 0 ≠ root, odd shells) |
| `cat /etc/shadow` | password hashes & aging (root only) |
| `cat /etc/group` | group membership (who's in `sudo`/`wheel`) |
| `getent passwd` | accounts incl. directory services |
| `sudo grep -i sudo /var/log/auth.log` | sudo usage |
| `awk -F: '$3==0{print $1}' /etc/passwd` | **find all UID-0 (root-equivalent) accounts** |

---

## 3. Processes & memory (volatile — collect early)

| Command | Purpose |
|---------|---------|
| `ps aux` / `ps -ef` | snapshot of all processes |
| `ps auxf` | process **tree** (spot suspicious parents) |
| `top` / `htop` | live resource usage |
| `pstree -p` | parent/child relationships with PIDs |
| `ls -l /proc/<PID>/exe` | real path of a process binary (catches deleted/renamed) |
| `cat /proc/<PID>/cmdline` | exact command line used to launch |
| `ls -l /proc/<PID>/cwd` | working directory of a process |
| `lsof -p <PID>` | files & sockets a process has open |
| `lsof +L1` | **open files with link count 0 (deleted but still running)** |

> RAM capture (for deep analysis) uses tools like **LiME** or **AVML**, analyzed later with **Volatility**.

---

## 4. Network (volatile — collect early)

| Command | Purpose |
|---------|---------|
| `ss -tulpn` | listening ports + owning process (modern `netstat`) |
| `ss -tan` | all TCP connections & states |
| `netstat -anob` | connections (legacy) |
| `ip addr` / `ip a` | interfaces & IPs |
| `ip route` | routing table |
| `ip neigh` | ARP cache (recent peers) |
| `cat /etc/resolv.conf` | configured DNS servers |
| `iptables -L -n -v` / `nft list ruleset` | firewall rules |

---

## 5. Persistence — where attackers hide

| Location / command | What to check |
|--------------------|---------------|
| `crontab -l` ; `ls -la /etc/cron*` ; `/var/spool/cron/` | scheduled jobs |
| `systemctl list-units --type=service` | running services |
| `ls -la /etc/systemd/system/ ~/.config/systemd/user/` | custom/rogue service units |
| `ls -la /etc/init.d/ /etc/rc*.d/` | legacy startup scripts |
| `~/.bashrc`, `~/.bash_profile`, `/etc/profile.d/` | shell-startup persistence |
| `cat ~/.ssh/authorized_keys` | **unauthorized SSH keys = backdoor access** |
| `ls -la /etc/ld.so.preload` | library-preload hijacking |

---

## 6. Files & timeline

| Command | Purpose |
|---------|---------|
| `ls -la` / `ls -lat` | list incl. hidden, sorted by mtime |
| `stat file` | access/modify/change (MAC) times |
| `find / -mtime -1 -type f 2>/dev/null` | files **modified in the last 24h** |
| `find / -newermt "2024-01-01" ! -newermt "2024-01-02"` | files changed in a date window |
| `find / -perm -4000 -type f 2>/dev/null` | **SUID binaries (privilege-escalation hunting)** |
| `find / -name ".*" -type f 2>/dev/null` | hidden files |
| `find /tmp /dev/shm -type f 2>/dev/null` | common malware drop spots |
| `file suspicious_bin` | identify real file type (not just extension) |
| `strings -n 8 suspicious_bin` | readable strings (IPs, URLs, commands) |
| `sha256sum file` | hash for IOC lookup / VirusTotal |

---

## 7. Logs (the analyst's gold mine)

| Source | Command / path |
|--------|----------------|
| Auth (Debian/Ubuntu) | `/var/log/auth.log` |
| Auth (RHEL/CentOS) | `/var/log/secure` |
| Kernel / system | `dmesg`, `/var/log/syslog`, `/var/log/messages` |
| systemd journal | `journalctl -xe`, `journalctl --since "1 hour ago"` |
| Per-boot journal | `journalctl -b` |
| Web server | `/var/log/apache2/`, `/var/log/nginx/` |
| Shell history | `cat ~/.bash_history`, `history` |
| Package installs | `/var/log/dpkg.log`, `/var/log/yum.log` |

```bash
# Failed SSH logins grouped by source IP (quick brute-force triage)
grep "Failed password" /var/log/auth.log \
  | grep -oE "from [0-9.]+" | awk '{print $2}' \
  | sort | uniq -c | sort -rn
```

---

## 8. Disk & storage

| Command | Purpose |
|---------|---------|
| `df -h` | mounted filesystems & usage |
| `lsblk` | block devices & partitions |
| `mount` | what's mounted and how (ro/rw) |
| `dd if=/dev/sdX of=/eviden.img bs=4M conv=noerror,sync` | raw disk image (prefer `dcfldd`/write-blocker) |
| `dmsetup`, `losetup` | work with images/loop devices |

> For real acquisitions use a **write blocker** and forensic imagers (`dc3dd`, `dcfldd`, `Guymager`).

---

## 9. Quick triage one-liners

```bash
# Top processes by memory
ps aux --sort=-%mem | head

# Established outbound connections + process
ss -tnp state established

# All scheduled tasks across every user
for u in $(cut -f1 -d: /etc/passwd); do echo "== $u =="; crontab -u "$u" -l 2>/dev/null; done

# Recently modified files in web root (possible webshell)
find /var/www -type f -mmin -120 2>/dev/null

# Listening services not bound to localhost
ss -tulpn | grep -v '127.0.0.1\|::1'
```

---

## 10. Where to go deeper

- **Memory analysis:** Volatility 3, LiME, AVML
- **Disk/timeline:** Sleuth Kit (`fls`, `mactime`), Autopsy, `log2timeline`/`plaso`
- **Triage frameworks:** UAC (Unix-like Artifacts Collector), CyLR

---

Made by [Catalina Carlen](https://github.com/catalinacarlen) · Cybersecurity — Universidad de Palermo
