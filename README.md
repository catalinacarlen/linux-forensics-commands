# Linux Forensics Commands

What to collect on a Linux box during an incident, in what order, and the exact commands that get it. I use it to study and to grab mid-incident.

> Run this only on systems you own or are authorized to investigate. Favor read-only actions and write down everything you do.

[Versión en español más abajo.](#español)

---

## English

### 0. Golden rules

Collect the most volatile data first (RAM, network state, running processes), and only then touch the disk. Once the machine is powered off, the volatile stuff is gone for good. Work on copies, record timestamps, and keep a chain of custody: who did what, when, where, and the hash of every artifact.

```bash
# Record the whole terminal session
script -a "/mnt/evidence/session_$(date +%F_%H-%M-%S).log"

# Hash every artifact you collect
sha256sum artifact.img > artifact.img.sha256
```

### 1. System & host context

| Command | What it tells you |
|---------|-------------------|
| `uname -a` | kernel, architecture, hostname |
| `cat /etc/os-release` | distro and version |
| `hostnamectl` | host identity, boot ID |
| `uptime` | how long it has been up |
| `date` / `timedatectl` | current time and timezone (key for timelines) |
| `w` / `who` | who is logged in right now |
| `last -a` | login history (`/var/log/wtmp`) |
| `lastb` | failed logins (`/var/log/btmp`, needs root) |

### 2. Users & authentication

| Command | Purpose |
|---------|---------|
| `cat /etc/passwd` | all accounts (watch for UID 0 that isn't root, odd shells) |
| `sudo cat /etc/shadow` | password hashes and aging (root only) |
| `cat /etc/group` | group membership (who's in `sudo`/`wheel`) |
| `getent passwd` | accounts including directory services |
| `sudo grep -i sudo /var/log/auth.log` | sudo usage |
| `awk -F: '($3==0){print $1}' /etc/passwd` | every UID-0 (root-equivalent) account |

### 3. Processes & memory (volatile, collect early)

| Command | Purpose |
|---------|---------|
| `ps aux` / `ps -ef` | snapshot of all processes |
| `ps auxf` | process tree (spot suspicious parents) |
| `pstree -p` | parent/child relationships with PIDs |
| `top -b -n1` | one non-interactive resource snapshot |
| `ls -l /proc/<PID>/exe` | real path of the binary (catches deleted/renamed) |
| `cat /proc/<PID>/cmdline \| tr '\0' ' '` | exact command line used to launch |
| `ls -l /proc/<PID>/cwd` | working directory of the process |
| `lsof -p <PID>` | files and sockets the process has open |
| `lsof +L1` | open files with link count 0 (deleted but still running) |

For deep RAM analysis you capture memory with LiME or AVML and then analyze it with Volatility.

### 4. Network (volatile, collect early)

| Command | Purpose |
|---------|---------|
| `ss -tulpn` | listening ports plus owning process |
| `ss -tanp` | all TCP connections, states and process |
| `netstat -anp` | same idea on older systems (legacy) |
| `ip addr` / `ip a` | interfaces and IPs |
| `ip route` | routing table |
| `ip neigh` | ARP cache (recent peers) |
| `cat /etc/resolv.conf` | configured DNS servers |
| `sudo iptables -L -n -v` / `sudo nft list ruleset` | firewall rules |

### 5. Persistence (where attackers hide)

| Location / command | What to check |
|--------------------|---------------|
| `crontab -l`, `ls -la /etc/cron*`, `/var/spool/cron/` | scheduled jobs |
| `systemctl list-units --type=service` | running services |
| `ls -la /etc/systemd/system/ ~/.config/systemd/user/` | custom or rogue service units |
| `ls -la /etc/init.d/ /etc/rc*.d/` | legacy startup scripts |
| `~/.bashrc`, `~/.bash_profile`, `/etc/profile.d/` | shell-startup persistence |
| `cat ~/.ssh/authorized_keys` | unauthorized SSH keys mean backdoor access |
| `ls -la /etc/ld.so.preload` | library-preload hijacking |

### 6. Files & timeline

| Command | Purpose |
|---------|---------|
| `ls -la` / `ls -lat` | list hidden files, sorted by mtime |
| `stat file` | access/modify/change (MAC) times |
| `find / -mtime -1 -type f 2>/dev/null` | files modified in the last 24h |
| `find / -newermt "$(date -d '2 days ago' +%F)" -type f 2>/dev/null` | files changed since a given date |
| `find / -perm -4000 -type f 2>/dev/null` | SUID binaries (privilege-escalation hunting) |
| `find / -name ".*" -type f 2>/dev/null` | hidden files |
| `find /tmp /dev/shm -type f 2>/dev/null` | common malware drop spots |
| `file suspicious_bin` | real file type, not just the extension |
| `strings -n 8 suspicious_bin` | readable strings (IPs, URLs, commands) |
| `sha256sum file` | hash for IOC lookup / VirusTotal |

### 7. Logs

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

### 8. Disk & storage

| Command | Purpose |
|---------|---------|
| `df -h` | mounted filesystems and usage |
| `lsblk` | block devices and partitions |
| `mount` | what's mounted and how (ro/rw) |
| `sudo dd if=/dev/sdX of=/mnt/evidence/disk.img bs=4M conv=noerror,sync status=progress` | raw disk image to external media |
| `losetup`, `dmsetup` | work with images and loop devices |

Write the image to external media, never to the disk you are imaging. For real acquisitions use a write blocker and a forensic imager like `dc3dd`, `dcfldd` or Guymager.

### 9. Quick triage one-liners

```bash
# Top processes by memory
ps aux --sort=-%mem | head

# Established outbound connections + process
ss -tnp state established

# All scheduled tasks across every user
for u in $(cut -f1 -d: /etc/passwd); do
  echo "== $u =="
  crontab -u "$u" -l 2>/dev/null
done

# Recently modified files in web root (possible webshell)
find /var/www -type f -mmin -120 2>/dev/null

# Listening services not bound to localhost
ss -tulpn | grep -vE '127.0.0.1|::1'
```

### 10. Where to go deeper

- Memory analysis: Volatility 3, LiME, AVML
- Disk and timeline: Sleuth Kit (`fls`, `mactime`), Autopsy, `log2timeline`/`plaso`
- Triage frameworks: UAC (Unix-like Artifacts Collector), CyLR

There's also a `triage.sh` in this repo that runs the early, volatile collection in order and hashes what it saves.

---

## Español

Qué recolectar en una máquina Linux durante un incidente, en qué orden, y con qué comandos. Lo uso para estudiar y para tener a mano en pleno incidente.

> Usalo solo en sistemas propios o que estás autorizada a investigar. Priorizá acciones de solo lectura y documentá todo lo que hacés.

### 0. Reglas de oro

Recolectá primero lo más volátil (RAM, estado de red, procesos en ejecución) y recién después tocá el disco. Apagada la máquina, lo volátil se pierde. Trabajá sobre copias, registrá horarios y mantené la cadena de custodia: quién, qué, cuándo, dónde y el hash de cada artefacto.

```bash
# Graba toda la sesión de terminal
script -a "/mnt/evidence/session_$(date +%F_%H-%M-%S).log"

# Hashea cada artefacto que recolectás
sha256sum artifact.img > artifact.img.sha256
```

### 1. Contexto del host

| Comando | Qué te dice |
|---------|-------------|
| `uname -a` | kernel, arquitectura, hostname |
| `cat /etc/os-release` | distribución y versión |
| `hostnamectl` | identidad del host, boot ID |
| `uptime` | hace cuánto está encendido |
| `date` / `timedatectl` | hora y zona horaria (clave para las líneas de tiempo) |
| `w` / `who` | quién está conectado ahora |
| `last -a` | historial de logins (`/var/log/wtmp`) |
| `lastb` | logins fallidos (`/var/log/btmp`, necesita root) |

### 2. Usuarios y autenticación

| Comando | Propósito |
|---------|-----------|
| `cat /etc/passwd` | todas las cuentas (ojo con UID 0 que no sea root, o shells raras) |
| `sudo cat /etc/shadow` | hashes y caducidad de contraseñas (solo root) |
| `cat /etc/group` | membresía de grupos (quién está en `sudo`/`wheel`) |
| `getent passwd` | cuentas incluyendo servicios de directorio |
| `sudo grep -i sudo /var/log/auth.log` | uso de sudo |
| `awk -F: '($3==0){print $1}' /etc/passwd` | toda cuenta con UID 0 (equivalente a root) |

### 3. Procesos y memoria (volátil, recolectar temprano)

| Comando | Propósito |
|---------|-----------|
| `ps aux` / `ps -ef` | foto de todos los procesos |
| `ps auxf` | árbol de procesos (padres sospechosos) |
| `pstree -p` | relaciones padre/hijo con PIDs |
| `top -b -n1` | una foto de recursos, no interactiva |
| `ls -l /proc/<PID>/exe` | ruta real del binario (detecta borrados/renombrados) |
| `cat /proc/<PID>/cmdline \| tr '\0' ' '` | línea de comando exacta de lanzamiento |
| `ls -l /proc/<PID>/cwd` | directorio de trabajo del proceso |
| `lsof -p <PID>` | archivos y sockets abiertos por el proceso |
| `lsof +L1` | archivos abiertos con link count 0 (borrados pero aún en ejecución) |

Para análisis profundo de RAM se captura memoria con LiME o AVML y luego se analiza con Volatility.

### 4. Red (volátil, recolectar temprano)

| Comando | Propósito |
|---------|-----------|
| `ss -tulpn` | puertos a la escucha y su proceso |
| `ss -tanp` | todas las conexiones TCP, estados y proceso |
| `netstat -anp` | lo mismo en sistemas viejos (legacy) |
| `ip addr` / `ip a` | interfaces e IPs |
| `ip route` | tabla de ruteo |
| `ip neigh` | caché ARP (peers recientes) |
| `cat /etc/resolv.conf` | servidores DNS configurados |
| `sudo iptables -L -n -v` / `sudo nft list ruleset` | reglas de firewall |

### 5. Persistencia (dónde se esconden los atacantes)

| Ubicación / comando | Qué revisar |
|---------------------|-------------|
| `crontab -l`, `ls -la /etc/cron*`, `/var/spool/cron/` | tareas programadas |
| `systemctl list-units --type=service` | servicios en ejecución |
| `ls -la /etc/systemd/system/ ~/.config/systemd/user/` | units de servicio propias o maliciosas |
| `ls -la /etc/init.d/ /etc/rc*.d/` | scripts de arranque legacy |
| `~/.bashrc`, `~/.bash_profile`, `/etc/profile.d/` | persistencia por arranque de shell |
| `cat ~/.ssh/authorized_keys` | claves SSH no autorizadas = acceso por la puerta de atrás |
| `ls -la /etc/ld.so.preload` | secuestro por precarga de librerías |

### 6. Archivos y línea de tiempo

| Comando | Propósito |
|---------|-----------|
| `ls -la` / `ls -lat` | lista archivos ocultos, ordenados por mtime |
| `stat file` | tiempos de acceso/modificación/cambio (MAC) |
| `find / -mtime -1 -type f 2>/dev/null` | archivos modificados en las últimas 24h |
| `find / -newermt "$(date -d '2 days ago' +%F)" -type f 2>/dev/null` | archivos cambiados desde una fecha dada |
| `find / -perm -4000 -type f 2>/dev/null` | binarios SUID (caza de escalada de privilegios) |
| `find / -name ".*" -type f 2>/dev/null` | archivos ocultos |
| `find /tmp /dev/shm -type f 2>/dev/null` | lugares típicos donde cae malware |
| `file suspicious_bin` | tipo real del archivo, no solo la extensión |
| `strings -n 8 suspicious_bin` | cadenas legibles (IPs, URLs, comandos) |
| `sha256sum file` | hash para buscar IOCs o en VirusTotal |

### 7. Logs

| Fuente | Comando / ruta |
|--------|----------------|
| Auth (Debian/Ubuntu) | `/var/log/auth.log` |
| Auth (RHEL/CentOS) | `/var/log/secure` |
| Kernel / sistema | `dmesg`, `/var/log/syslog`, `/var/log/messages` |
| Journal de systemd | `journalctl -xe`, `journalctl --since "1 hour ago"` |
| Journal por arranque | `journalctl -b` |
| Servidor web | `/var/log/apache2/`, `/var/log/nginx/` |
| Historial de shell | `cat ~/.bash_history`, `history` |
| Instalación de paquetes | `/var/log/dpkg.log`, `/var/log/yum.log` |

```bash
# Logins SSH fallidos agrupados por IP de origen (triage rápido de fuerza bruta)
grep "Failed password" /var/log/auth.log \
  | grep -oE "from [0-9.]+" | awk '{print $2}' \
  | sort | uniq -c | sort -rn
```

### 8. Disco y almacenamiento

| Comando | Propósito |
|---------|-----------|
| `df -h` | sistemas de archivos montados y uso |
| `lsblk` | dispositivos de bloque y particiones |
| `mount` | qué está montado y cómo (ro/rw) |
| `sudo dd if=/dev/sdX of=/mnt/evidence/disk.img bs=4M conv=noerror,sync status=progress` | imagen cruda del disco hacia medio externo |
| `losetup`, `dmsetup` | trabajar con imágenes y loop devices |

Escribí la imagen en un medio externo, nunca en el disco que estás copiando. Para adquisiciones reales usá un write blocker y un imager forense como `dc3dd`, `dcfldd` o Guymager.

### 9. One-liners de triage

```bash
# Procesos que más memoria usan
ps aux --sort=-%mem | head

# Conexiones salientes establecidas + proceso
ss -tnp state established

# Todas las tareas programadas de cada usuario
for u in $(cut -f1 -d: /etc/passwd); do
  echo "== $u =="
  crontab -u "$u" -l 2>/dev/null
done

# Archivos modificados hace poco en el web root (posible webshell)
find /var/www -type f -mmin -120 2>/dev/null

# Servicios a la escucha no atados a localhost
ss -tulpn | grep -vE '127.0.0.1|::1'
```

### 10. Para ir más a fondo

- Análisis de memoria: Volatility 3, LiME, AVML
- Disco y línea de tiempo: Sleuth Kit (`fls`, `mactime`), Autopsy, `log2timeline`/`plaso`
- Frameworks de triage: UAC (Unix-like Artifacts Collector), CyLR

También hay un `triage.sh` en este repo que corre la recolección volátil temprana en orden y hashea lo que guarda.

---

Made by [Catalina Carlen](https://github.com/catalinacarlen) · Cybersecurity, Universidad de Palermo
