# Linux Forensics Commands

A command reference for digital forensics and incident response (DFIR) on Linux: what to collect, in what order, and the commands that get it. I keep this as a study aid and a field cheat sheet.

*Referencia de comandos para forense digital y respuesta a incidentes (DFIR) en Linux: qué recolectar, en qué orden y con qué comandos. Lo mantengo como ayuda de estudio y referencia de campo.*

> Use this only on systems you own or are authorized to investigate. Preserve evidence: prefer read-only actions and write down everything you do.
>
> *Usalo solo en sistemas propios o que estás autorizada a investigar. Preservá la evidencia: priorizá acciones de solo lectura y documentá todo lo que hacés.*

---

## 0. Golden rules / Reglas de oro

Collect the most volatile data first (RAM, network state, running processes), and only then touch the disk. Once the machine is powered off, the volatile stuff is gone for good. Work on copies, record timestamps, and keep a chain of custody: who did what, when, where, and the hash of every artifact.

*Recolectá primero lo más volátil (RAM, estado de red, procesos en ejecución) y recién después tocá el disco. Apagada la máquina, lo volátil se pierde. Trabajá sobre copias, registrá horarios y mantené la cadena de custodia: quién, qué, cuándo, dónde y el hash de cada artefacto.*

```bash
# Record the whole terminal session / Graba toda la sesión de terminal
script -a "/mnt/evidence/session_$(date +%F_%H-%M-%S).log"

# Hash every artifact you collect / Hashea cada artefacto que recolectás
sha256sum artifact.img > artifact.img.sha256
```

---

## 1. System & host context / Contexto del host

| Command | What it tells you / Qué te dice |
|---------|---------------------------------|
| `uname -a` | kernel, architecture, hostname / kernel, arquitectura, hostname |
| `cat /etc/os-release` | distro and version / distribución y versión |
| `hostnamectl` | host identity, boot ID / identidad del host, boot ID |
| `uptime` | how long it has been up / hace cuánto está encendido |
| `date` / `timedatectl` | current time and timezone (key for timelines) / hora y zona horaria (clave para las líneas de tiempo) |
| `w` / `who` | who is logged in right now / quién está conectado ahora |
| `last -a` | login history (`/var/log/wtmp`) / historial de logins |
| `lastb` | failed logins (`/var/log/btmp`, needs root) / logins fallidos (necesita root) |

---

## 2. Users & authentication / Usuarios y autenticación

| Command | Purpose / Propósito |
|---------|---------------------|
| `cat /etc/passwd` | all accounts (watch for UID 0 that isn't root, odd shells) / todas las cuentas (ojo con UID 0 que no sea root, o shells raras) |
| `sudo cat /etc/shadow` | password hashes and aging (root only) / hashes y caducidad de contraseñas (solo root) |
| `cat /etc/group` | group membership (who's in `sudo`/`wheel`) / membresía de grupos (quién está en `sudo`/`wheel`) |
| `getent passwd` | accounts including directory services / cuentas incluyendo servicios de directorio |
| `sudo grep -i sudo /var/log/auth.log` | sudo usage / uso de sudo |
| `awk -F: '($3==0){print $1}' /etc/passwd` | every UID-0 (root-equivalent) account / toda cuenta con UID 0 (equivalente a root) |

---

## 3. Processes & memory / Procesos y memoria (volatile — collect early)

| Command | Purpose / Propósito |
|---------|---------------------|
| `ps aux` / `ps -ef` | snapshot of all processes / foto de todos los procesos |
| `ps auxf` | process tree (spot suspicious parents) / árbol de procesos (padres sospechosos) |
| `pstree -p` | parent/child relationships with PIDs / relaciones padre/hijo con PIDs |
| `top -b -n1` | one non-interactive resource snapshot / una foto de recursos, no interactiva |
| `ls -l /proc/<PID>/exe` | real path of the binary (catches deleted/renamed) / ruta real del binario (detecta borrados/renombrados) |
| `cat /proc/<PID>/cmdline \| tr '\0' ' '` | exact command line used to launch / línea de comando exacta de lanzamiento |
| `ls -l /proc/<PID>/cwd` | working directory of the process / directorio de trabajo del proceso |
| `lsof -p <PID>` | files and sockets the process has open / archivos y sockets abiertos por el proceso |
| `lsof +L1` | open files with link count 0 (deleted but still running) / archivos abiertos con link count 0 (borrados pero aún en ejecución) |

For deep RAM analysis you capture memory with LiME or AVML and then analyze it with Volatility.

*Para análisis profundo de RAM se captura memoria con LiME o AVML y luego se analiza con Volatility.*

---

## 4. Network / Red (volatile — collect early)

| Command | Purpose / Propósito |
|---------|---------------------|
| `ss -tulpn` | listening ports plus owning process / puertos a la escucha y su proceso |
| `ss -tanp` | all TCP connections, states and process / todas las conexiones TCP, estados y proceso |
| `netstat -anp` | same idea on older systems (legacy) / lo mismo en sistemas viejos (legacy) |
| `ip addr` / `ip a` | interfaces and IPs / interfaces e IPs |
| `ip route` | routing table / tabla de ruteo |
| `ip neigh` | ARP cache (recent peers) / caché ARP (peers recientes) |
| `cat /etc/resolv.conf` | configured DNS servers / servidores DNS configurados |
| `sudo iptables -L -n -v` / `sudo nft list ruleset` | firewall rules / reglas de firewall |

---

## 5. Persistence / Persistencia — where attackers hide

| Location / command | What to check / Qué revisar |
|--------------------|-----------------------------|
| `crontab -l`, `ls -la /etc/cron*`, `/var/spool/cron/` | scheduled jobs / tareas programadas |
| `systemctl list-units --type=service` | running services / servicios en ejecución |
| `ls -la /etc/systemd/system/ ~/.config/systemd/user/` | custom or rogue service units / units de servicio propias o maliciosas |
| `ls -la /etc/init.d/ /etc/rc*.d/` | legacy startup scripts / scripts de arranque legacy |
| `~/.bashrc`, `~/.bash_profile`, `/etc/profile.d/` | shell-startup persistence / persistencia por arranque de shell |
| `cat ~/.ssh/authorized_keys` | unauthorized SSH keys mean backdoor access / claves SSH no autorizadas = acceso por la puerta de atrás |
| `ls -la /etc/ld.so.preload` | library-preload hijacking / secuestro por precarga de librerías |

---

## 6. Files & timeline / Archivos y línea de tiempo

| Command | Purpose / Propósito |
|---------|---------------------|
| `ls -la` / `ls -lat` | list hidden files, sorted by mtime / lista archivos ocultos, ordenados por mtime |
| `stat file` | access/modify/change (MAC) times / tiempos de acceso/modificación/cambio (MAC) |
| `find / -mtime -1 -type f 2>/dev/null` | files modified in the last 24h / archivos modificados en las últimas 24h |
| `find / -newermt "$(date -d '2 days ago' +%F)" -type f 2>/dev/null` | files changed since a given date / archivos cambiados desde una fecha dada |
| `find / -perm -4000 -type f 2>/dev/null` | SUID binaries (privilege-escalation hunting) / binarios SUID (caza de escalada de privilegios) |
| `find / -name ".*" -type f 2>/dev/null` | hidden files / archivos ocultos |
| `find /tmp /dev/shm -type f 2>/dev/null` | common malware drop spots / lugares típicos donde cae malware |
| `file suspicious_bin` | real file type, not just the extension / tipo real del archivo, no solo la extensión |
| `strings -n 8 suspicious_bin` | readable strings (IPs, URLs, commands) / cadenas legibles (IPs, URLs, comandos) |
| `sha256sum file` | hash for IOC lookup / VirusTotal / hash para buscar IOCs o en VirusTotal |

---

## 7. Logs

| Source / Fuente | Command / path |
|-----------------|----------------|
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
# Logins SSH fallidos agrupados por IP de origen (triage rápido de fuerza bruta)
grep "Failed password" /var/log/auth.log \
  | grep -oE "from [0-9.]+" | awk '{print $2}' \
  | sort | uniq -c | sort -rn
```

---

## 8. Disk & storage / Disco y almacenamiento

| Command | Purpose / Propósito |
|---------|---------------------|
| `df -h` | mounted filesystems and usage / sistemas de archivos montados y uso |
| `lsblk` | block devices and partitions / dispositivos de bloque y particiones |
| `mount` | what's mounted and how (ro/rw) / qué está montado y cómo (ro/rw) |
| `sudo dd if=/dev/sdX of=/mnt/evidence/disk.img bs=4M conv=noerror,sync status=progress` | raw disk image to external media / imagen cruda del disco hacia medio externo |
| `losetup`, `dmsetup` | work with images and loop devices / trabajar con imágenes y loop devices |

Write the image to external media, never to the disk you are imaging. For real acquisitions use a write blocker and a forensic imager like `dc3dd`, `dcfldd` or Guymager.

*Escribí la imagen en un medio externo, nunca en el disco que estás copiando. Para adquisiciones reales usá un write blocker y un imager forense como `dc3dd`, `dcfldd` o Guymager.*

---

## 9. Quick triage one-liners / One-liners de triage

```bash
# Top processes by memory / Procesos que más memoria usan
ps aux --sort=-%mem | head

# Established outbound connections + process / Conexiones salientes establecidas + proceso
ss -tnp state established

# All scheduled tasks across every user / Todas las tareas programadas de cada usuario
for u in $(cut -f1 -d: /etc/passwd); do
  echo "== $u =="
  crontab -u "$u" -l 2>/dev/null
done

# Recently modified files in web root (possible webshell)
# Archivos modificados hace poco en el web root (posible webshell)
find /var/www -type f -mmin -120 2>/dev/null

# Listening services not bound to localhost / Servicios a la escucha no atados a localhost
ss -tulpn | grep -vE '127.0.0.1|::1'
```

---

## 10. Where to go deeper / Para ir más a fondo

- Memory analysis / análisis de memoria: Volatility 3, LiME, AVML
- Disk and timeline / disco y línea de tiempo: Sleuth Kit (`fls`, `mactime`), Autopsy, `log2timeline`/`plaso`
- Triage frameworks: UAC (Unix-like Artifacts Collector), CyLR

There's also a `triage.sh` in this repo that runs the early, volatile collection in order and hashes what it saves.

*También hay un `triage.sh` en este repo que corre la recolección volátil temprana en orden y hashea lo que guarda.*

---

Made by [Catalina Carlen](https://github.com/catalinacarlen) · Cybersecurity, Universidad de Palermo
