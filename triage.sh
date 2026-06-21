#!/usr/bin/env bash
#
# triage.sh - Linux DFIR live triage collector
# Collects volatile data first (processes, network, memory-resident info),
# then host/user/persistence context, and hashes everything it saves.
#
# Recolector de triage en vivo para DFIR en Linux. Junta primero lo volátil
# (procesos, red, info residente en memoria) y luego el contexto del host,
# usuarios y persistencia, hasheando todo lo que guarda.
#
# Usage:   sudo ./triage.sh [output_dir]
# Default output: ./triage_<hostname>_<timestamp>
#
# Read-only by design: it reads system state, it does not modify the host.
# Run as root to capture everything (shadow, btmp, some /proc entries).

set -euo pipefail

# --- Setup ------------------------------------------------------------------

TS="$(date +%F_%H-%M-%S)"
HOST="$(hostname 2>/dev/null || echo unknown)"
OUTDIR="${1:-./triage_${HOST}_${TS}}"
MANIFEST=""   # set after OUTDIR exists

mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"   # absolute path
MANIFEST="${OUTDIR}/MANIFEST.sha256"
: > "$MANIFEST"

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Not running as root. Some artifacts (shadow, btmp, /proc) may be incomplete." >&2
fi

echo "[*] Output: $OUTDIR"

# Run a command and save its output to a file under OUTDIR, then hash it.
# save <relative_file> <command> [args...]
save() {
  local out="$OUTDIR/$1"; shift
  "$@" > "$out" 2>/dev/null || true
  if [ ! -s "$out" ]; then
    echo "(no output - command failed or unavailable: $*)" > "$out"
  fi
  ( cd "$OUTDIR" && sha256sum "${out#"$OUTDIR"/}" >> "$MANIFEST" ) || true
}

# Copy a file if it exists, then hash the copy. Follows symlinks so we capture
# the real content (e.g. /etc/os-release often points to /usr/lib/os-release).
grab() {
  local src="$1" dst="$OUTDIR/$2"
  if [ -r "$src" ]; then
    cp -L --preserve=timestamps "$src" "$dst" 2>/dev/null || cp -L "$src" "$dst" 2>/dev/null || return 0
    ( cd "$OUTDIR" && sha256sum "${dst#"$OUTDIR"/}" >> "$MANIFEST" ) || true
  fi
}

# --- 0. Collection metadata -------------------------------------------------

{
  echo "Collected at : $(date --iso-8601=seconds 2>/dev/null || date)"
  echo "Hostname     : $HOST"
  echo "Collector UID: $(id -u) ($(id -un 2>/dev/null || echo '?'))"
  echo "Kernel       : $(uname -a)"
} > "$OUTDIR/_collection_info.txt"
( cd "$OUTDIR" && sha256sum _collection_info.txt >> "$MANIFEST" ) || true

# --- 1. Volatile: processes -------------------------------------------------

echo "[*] Processes / Procesos"
save "proc_ps_auxf.txt"   ps auxf
save "proc_ps_ef.txt"     ps -ef
save "proc_pstree.txt"    pstree -p
save "proc_top.txt"       top -b -n1
save "proc_lsof_deleted.txt" lsof +L1

# --- 2. Volatile: network ---------------------------------------------------

echo "[*] Network / Red"
save "net_listening.txt"   ss -tulpn
save "net_tcp_all.txt"     ss -tanp
save "net_established.txt" ss -tnp state established
save "net_ip_addr.txt"     ip addr
save "net_ip_route.txt"    ip route
save "net_ip_neigh.txt"    ip neigh
grab "/etc/resolv.conf"    "net_resolv.conf"
if command -v iptables >/dev/null 2>&1; then
  save "net_iptables.txt"  iptables -L -n -v
fi
if command -v nft >/dev/null 2>&1; then
  save "net_nft_ruleset.txt" nft list ruleset
fi

# --- 3. Host context --------------------------------------------------------

echo "[*] Host context / Contexto del host"
save "host_uname.txt"      uname -a
grab "/etc/os-release"     "host_os-release"
save "host_uptime.txt"     uptime
save "host_date.txt"       date
save "host_who.txt"        who
save "host_last.txt"       last -a
save "host_lastb.txt"      lastb

# --- 4. Users & auth --------------------------------------------------------

echo "[*] Users / Usuarios"
grab "/etc/passwd"         "user_passwd"
grab "/etc/group"          "user_group"
grab "/etc/shadow"         "user_shadow"   # root only
save "user_uid0.txt"       awk -F: '($3==0){print $1}' /etc/passwd

# --- 5. Persistence ---------------------------------------------------------

echo "[*] Persistence / Persistencia"
save "persist_services.txt"  systemctl list-units --type=service --all
save "persist_systemd_units.txt" ls -la /etc/systemd/system/
save "persist_cron_etc.txt"  ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly
grab "/etc/crontab"          "persist_crontab"
grab "/etc/ld.so.preload"    "persist_ld.so.preload"

# Per-user crontabs / Crontabs por usuario
{
  for u in $(cut -f1 -d: /etc/passwd); do
    echo "== $u =="
    crontab -u "$u" -l 2>/dev/null || true
  done
} > "$OUTDIR/persist_user_crontabs.txt"
( cd "$OUTDIR" && sha256sum persist_user_crontabs.txt >> "$MANIFEST" ) || true

# --- 6. Quick file timeline -------------------------------------------------

echo "[*] Recent files / Archivos recientes"
save "files_modified_24h.txt" find / -xdev -mtime -1 -type f
save "files_suid.txt"         find / -xdev -perm -4000 -type f
save "files_tmp.txt"          find /tmp /dev/shm -type f

# --- Wrap up ----------------------------------------------------------------

# Hash the manifest itself so its integrity can be checked separately.
sha256sum "$MANIFEST" > "${MANIFEST}.sha256"

echo "[*] Done. Artifacts in: $OUTDIR"
echo "[*] Verify later with:  ( cd '$OUTDIR' && sha256sum -c MANIFEST.sha256 )"
