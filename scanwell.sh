#!/usr/bin/env bash
set -euo pipefail
# ══════════════════════════════════════════════════════════════════════════════
# scanwell.sh v7.3 — Full-stack CVE scanner (OpenClaw + standalone)
# Scans: OS packages (debsecan/brew), container images (Trivy), npm/pip deps,
#        secrets hygiene, version CVE check, osv-scanner, semgrep SAST, AgentShield CP upload
# Usage:  sudo bash scanwell.sh [--install]
#         --install: installs required tools; prompts to securely add optional tools (osv-scanner, semgrep)
# Works without OpenClaw/containers — host-only scans run automatically.
# ══════════════════════════════════════════════════════════════════════════════

# ── USER CONFIGURATION ────────────────────────────────────────────────────────
# Edit these to match your deployment before running.
OPENCLAW_USER="${OPENCLAW_USER:-openclaw}"          # user that owns the Podman containers
ADMIN_USER="${ADMIN_USER:-lord}"                    # admin/sudo user running this script
OPENCLAW_DOCKER_DIR="${OPENCLAW_DOCKER_DIR:-/home/${OPENCLAW_USER}/openclaw-docker}"
DOPPLER_TOKEN_FILE="${DOPPLER_TOKEN_FILE:-/home/${OPENCLAW_USER}/.doppler/service-token}"
# ── END USER CONFIGURATION ────────────────────────────────────────────────────

# ── OS DETECTION ──────────────────────────────────────────────────────────────
OS_TYPE="$(uname -s)"
IS_MACOS=false
[[ "$OS_TYPE" == "Darwin" ]] && IS_MACOS=true && \
  echo "[OS] macOS detected — Linux-only scans (debsecan) will be skipped"

# ── PORTABLE HOME DIRECTORY RESOLUTION (Linux + macOS) ────────────────────────
_user_home() { eval echo "~${1}" 2>/dev/null || echo "/home/${1}"; }
OPENCLAW_HOME=$(_user_home "$OPENCLAW_USER")
ADMIN_HOME=$(_user_home "$ADMIN_USER")

# ── INTERACTIVE SETUP (TTY only — auto-skipped in cron/pipe/CI) ───────────────
if [[ -t 0 && -t 1 ]]; then
  echo "════════════════════════════════════════════════════════════════"
  echo " scanwell.sh v7.3 — Confirm Configuration"
  echo "════════════════════════════════════════════════════════════════"
  printf "  OPENCLAW_USER       = %s\n" "$OPENCLAW_USER"
  printf "  ADMIN_USER          = %s\n" "$ADMIN_USER"
  printf "  OPENCLAW_DOCKER_DIR = %s\n" "$OPENCLAW_DOCKER_DIR"
  printf "  DOPPLER_TOKEN_FILE  = %s\n" "$DOPPLER_TOKEN_FILE"
  printf "  OPENCLAW_HOME       = %s\n" "$OPENCLAW_HOME"
  printf "  ADMIN_HOME          = %s\n" "$ADMIN_HOME"
  echo ""
  read -rp " Correct? [Y/n] " _ans
  if [[ "${_ans,,}" == "n" ]]; then
    read -rp " OPENCLAW_USER [$OPENCLAW_USER]: " _in
    [[ -n "$_in" ]] && OPENCLAW_USER="$_in" && OPENCLAW_HOME=$(_user_home "$OPENCLAW_USER")
    read -rp " ADMIN_USER [$ADMIN_USER]: " _in
    [[ -n "$_in" ]] && ADMIN_USER="$_in" && ADMIN_HOME=$(_user_home "$ADMIN_USER")
    read -rp " OPENCLAW_DOCKER_DIR [$OPENCLAW_DOCKER_DIR]: " _in
    [[ -n "$_in" ]] && OPENCLAW_DOCKER_DIR="$_in"
    read -rp " DOPPLER_TOKEN_FILE [$DOPPLER_TOKEN_FILE]: " _in
    [[ -n "$_in" ]] && DOPPLER_TOKEN_FILE="$_in"
  fi
  echo "════════════════════════════════════════════════════════════════"
fi

# ── RUNTIME DETECTION ─────────────────────────────────────────────────────────
# SAFETY RULE: Rootless Podman (OPENCLAW_USER) is ALWAYS preferred.
# Docker is only used when OPENCLAW_USER does not exist on this system.
# This prevents Docker from ever interacting with Podman-managed containers.
OC_UID=""
CONTAINER_RUNTIME=""

if id "$OPENCLAW_USER" &>/dev/null && command -v podman &>/dev/null; then
  OC_UID=$(id -u "$OPENCLAW_USER" 2>/dev/null) || { echo "[ERROR] Cannot get ${OPENCLAW_USER} UID"; exit 1; }
  CONTAINER_RUNTIME="podman"
  # Safety check: verify rootless Podman is functional and openclaw-agent is actually running
  _PODMAN_CHECK=$(sudo su - "$OPENCLAW_USER" -s /bin/bash -c \
    "XDG_RUNTIME_DIR=/run/user/${OC_UID} podman ps --format '{{.Names}}'" 2>/dev/null || true)
  if ! echo "$_PODMAN_CHECK" | grep -q "openclaw-agent"; then
    echo "[RUNTIME] openclaw-agent not running — container scans will be skipped"
    CONTAINER_RUNTIME=""
  else
    echo "[RUNTIME] Rootless Podman confirmed — openclaw UID=${OC_UID}, openclaw-agent running"
  fi
elif command -v docker &>/dev/null; then
  CONTAINER_RUNTIME="docker"
  echo "[RUNTIME] Docker detected — running as $(whoami)"
  # Docker requires group membership — warn and skip container scans if inaccessible
  if ! docker info &>/dev/null; then
    echo "[RUNTIME] Docker not accessible to $(whoami) — container scans will be skipped"
    echo "          To enable: sudo usermod -aG docker $(whoami) && newgrp docker"
    CONTAINER_RUNTIME=""
  elif command -v podman &>/dev/null; then
    echo "[RUNTIME] WARNING: Both Docker and Podman found, but openclaw user is absent."
    echo "          Using Docker. If this is wrong, create the openclaw user first."
  fi
else
  echo "[RUNTIME] No container runtime found — container scans will be skipped"
  echo "          Host-only scans (secrets, OS packages, npm/pip, Ollama, Tailscale) will run."
fi

# container_exec — runs a command in the appropriate runtime context
# For Podman: switches to openclaw user with XDG_RUNTIME_DIR set
# For Docker: runs directly (docker exec requires docker group or root)
container_exec() {
  if [[ "$CONTAINER_RUNTIME" == "podman" ]]; then
    sudo su - "$OPENCLAW_USER" -s /bin/bash -c \
      "XDG_RUNTIME_DIR=/run/user/${OC_UID} $1" 2>/dev/null
  elif [[ -n "$CONTAINER_RUNTIME" ]]; then
    # Only run for non-empty runtime — avoids bash treating "exec ..." as a builtin
    bash -c "$1" 2>/dev/null
  fi
  # Empty CONTAINER_RUNTIME: return nothing, exit 0
}

# container_save — saves a container image to a tarball for Trivy scanning
container_save() {
  local image="$1" tarball="$2"
  if [[ "$CONTAINER_RUNTIME" == "podman" ]]; then
    sudo su - "$OPENCLAW_USER" -s /bin/bash -c \
      "XDG_RUNTIME_DIR=/run/user/${OC_UID} \
       podman save --format docker-archive -o '${tarball}' '${image}'" 2>/dev/null && \
      sudo chmod 644 "$tarball"
  else
    docker save "${image}" -o "${tarball}" 2>/dev/null
  fi
}

DOCKER_DIR="$OPENCLAW_DOCKER_DIR"
if [[ "$IS_MACOS" == "true" ]]; then
  LOG_DIR="${HOME}/Library/Logs/scanwell"
elif [[ "$EUID" -eq 0 ]]; then
  LOG_DIR="/var/log/scanwell"
else
  LOG_DIR="${HOME}/.local/share/scanwell/logs"
fi
TIMESTAMP=$(date +%Y%m%d-%H%M)
REPORT_TXT="${LOG_DIR}/${TIMESTAMP}.txt"
REPORT_JSON="${LOG_DIR}/${TIMESTAMP}.json"
if [[ "$IS_MACOS" == "true" || "$EUID" -ne 0 ]]; then
  TRIVY_CACHE="${HOME}/.cache/trivy"     # user-writable (macOS or non-root Linux)
else
  TRIVY_CACHE="/var/cache/trivy"         # root on Linux
fi

# Tarball staging dir — Podman uses agent-user-owned path; Docker uses /tmp
if [[ "$CONTAINER_RUNTIME" == "podman" ]]; then
  OC_TARBALL_DIR="/home/${OPENCLAW_USER}/stack-scan-tmp"
else
  OC_TARBALL_DIR="/tmp/stack-scan-tmp"
fi

# Auto-discover all running containers and their images.
# Works with any stack — not hardcoded to openclaw names.
# Format per line: "container-name:image-ref"
CONTAINERS=()
if [[ -n "$CONTAINER_RUNTIME" ]]; then
  while IFS=' ' read -r _cn _ci; do
    [[ -z "$_cn" || -z "$_ci" ]] && continue
    _cn="${_cn#/}"   # Docker ps sometimes prefixes names with /
    _cn="${_cn%%,*}" # Podman multi-name output: take first name only
    CONTAINERS+=("${_cn}:${_ci}")
  done < <(container_exec \
    "${CONTAINER_RUNTIME} ps --format '{{.Names}} {{.Image}}'" 2>/dev/null || true)

  if [[ ${#CONTAINERS[@]} -gt 0 ]]; then
    echo "[RUNTIME] Auto-discovered ${#CONTAINERS[@]} running container(s):"
    for _c in "${CONTAINERS[@]}"; do
      printf "          %-30s → %s\n" "${_c%%:*}" "${_c#*:}"
    done
  else
    echo "[RUNTIME] No running containers found — Section B (Trivy image scan) will be skipped"
  fi
fi

TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOTAL_MEDIUM=0
TOTAL_LOW=0
SCAN_ERRORS=0
FINDINGS_JSON_ARRAY="[]"

log() { echo "[SCAN] $1" | tee -a "$REPORT_TXT"; }
header() { printf '\n%s\n %s\n%s\n' "════════════════════════════════════════════════════════════════" "$1" "════════════════════════════════════════════════════════════════" | tee -a "$REPORT_TXT"; }
subheader() { printf '\n── %s ──────────────────────────────────────────────\n' "$1" | tee -a "$REPORT_TXT"; }
ok() { echo "[SCAN][✅] $1" | tee -a "$REPORT_TXT"; }
warn() { echo "[SCAN][⚠️ ] $1" | tee -a "$REPORT_TXT"; }
crit() { echo "[SCAN][🔴] $1" | tee -a "$REPORT_TXT"; }

# ── DISPLAY HELPERS ───────────────────────────────────────────────────────────
BLUE='\033[1;34m'
RESET='\033[0m'

# Blue-bordered header — colored to terminal, plain to log file
blue_header() {
  local _L="════════════════════════════════════════════════════════════════"
  printf "${BLUE}\n%s\n %s\n%s\n${RESET}" "$_L" "$1" "$_L"
  printf '\n%s\n %s\n%s\n' "$_L" "$1" "$_L" >> "$REPORT_TXT"
}

# OSC 8 hyperlink — clickable in modern terminals (iTerm2, GNOME Terminal, Windows Terminal).
# Degrades silently to plain text in older/dumb terminals.
_hyperlink() {
  local url="$1" text="$2"
  if [[ -t 1 && "${TERM:-}" != "dumb" && -z "${NO_COLOR:-}" ]]; then
    printf '\033]8;;%s\033\\%s\033]8;;\033\\' "$url" "$text"
  else
    printf '%s' "$text"
  fi
}
# Animated sparkle — bouncing ✨ ⋆ · ⋆ across the line during quiet long-running commands.
# Usage: _sparkle_run "label" command [args...]
# TTY-gated: cron/pipe runs the command directly with no animation.
_sparkle_run() {
  local _msg="$1"
  shift

  # Non-TTY (cron, pipe): run directly, suppress Trivy noise
  if [[ ! -t 1 ]]; then
    "$@" 2>/dev/null
    return $?
  fi

  printf '\033[?25l'  # hide cursor during animation

  "$@" >/dev/null 2>&1 &
  local _pid=$! _pos=0 _dir=1 _ci=0 _rc=0 _running=true

  local _chars=('✨' '⋆' '·' '⋆')

  local _cols
  _cols=$(tput cols 2>/dev/null || echo 80)
  local _max=$(( _cols - ${#_msg} - 15 ))
  [[ $_max -lt 10 ]] && _max=30

  while "$_running"; do
    local _pad
    _pad=$(printf '%*s' "$_pos" "")
    printf "\r${BLUE}%s %s${RESET} %s ${BLUE}%s %s${RESET}\033[K" \
      "$_pad${_chars[$(( _ci % ${#_chars[@]} ))]}" \
      "${_chars[$(( (_ci + 2) % ${#_chars[@]} ))]}" \
      "$_msg" \
      "${_chars[$(( (_ci + 2) % ${#_chars[@]} ))]}" \
      "${_chars[$(( _ci % ${#_chars[@]} ))]}"

    _pos=$(( _pos + _dir ))
    if [[ $_pos -ge $_max ]]; then
      _dir=-1; _pos=$_max
    elif [[ $_pos -le 0 ]]; then
      _dir=1; _pos=0
    fi

    (( _ci++ )) || true   # || true: guards set -euo pipefail when _ci==0

    sleep 0.12   # ~8 FPS (50% slower than original)

    kill -0 "$_pid" 2>/dev/null || _running=false
  done

  wait "$_pid" || _rc=$?
  printf "\r\033[K\033[?25h"   # clear line, restore cursor
  return $_rc
}
# Fixed-duration sparkle burst — decorative, no command attached.
# Usage: _sparkle_burst [seconds]
_sparkle_burst() {
  local _secs="${1:-3}"
  [[ ! -t 1 ]] && return 0
  printf '\033[?25l'
  local _pos=0 _dir=1 _ci=0
  local _chars=('✨' '⋆' '·' '⋆')
  local _cols
  _cols=$(tput cols 2>/dev/null || echo 80)
  local _max=$(( _cols / 2 ))
  [[ $_max -lt 10 ]] && _max=30
  local _end=$(( $(date +%s) + _secs ))
  while [[ $(date +%s) -lt $_end ]]; do
    local _pad
    _pad=$(printf '%*s' "$_pos" "")
    printf "\r${BLUE}%s %s${RESET}  ${BLUE}%s %s${RESET}\033[K" \
      "$_pad${_chars[$(( _ci % ${#_chars[@]} ))]}" \
      "${_chars[$(( (_ci + 2) % ${#_chars[@]} ))]}" \
      "${_chars[$(( (_ci + 2) % ${#_chars[@]} ))]}" \
      "${_chars[$(( _ci % ${#_chars[@]} ))]}"
    _pos=$(( _pos + _dir ))
    if [[ $_pos -ge $_max ]]; then
      _dir=-1; _pos=$_max
    elif [[ $_pos -le 0 ]]; then
      _dir=1; _pos=0
    fi
    (( _ci++ )) || true
    sleep 0.12
  done
  printf "\r\033[K\033[?25h"
}
# ── END DISPLAY HELPERS ───────────────────────────────────────────────────────

add_finding() {
  local layer="$1" sev="$2" pkg="$3" vid="$4" desc="$5"
  FINDINGS_JSON_ARRAY=$(echo "$FINDINGS_JSON_ARRAY" | jq \
    --arg layer "$layer" --arg sev "$sev" \
    --arg pkg "$pkg" --arg vid "$vid" --arg desc "$desc" \
    '. += [{"layer":$layer,"severity":$sev,"package":$pkg,"id":$vid,"desc":$desc}]')
  case "$sev" in
    CRITICAL) (( TOTAL_CRITICAL++ )) || true ;;
    HIGH)     (( TOTAL_HIGH++ )) || true ;;
    MEDIUM)   (( TOTAL_MEDIUM++ )) || true ;;
    LOW)      (( TOTAL_LOW++ )) || true ;;
  esac
}

semver_gte() {
  local a b
  a=$(echo "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "0.0.0")
  b=$(echo "$2" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "0.0.0")
  IFS='.' read -ra A <<< "$a"
  IFS='.' read -ra B <<< "$b"
  for i in 0 1 2; do
    local av="${A[$i]:-0}" bv="${B[$i]:-0}"
    (( av > bv )) && return 0
    (( av < bv )) && return 1
  done
  return 0
}

# ── OPTIONAL TOOL INSTALLERS (called interactively by install_deps) ──────────
_install_osv_scanner() {
  echo "[INSTALL] Installing osv-scanner..."
  if [[ "$IS_MACOS" == "true" ]]; then
    # Homebrew verifies bottle checksums and GPG signatures automatically
    brew install osv-scanner
  else
    # Linux: fetch release metadata, download binary + checksums, verify SHA256.
    # Refuses to install if verification fails.
    local _rel _ver _bin_url _sum_url _bin_name
    _rel=$(curl -sf "https://api.github.com/repos/google/osv-scanner/releases/latest") || {
      echo "[ERROR] Could not fetch osv-scanner release info from GitHub API"; return 1
    }
    _ver=$(echo "$_rel" | jq -r '.tag_name')
    # Broad match: catches osv-scanner_linux_amd64, osv-scanner_v2.x_linux_amd64, etc.
    # Excludes checksum files, zip archives, and GPG signatures.
    _bin_url=$(echo "$_rel" | jq -r '.assets[].browser_download_url' \
      | grep -iE 'linux.*(amd64|x86_64)' \
      | grep -Ev '(sha256|checksum|\.zip|\.tar\.gz|\.sig)' | head -1)
    _sum_url=$(echo "$_rel" | jq -r '.assets[].browser_download_url' \
      | grep -iE '(checksums?\.txt|sha256sums?)' | grep -v '\.sig' | head -1)
    if [[ -z "$_bin_url" || -z "$_sum_url" ]]; then
      echo "[ERROR] Cannot find linux_amd64 binary or checksums file for release ${_ver}"
      echo "        Available assets:"
      echo "$_rel" | jq -r '.assets[].name' | sed 's/^/          /'
      echo "        Install manually: https://github.com/google/osv-scanner/releases"
      return 1
    fi
    _bin_name=$(basename "$_bin_url")
    echo "[INSTALL] Downloading osv-scanner ${_ver} (${_bin_name})..."
    curl -fsSL "$_bin_url"  -o "/tmp/${_bin_name}"
    curl -fsSL "$_sum_url" -o /tmp/osv-scanner-checksums.txt
    echo "[INSTALL] Verifying SHA256 checksum..."
    # Extract the expected hash directly from checksums file, then compare against
    # the actual file hash. Avoids sha256sum -c filename-matching edge cases
    # (whitespace format, ./ prefix, line endings) that caused false failures.
    _expected=$(grep -F "$_bin_name" /tmp/osv-scanner-checksums.txt 2>/dev/null | awk '{print $1}' | tr -d '[:space:]')
    _actual=$(sha256sum "/tmp/${_bin_name}" 2>/dev/null | awk '{print $1}' | tr -d '[:space:]')
    if [[ -n "$_expected" && -n "$_actual" && "$_expected" == "$_actual" ]]; then
      sudo install -m 755 "/tmp/${_bin_name}" /usr/local/bin/osv-scanner
      echo "[INSTALL] osv-scanner ${_ver} installed and verified ✓"
      echo "[INSTALL]   expected: ${_expected}"
      echo "[INSTALL]   actual:   ${_actual}"
    else
      echo "[ERROR] Checksum verification FAILED — osv-scanner NOT installed"
      echo "        expected: ${_expected:-<not found in checksums file>}"
      echo "        actual:   ${_actual:-<could not hash file>}"
      echo "        Install manually: https://github.com/google/osv-scanner/releases"
    fi
    rm -f "/tmp/${_bin_name}" /tmp/osv-scanner-checksums.txt
  fi
}

_install_semgrep() {
  # PyPI over TLS — pip verifies package hashes on every download automatically.
  # --ignore-installed skips the uninstall step for Debian-managed packages that
  # lack RECORD files (e.g. typing_extensions). Without it, pip errors even though
  # semgrep itself installs correctly.
  if [[ "$IS_MACOS" == "true" ]]; then
    # brew is cleaner on macOS — avoids system Python restrictions (Sonoma+)
    echo "[INSTALL] Installing semgrep via Homebrew..."
    brew install semgrep
  else
    # --ignore-installed skips uninstall of Debian-managed packages that lack
    # RECORD files (e.g. typing_extensions) — pip errors without it even though
    # semgrep installs correctly. || true: don't let pip warnings kill the script.
    echo "[INSTALL] Installing semgrep via pip3..."
    pip3 install --break-system-packages --ignore-installed semgrep || true
  fi
  if command -v semgrep &>/dev/null; then
    echo "[INSTALL] semgrep: $(semgrep --version 2>/dev/null)"
  else
    echo "[INSTALL] ⚠️  semgrep not in PATH — try opening a new shell, then: semgrep --version"
  fi
}

# Install
install_deps() {
  echo "════════════════════════════════════════════════════════════════"
  echo " scanwell.sh — Installing dependencies"
  echo "════════════════════════════════════════════════════════════════"

  if [[ "$IS_MACOS" == "true" ]]; then
    # macOS — install via Homebrew
    if ! command -v brew &>/dev/null; then
      echo "[ERROR] Homebrew not found. Install from https://brew.sh then re-run."
      exit 1
    fi
    echo "[INSTALL] macOS: installing via Homebrew..."
    brew install jq trivy
    echo "[INSTALL] Note: debsecan is Linux-only and will be skipped on macOS."
    echo "[INSTALL] Note: For OS-level CVEs on macOS, run: softwareupdate --list"
  else
    # Linux (Debian/Ubuntu)
    # Remove stale Trivy apt config before the first update — a broken trivy.list
    # from a previous failed install poisons apt-get update with GPG errors.
    sudo rm -f /etc/apt/sources.list.d/trivy.list
    sudo apt-get update -qq
    sudo apt-get install -y wget gnupg apt-transport-https debsecan jq lsb-release curl

    if command -v trivy &>/dev/null; then
      echo "[INSTALL] trivy already installed: $(trivy --version | head -1) — skipping apt setup"
    else
      # Trivy — installed via the official signed apt repo, not curl | sh.
      # Uses sudo gpg --dearmor -o (same pattern as CrowdSec/Tailscale) so gpg
      # writes the file directly as root with correct ownership and format.
      echo "[INSTALL] Adding Trivy GPG key..."
      sudo mkdir -p /etc/apt/keyrings
      sudo rm -f /etc/apt/keyrings/trivy.gpg /usr/share/keyrings/trivy.gpg
      curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key | \
        sudo gpg --dearmor -o /etc/apt/keyrings/trivy.gpg
      sudo chmod 644 /etc/apt/keyrings/trivy.gpg

      echo "[INSTALL] Adding Trivy apt repository..."
      echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] \
https://aquasecurity.github.io/trivy-repo/deb generic main" | \
        sudo tee /etc/apt/sources.list.d/trivy.list > /dev/null

      sudo apt-get update -qq
      sudo apt-get install -y trivy
    fi
  fi

  echo "[INSTALL] Trivy version: $(trivy --version | head -1)"

  if [[ "$IS_MACOS" == "true" ]]; then
    mkdir -p "$LOG_DIR" "$TRIVY_CACHE" && chmod 750 "$LOG_DIR"
  else
    sudo mkdir -p "$LOG_DIR" "$TRIVY_CACHE" && sudo chmod 750 "$LOG_DIR"
  fi
  trivy image --download-db-only --cache-dir "$TRIVY_CACHE" --quiet || true
  echo "[INSTALL] Required tools installed."
  echo ""
  echo "════════════════════════════════════════════════════════════════"
  echo " Optional tools for deeper scanning"
  echo "════════════════════════════════════════════════════════════════"
  for _opt in \
    "osv-scanner:_install_osv_scanner:multi-ecosystem dependency CVEs" \
    "semgrep:_install_semgrep:SAST code security analysis"; do
    _ot_name="${_opt%%:*}"
    _ot_fn="${_opt#*:}";   _ot_fn="${_ot_fn%:*}"
    _ot_desc="${_opt##*:}"
    if command -v "$_ot_name" &>/dev/null; then
      echo "[INSTALL] ${_ot_name} already installed — skipping"
    elif [[ -t 0 && -t 1 ]]; then
      _sparkle_burst 2
      read -rp " Shall I securely install ${_ot_name} for more thorough scanning reports? [y/N] " _ans
      [[ "${_ans,,}" =~ ^y ]] && "$_ot_fn" || echo "[INSTALL] ${_ot_name} skipped"
    else
      echo "[INSTALL] ${_ot_name} (${_ot_desc}) — re-run sudo bash $0 --install interactively to add"
    fi
  done
  echo ""
  echo "[INSTALL] Done. Run: sudo bash $0"
  exit 0
}
[[ "${1:-}" == "--install" ]] && install_deps

# Preflight
mkdir -p "$LOG_DIR" "$TRIVY_CACHE"
for tool in trivy jq; do
  if ! command -v "$tool" &>/dev/null; then
    echo "[ERROR] $tool not found. Run: sudo bash $0 --install"
    exit 2
  fi
done
if [[ "$IS_MACOS" != "true" ]] && ! command -v debsecan &>/dev/null; then
  echo "[ERROR] debsecan not found. Run: sudo bash $0 --install"
  exit 2
fi

if [[ "$CONTAINER_RUNTIME" == "podman" ]]; then
  sudo su - "$OPENCLAW_USER" -s /bin/bash -c \
    "XDG_RUNTIME_DIR=/run/user/${OC_UID} mkdir -p ${OC_TARBALL_DIR}" 2>/dev/null || true
elif [[ -n "$CONTAINER_RUNTIME" ]]; then
  mkdir -p "$OC_TARBALL_DIR"
fi
trap '[[ -n "${OC_TARBALL_DIR:-}" ]] && sudo rm -rf "${OC_TARBALL_DIR}" 2>/dev/null || true' EXIT

# Header
{
  echo "════════════════════════════════════════════════════════════════"
  echo " OpenClaw Full Stack CVE Scan"
  echo " $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo " Host: $(hostname)"
  echo "════════════════════════════════════════════════════════════════"
} | tee "$REPORT_TXT"
log "Report: $REPORT_TXT"
log "JSON:   $REPORT_JSON"

# A. OS PACKAGES
# Auto-detect Ubuntu suite; skip gracefully on non-Debian hosts
UBUNTU_SUITE=$(lsb_release -cs 2>/dev/null || grep -oP '(?<=UBUNTU_CODENAME=)\w+' /etc/os-release 2>/dev/null || echo "")
header "A. OS PACKAGES — debsecan (suite: ${UBUNTU_SUITE:-unknown})"
if [[ "$IS_MACOS" == "true" ]]; then
  warn "debsecan is Linux-only — skipped on macOS"
  warn "macOS alternative: run 'softwareupdate --list' for pending OS security patches"
  SCAN_ERRORS=$((SCAN_ERRORS+1))
  DEB_OUT=""
elif [[ -z "$UBUNTU_SUITE" ]]; then
  warn "Cannot detect Ubuntu suite — debsecan skipped (non-Ubuntu host or lsb_release missing)"
  SCAN_ERRORS=$((SCAN_ERRORS+1))
  DEB_OUT=""
else
DEB_OUT=$(debsecan --suite "$UBUNTU_SUITE" --format summary 2>/dev/null || true)
if [[ -z "$DEB_OUT" ]]; then
  ok "No CVEs found in installed OS packages"
else
  echo "$DEB_OUT" >> "$REPORT_TXT"
  FIXED=$(debsecan --suite "$UBUNTU_SUITE" --format packages --only-fixed 2>/dev/null | wc -l || echo 0)
  if [[ "$FIXED" -gt 0 ]]; then
    crit "debsecan: ${FIXED} packages have available security fixes"
    add_finding "ubuntu-os" "HIGH" "apt-packages" "debsecan" "${FIXED} OS packages with security updates available"
  else
    ok "debsecan: No packages with available fixes"
  fi
fi
fi  # end UBUNTU_SUITE check
if [[ "$IS_MACOS" == "true" ]]; then
  log "Total installed packages: $(brew list 2>/dev/null | wc -l | tr -d ' ') (Homebrew)"
else
  log "Total installed packages: $(dpkg -l | grep -c '^ii' 2>/dev/null || echo unknown)"
fi

# B. CONTAINERS (with squid fallback)
header "B. CONTAINER IMAGES — Trivy"
if [[ -z "$CONTAINER_RUNTIME" ]]; then
  warn "No container runtime active — container image scans skipped"
elif [[ ${#CONTAINERS[@]} -eq 0 ]]; then
  warn "No running containers discovered — Trivy image scan skipped"
else
log "Updating Trivy DB..."
_sparkle_run "Updating Trivy vulnerability database..." \
  trivy image --download-db-only --cache-dir "$TRIVY_CACHE" --quiet \
  && ok "Trivy DB updated" || warn "Trivy DB update failed"

# Socket detection for Trivy direct-scan mode
# Podman socket: enable with: sudo su - openclaw -c 'systemctl --user enable --now podman.socket'
# Docker socket: /var/run/docker.sock (present if Docker daemon is running)
if [[ "$CONTAINER_RUNTIME" == "podman" ]]; then
  CONTAINER_SOCK="/run/user/${OC_UID}/podman/podman.sock"
else
  CONTAINER_SOCK="/var/run/docker.sock"
fi
if [[ -S "$CONTAINER_SOCK" ]]; then
  log "Container socket found (${CONTAINER_SOCK}) — Trivy will use socket mode"
  USE_CONTAINER_SOCK=true
else
  log "Container socket not found — using tarball mode for Trivy"
  USE_CONTAINER_SOCK=false
fi

for entry in "${CONTAINERS[@]}"; do
  CONTAINER_NAME="${entry%%:*}"
  IMAGE_REF="${entry#*:}"
  subheader "$CONTAINER_NAME ($IMAGE_REF)"

  TRIVY_JSON_TMP=$(mktemp)
  TRIVY_SCAN_OK=false

  if [[ "$USE_CONTAINER_SOCK" == "true" ]]; then
    # Docker socket is Trivy's default; for Podman we set DOCKER_HOST
    if [[ "$CONTAINER_RUNTIME" == "podman" ]]; then
      TRIVY_ENV="DOCKER_HOST=unix://${CONTAINER_SOCK}"
    else
      TRIVY_ENV=""
    fi
    if _sparkle_run "Scanning ${CONTAINER_NAME}..." \
         env $TRIVY_ENV trivy image \
         --cache-dir "$TRIVY_CACHE" --format json --output "$TRIVY_JSON_TMP" \
         --severity CRITICAL,HIGH,MEDIUM,LOW --skip-db-update \
         "${IMAGE_REF}" --quiet; then
      TRIVY_SCAN_OK=true
    else
      warn "Socket scan failed for ${IMAGE_REF} — falling back to tarball"
    fi
  fi

  if [[ "$TRIVY_SCAN_OK" != "true" ]]; then
    TARBALL="${OC_TARBALL_DIR}/${CONTAINER_NAME}.tar"
    if _sparkle_run "Trivy Security Scan Loading ${CONTAINER_NAME} image..." \
         container_save "${IMAGE_REF}" "${TARBALL}"; then
      SCAN_SOURCE="--input $TARBALL"
    else
      warn "${CONTAINER_RUNTIME} save failed for ${IMAGE_REF} — falling back to direct pull"
      SCAN_SOURCE="${IMAGE_REF}"
    fi
    if _sparkle_run "Scanning ${CONTAINER_NAME}..." \
         trivy image --cache-dir "$TRIVY_CACHE" --format json --output "$TRIVY_JSON_TMP" \
         --severity CRITICAL,HIGH,MEDIUM,LOW --skip-db-update $SCAN_SOURCE --quiet; then
      TRIVY_SCAN_OK=true
    fi
    rm -f "$TARBALL" 2>/dev/null || true
  fi

  if [[ "$TRIVY_SCAN_OK" == "true" ]]; then

    C=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$TRIVY_JSON_TMP" 2>/dev/null || echo 0)
    H=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$TRIVY_JSON_TMP" 2>/dev/null || echo 0)
    M=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' "$TRIVY_JSON_TMP" 2>/dev/null || echo 0)
    L=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="LOW")] | length' "$TRIVY_JSON_TMP" 2>/dev/null || echo 0)

    (( TOTAL_CRITICAL += C )) || true
    (( TOTAL_HIGH += H )) || true
    (( TOTAL_MEDIUM += M )) || true
    (( TOTAL_LOW += L )) || true

    if [[ $((C + H)) -gt 0 ]]; then
      crit "${CONTAINER_NAME}: CRITICAL=${C} HIGH=${H} MEDIUM=${M} LOW=${L}"
      log " Top findings (CRITICAL+HIGH):"
      jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL" or .Severity=="HIGH") |
        "  [\(.Severity)] \(.VulnerabilityID) — \(.PkgName) \(.InstalledVersion) → \(.FixedVersion // "no fix") — \(.Title // "no title")"' \
        "$TRIVY_JSON_TMP" 2>/dev/null | head -20 | tee -a "$REPORT_TXT" || true
    elif [[ $((M + L)) -gt 0 ]]; then
      warn "${CONTAINER_NAME}: CRITICAL=${C} HIGH=${H} MEDIUM=${M} LOW=${L}"
    else
      ok "${CONTAINER_NAME}: No vulnerabilities found"
    fi

    cp "$TRIVY_JSON_TMP" "${LOG_DIR}/${TIMESTAMP}-trivy-${CONTAINER_NAME}.json"
    ok "Full Trivy JSON: ${LOG_DIR}/${TIMESTAMP}-trivy-${CONTAINER_NAME}.json"
  else
    warn "Trivy scan failed for ${CONTAINER_NAME}"
    (( SCAN_ERRORS++ )) || true
  fi
  rm -f "$TRIVY_JSON_TMP" 2>/dev/null || true
done
fi # end container runtime check — section B


# ====================  C. npm audit — openclaw-agent  ====================
header "C. NODE.JS DEPS — npm audit (openclaw-agent)"
# NOTE: OpenClaw is a global npm install — no package-lock.json exists in the install dir.
# ENOLOCK is expected. Trivy (Section B) covers npm dep CVEs via image filesystem scan.
# npm audit only adds value here if a lockfile is present (e.g. a local workspace package.json).
NPM_JSON=$(container_exec "${CONTAINER_RUNTIME} exec openclaw-agent sh -c '
  cd /usr/local/lib/node_modules/openclaw 2>/dev/null || cd /app 2>/dev/null || cd /home/node;
  npm audit --json 2>/dev/null; true
' " 2>/dev/null || true)

if echo "$NPM_JSON" | jq -e '.error.code == "ENOLOCK"' &>/dev/null; then
  ok "npm audit (openclaw-agent): ENOLOCK — global install has no lockfile. Node dep CVEs covered by Trivy (Section B)."
elif echo "$NPM_JSON" | jq . &>/dev/null; then
  NPM_CRIT=$(echo "$NPM_JSON" | jq -r '.metadata.vulnerabilities.critical // 0' 2>/dev/null | head -1 || echo 0)
  NPM_HIGH=$(echo "$NPM_JSON" | jq -r '.metadata.vulnerabilities.high // 0' 2>/dev/null | head -1 || echo 0)
  (( TOTAL_CRITICAL += NPM_CRIT )) || true
  (( TOTAL_HIGH += NPM_HIGH )) || true
  if [[ $((NPM_CRIT + NPM_HIGH)) -gt 0 ]]; then
    crit "npm audit (openclaw-agent): CRITICAL=${NPM_CRIT} HIGH=${NPM_HIGH}"
  else
    ok "npm audit (openclaw-agent): Clean"
  fi
  echo "$NPM_JSON" > "${LOG_DIR}/${TIMESTAMP}-npm-audit-openclaw-agent.json" 2>/dev/null || true
elif [[ -n "$CONTAINER_RUNTIME" ]]; then
  warn "npm audit (openclaw-agent): unexpected output — check proxy and lockfile"
  (( SCAN_ERRORS++ )) || true
fi

# ====================  D. npm audit — litellm  ====================
header "D. NODE.JS DEPS — npm audit (litellm)"
NPM_JSON_LITELLM=$(container_exec "${CONTAINER_RUNTIME} exec openclaw-litellm sh -c 'npm audit --json 2>/dev/null; true'" 2>/dev/null || true)

if echo "$NPM_JSON_LITELLM" | jq . &>/dev/null; then
  NPM_CRIT_L=$(echo "$NPM_JSON_LITELLM" | jq -r '.metadata.vulnerabilities.critical // 0' 2>/dev/null | head -1 || echo 0)
  NPM_HIGH_L=$(echo "$NPM_JSON_LITELLM" | jq -r '.metadata.vulnerabilities.high // 0' 2>/dev/null | head -1 || echo 0)
  (( TOTAL_CRITICAL += NPM_CRIT_L )) || true
  (( TOTAL_HIGH += NPM_HIGH_L )) || true

  if [[ $((NPM_CRIT_L + NPM_HIGH_L)) -gt 0 ]]; then
    crit "npm audit (litellm): CRITICAL=${NPM_CRIT_L} HIGH=${NPM_HIGH_L}"
  else
    ok "npm audit (litellm): Clean"
  fi
  echo "$NPM_JSON_LITELLM" > "${LOG_DIR}/${TIMESTAMP}-npm-audit-litellm.json" 2>/dev/null || true
elif [[ -n "$CONTAINER_RUNTIME" ]]; then
  warn "npm audit (litellm) returned invalid JSON"
  (( SCAN_ERRORS++ )) || true
fi

# ====================  E. pip-audit — openclaw-agent  ====================
header "E. PYTHON DEPS — pip-audit (openclaw-agent)"
PIP_PRESENT_AGENT=$(container_exec "${CONTAINER_RUNTIME} exec openclaw-agent which pip-audit 2>/dev/null || echo ''" || echo "")
if [[ -z "$CONTAINER_RUNTIME" ]]; then
  warn "No container runtime active — pip-audit (openclaw-agent) skipped"
elif [[ -z "$PIP_PRESENT_AGENT" ]]; then
  warn "pip-audit not found in openclaw-agent — skipping"
  (( SCAN_ERRORS++ )) || true
else
  PIP_JSON=$(container_exec "${CONTAINER_RUNTIME} exec openclaw-agent pip-audit --format json 2>/dev/null" || true)
  # pip-audit 2.x returns {"dependencies":[...],"fixes":[...]} not a bare array
  PIP_VULN=$(echo "$PIP_JSON" | \
    jq '(.dependencies // .) | [.[] | select(.vulns | length > 0)] | length' \
    2>/dev/null || echo 0)
  PIP_VULN_TOTAL=$(echo "$PIP_JSON" | \
    jq '(.dependencies // .) | [.[] | .vulns[]] | length' \
    2>/dev/null || echo 0)
  if [[ "$PIP_VULN" -gt 0 ]]; then
    crit "pip-audit (openclaw-agent): ${PIP_VULN} vulnerable packages (${PIP_VULN_TOTAL} CVEs total)"
    add_finding "python-deps" "HIGH" "pip-packages" "pip-audit" "${PIP_VULN} vulnerable packages in openclaw-agent"
    (( TOTAL_HIGH += 1 )) || true
  else
    ok "pip-audit (openclaw-agent): Clean"
  fi
  echo "$PIP_JSON" > "${LOG_DIR}/${TIMESTAMP}-pip-audit-openclaw-agent.json" 2>/dev/null || true
fi

# ====================  F. pip-audit — litellm  ====================
header "F. PYTHON DEPS — pip-audit (litellm)"
PIP_PRESENT_LITELLM=$(container_exec "${CONTAINER_RUNTIME} exec openclaw-litellm which pip-audit 2>/dev/null || echo ''" || echo "")
if [[ -z "$CONTAINER_RUNTIME" ]]; then
  warn "No container runtime active — pip-audit (litellm) skipped"
elif [[ -z "$PIP_PRESENT_LITELLM" ]]; then
  warn "pip-audit not found in litellm container — rebuild with Containerfile to install it"
  SCAN_ERRORS=$((SCAN_ERRORS+1))
else
  PIP_AUDIT_OUT=$(container_exec "${CONTAINER_RUNTIME} exec openclaw-litellm pip-audit --format json 2>/dev/null" || true)
  if [[ -n "$PIP_AUDIT_OUT" ]] && echo "$PIP_AUDIT_OUT" | jq . >/dev/null 2>&1; then
    # pip-audit 2.x returns {"dependencies":[...],"fixes":[...]} not a bare array
    PIP_VULN=$(echo "$PIP_AUDIT_OUT" | \
      jq '(.dependencies // .) | [.[] | select(.vulns | length > 0)] | length' \
      2>/dev/null || echo 0)
    PIP_VULN_TOTAL=$(echo "$PIP_AUDIT_OUT" | \
      jq '(.dependencies // .) | [.[] | .vulns[]] | length' \
      2>/dev/null || echo 0)
    if [[ "$PIP_VULN" -gt 0 ]]; then
      crit "pip-audit (litellm): ${PIP_VULN} vulnerable packages (${PIP_VULN_TOTAL} CVEs total)"
      add_finding "python-deps" "HIGH" "pip-packages" "pip-audit" "${PIP_VULN} vulnerable Python packages in litellm"
      (( TOTAL_HIGH += 1 )) || true
      log " Top vulnerable packages:"
      echo "$PIP_AUDIT_OUT" | jq -r \
        '(.dependencies // .) | .[] | select(.vulns | length > 0) |
         "  \(.name) \(.version) — \(.vulns | length) CVE(s) — fix: \(.vulns[0].fix_versions[0] // "none")"' \
        2>/dev/null | head -10 | tee -a "$REPORT_TXT" || true
    else
      ok "pip-audit (litellm): Clean"
    fi
    echo "$PIP_AUDIT_OUT" > "${LOG_DIR}/${TIMESTAMP}-pip-audit-litellm.json" 2>/dev/null || true
  else
    warn "pip-audit (litellm): output empty or invalid JSON"
    SCAN_ERRORS=$((SCAN_ERRORS+1))
  fi
fi

# ====================  F.1 pip-audit — squid  ====================
header "F.1 PYTHON DEPS — pip-audit (squid)"
PIP_PRESENT_SQUID=$(container_exec "${CONTAINER_RUNTIME} exec openclaw-squid which pip-audit 2>/dev/null || echo ''" || echo "")
if [[ -z "$CONTAINER_RUNTIME" ]]; then
  warn "No container runtime active — pip-audit (squid) skipped"
elif [[ -z "$PIP_PRESENT_SQUID" ]]; then
  ok "pip-audit not present in squid container — expected (Ubuntu/Squid base has no Python deps to audit)"
else
  PIP_SQUID_OUT=$(container_exec "${CONTAINER_RUNTIME} exec openclaw-squid pip-audit --format json 2>/dev/null" || true)
  if [[ -n "$PIP_SQUID_OUT" ]] && echo "$PIP_SQUID_OUT" | jq . >/dev/null 2>&1; then
    PIP_SQUID_VULN=$(echo "$PIP_SQUID_OUT" | \
      jq '(.dependencies // .) | [.[] | select(.vulns | length > 0)] | length' \
      2>/dev/null || echo 0)
    [[ "$PIP_SQUID_VULN" -gt 0 ]] && \
      crit "pip-audit (squid): ${PIP_SQUID_VULN} vulnerable packages" || \
      ok "pip-audit (squid): Clean"
  else
    warn "pip-audit (squid): unexpected output format"
  fi
fi




# G. OLLAMA
header "G. OLLAMA — Trivy filesystem scan"
OLLAMA_BIN=$(command -v ollama 2>/dev/null || echo "/usr/local/bin/ollama")
if [[ -f "$OLLAMA_BIN" ]]; then
  log "Scanning Ollama binary at $OLLAMA_BIN"
  OLLAMA_JSON=$(mktemp)
  if trivy fs --cache-dir "$TRIVY_CACHE" --format json --output "$OLLAMA_JSON" \
       --severity CRITICAL,HIGH --quiet "$OLLAMA_BIN" 2>/dev/null; then
    OL_C=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$OLLAMA_JSON" 2>/dev/null || echo 0)
    OL_H=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$OLLAMA_JSON" 2>/dev/null || echo 0)
    (( TOTAL_CRITICAL += OL_C )) || true
    (( TOTAL_HIGH += OL_H )) || true
    if [[ $((OL_C + OL_H)) -gt 0 ]]; then
      crit "Ollama: CRITICAL=${OL_C} HIGH=${OL_H}"
    else
      ok "Ollama: No CRITICAL/HIGH findings"
    fi
  else
    warn "Trivy fs scan of Ollama failed"
    (( SCAN_ERRORS++ )) || true
  fi
  rm -f "$OLLAMA_JSON"
else
  warn "Ollama binary not found — skipping"
fi

# H. TAILSCALE
header "H. TAILSCALE — Version and Trivy scan"
if command -v tailscale &>/dev/null; then
  TS_VERSION=$(tailscale version 2>/dev/null | head -1 || echo "unknown")
  log "Tailscale version: $TS_VERSION"
  TS_BIN=$(command -v tailscale)
  TS_JSON=$(mktemp)
  if trivy fs --cache-dir "$TRIVY_CACHE" --format json --output "$TS_JSON" \
       --severity CRITICAL,HIGH --quiet "$TS_BIN" 2>/dev/null; then
    TS_C=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$TS_JSON" 2>/dev/null || echo 0)
    TS_H=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$TS_JSON" 2>/dev/null || echo 0)
    (( TOTAL_CRITICAL += TS_C )) || true
    (( TOTAL_HIGH += TS_H )) || true
    if [[ $((TS_C + TS_H)) -gt 0 ]]; then
      crit "Tailscale: CRITICAL=${TS_C} HIGH=${TS_H}"
    else
      ok "Tailscale: No CRITICAL/HIGH findings from Trivy"
    fi
  else
    warn "Trivy fs scan of Tailscale failed"
    (( SCAN_ERRORS++ )) || true
  fi
  rm -f "$TS_JSON"
else
  warn "Tailscale not found — skipping"
fi

# I. SECRETS HYGIENE (stricter OpenRouter pattern)
header "I. SECRETS HYGIENE — Plaintext key detection"
SECRETS_FOUND=0
declare -A SECRET_PATTERNS=(
  ["OpenRouter API key"]="sk-or-[a-zA-Z0-9]{20,}"
  ["Generic API key"]="sk-[a-zA-Z0-9]{20,}"
  ["AWS Access Key"]="AKIA[0-9A-Z]{16}"
  # Require leading dashes — actual PEM format. Avoids matching prose that discusses key formats.
  ["Private key header"]="-----BEGIN.*PRIVATE KEY"
  # Require 20+ chars after prefix — avoids matching documentation that mentions the prefix only.
  ["Anthropic key"]="sk-ant-[a-zA-Z0-9-]{20,}"
)

SCAN_PATHS=(
  # Docker/compose stack files
  "$DOCKER_DIR/openclaw.json"
  "$DOCKER_DIR/litellm-config.yaml"
  "$DOCKER_DIR/docker-compose.yml"
  "$DOCKER_DIR/.env"
  "$DOCKER_DIR/workspace/memory"
  # Admin user home — scripts, dotfiles, credentials
  "$ADMIN_HOME"
  # OpenClaw agent user home — credentials/, auth-profiles.json, openclaw.json
  # device.json (ED25519 private key), telegram/discord/whatsapp tokens
  "$OPENCLAW_HOME/.openclaw"
  "$OPENCLAW_HOME/.doppler"
  # Shell profiles — secrets sometimes exported here
  "$ADMIN_HOME/.bashrc"
  "$ADMIN_HOME/.bash_profile"
  "$ADMIN_HOME/.profile"
  "$ADMIN_HOME/.zshrc"
  "$OPENCLAW_HOME/.bashrc"
  "$OPENCLAW_HOME/.profile"
)

for pattern_name in "${!SECRET_PATTERNS[@]}"; do
  pattern="${SECRET_PATTERNS[$pattern_name]}"
  for scan_path in "${SCAN_PATHS[@]}"; do
    [[ ! -e "$scan_path" ]] && continue
    MATCHES=$(sudo grep -rEl "$pattern" "$scan_path" \
      --exclude="*.bak*" \
      --exclude="*.md" \
      --exclude="*.jsonl" \
      --exclude="scanwell*.sh" \
      --exclude="NightWatchman*.sh" \
      --exclude-dir=".local" \
      --exclude-dir=".cache" \
      --exclude-dir="node_modules" \
      --exclude-dir="openclaw-docs" \
      --exclude-dir="file-history" \
      2>/dev/null || true)
    # Filter conversation history — contains key pattern mentions in documentation context.
    # .claude/.credentials.json is NOT filtered — it holds a real API key and should be visible.
    MATCHES=$(echo "$MATCHES" | \
      grep -v "\.ollama/id_ed25519" | \
      grep -v "\.claude/projects/" | \
      grep -v "txconfigs2/" \
      || true)
    if [[ -n "$MATCHES" ]]; then
      crit "SECRETS: '${pattern_name}' pattern found in:"
      echo "$MATCHES" | while read -r f; do echo " → $f" | tee -a "$REPORT_TXT"; done
      add_finding "secrets-hygiene" "CRITICAL" "plaintext-secret" "secret-scan" "${pattern_name} found in live config files"
      (( SECRETS_FOUND++ )) || true
      (( TOTAL_CRITICAL++ )) || true
    fi
  done
done
[[ "$SECRETS_FOUND" -eq 0 ]] && ok "No plaintext secrets found in live config paths"

# I.1 CONTAINER ENV — scan running container environment variables for secret values
subheader "I.1 Container environment — live secret value detection"
if [[ -z "$CONTAINER_RUNTIME" ]]; then
  warn "No container runtime active — container env scan skipped"
else
for _cname in openclaw-agent openclaw-litellm; do
  _ENV_OUT=$(container_exec "${CONTAINER_RUNTIME} exec ${_cname} env 2>/dev/null" 2>/dev/null || true)
  if [[ -z "$_ENV_OUT" ]]; then
    warn "Could not read env from ${_cname} — container may not be running"
    continue
  fi
  _env_hits=0
  while IFS='=' read -r _key _value; do
    [[ -z "$_key" || "$_key" == \#* ]] && continue
    # Flag env vars whose VALUES match known credential formats
    if echo "$_value" | grep -qE \
      '(sk-or-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9-]{20,}|sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN.*(PRIVATE|RSA))'; then
      warn "${_cname}: credential value detected in env var: ${_key}=***"
      add_finding "container-env" "HIGH" "${_cname}" "env-credential" \
        "${_key} holds a credential value in live container environment"
      (( TOTAL_HIGH++ )) || true
      (( _env_hits++ )) || true
    fi
  done < <(echo "$_ENV_OUT")
  [[ "$_env_hits" -eq 0 ]] && ok "${_cname}: No unexpected credential values in container env"
done
fi # end container runtime check — section I.1

# Doppler token permission check
TOKEN_FILE="$DOPPLER_TOKEN_FILE"
if [[ -f "$TOKEN_FILE" ]]; then
  TOKEN_PERMS=$(if [[ "$IS_MACOS" == "true" ]]; then stat -f "%p %Su:%Sg" "$TOKEN_FILE" 2>/dev/null || echo "unknown"; else stat -c "%a %U:%G" "$TOKEN_FILE" 2>/dev/null || echo "unknown"; fi)
  if [[ "$TOKEN_PERMS" == "700 openclaw:openclaw" ]]; then
    ok "Doppler token file permissions correct: $TOKEN_PERMS"
  else
    crit "Doppler token file permissions WRONG: $TOKEN_PERMS (expected: 700 openclaw:openclaw)"
    add_finding "secrets-hygiene" "HIGH" "doppler-token-file" "permissions" "Token file permissions: $TOKEN_PERMS"
  fi
else
  warn "Doppler token file not found at $TOKEN_FILE"
fi

CREDS_FILE="/home/${ADMIN_USER}/.claude/.credentials.json"
if [[ -f "$CREDS_FILE" ]]; then
  CREDS_PERMS=$(if [[ "$IS_MACOS" == "true" ]]; then stat -f "%p %Su:%Sg" "$CREDS_FILE" 2>/dev/null || echo "unknown"; else stat -c "%a %U:%G" "$CREDS_FILE" 2>/dev/null || echo "unknown"; fi)
  if [[ "$CREDS_PERMS" == "600 lord:lord" ]]; then
    ok "Claude credentials file permissions correct: $CREDS_PERMS"
  else
    crit "Claude credentials file permissions WRONG: $CREDS_PERMS (expected: 600 lord:lord)"
  fi
fi

# J. OPENCLAW KNOWN CVEs
header "J. OPENCLAW VERSION — Known critical CVE check"
OC_VERSION=$(container_exec "${CONTAINER_RUNTIME} exec openclaw-agent openclaw --version 2>/dev/null || echo unknown") || true
# Fallback: check for a locally installed openclaw binary (host install, no container needed)
if [[ -z "$OC_VERSION" || "$OC_VERSION" == "unknown" ]] && command -v openclaw &>/dev/null; then
  OC_VERSION=$(openclaw --version 2>/dev/null || echo unknown)
fi
OC_VER_CLEAN=$(echo "$OC_VERSION" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "0.0.0")
log "OpenClaw version detected: $OC_VERSION (parsed: $OC_VER_CLEAN)"

# Baked-in CVE list — updated at release time.
# Format: ["CVE-ID"]="first-fixed-version"
# Source: AgentShield advisory feed + Jerry Gamblin OpenClaw tracker
declare -A CRITICAL_FIXES=(
  ["CVE-2026-22172"]="2026.3.12"
  ["CVE-2026-32922"]="2026.3.11"
  ["CVE-2026-32915"]="2026.3.11"
  ["CVE-2026-32987"]="2026.3.13"
  ["CVE-2026-32916"]="2026.3.11"
  ["CVE-2026-32918"]="2026.3.11"
)

# Try to fetch updated CVE list from AgentShield feed (silently falls back on failure)
# Publish your live feed at this URL once the GitHub repo is live.
# Feed format: [{"id":"CVE-XXXX-XXXXX","fixed_in":"2026.X.X"},...]
_CVE_FEED_URL="${AGENTSHIELD_CVE_FEED:-https://raw.githubusercontent.com/agentwell/stack-scan/main/cve-feed.json}"
if command -v curl &>/dev/null; then
  _CVE_REMOTE=$(curl -sf --max-time 8 "$_CVE_FEED_URL" 2>/dev/null || echo "")
  if [[ -n "$_CVE_REMOTE" ]] && echo "$_CVE_REMOTE" | jq -e '.[0].id' &>/dev/null 2>&1; then
    _remote_count=$(echo "$_CVE_REMOTE" | jq 'length' 2>/dev/null || echo 0)
    log "CVE feed: loaded ${_remote_count} entries from remote (overrides baked-in list)"
    while IFS=$'\t' read -r _cve_id _fix_ver; do
      [[ -n "$_cve_id" && -n "$_fix_ver" ]] && CRITICAL_FIXES["$_cve_id"]="$_fix_ver"
    done < <(echo "$_CVE_REMOTE" | jq -r '.[] | [.id, .fixed_in] | @tsv' 2>/dev/null)
  else
    log "CVE feed: remote unavailable — using ${#CRITICAL_FIXES[@]} baked-in entries"
  fi
fi

UNPATCHED_CVES=0
if [[ "$OC_VER_CLEAN" == "0.0.0" ]]; then
  warn "Could not determine OpenClaw version — verify manually against CVE list"
  add_finding "openclaw-app" "HIGH" "openclaw" "version-unknown" "OpenClaw version could not be detected"
  (( SCAN_ERRORS++ )) || true
else
  for cve in "${!CRITICAL_FIXES[@]}"; do
    fixed_in="${CRITICAL_FIXES[$cve]}"
    if ! semver_gte "$OC_VER_CLEAN" "$fixed_in"; then
      crit " $cve — requires $fixed_in — PRESENT in running version $OC_VER_CLEAN"
      add_finding "openclaw-app" "CRITICAL" "openclaw" "$cve" \
        "Version ${OC_VER_CLEAN} below fix version ${fixed_in}"
      (( TOTAL_CRITICAL++ )) || true
      (( UNPATCHED_CVES++ )) || true
    fi
  done
  if [[ "$UNPATCHED_CVES" -gt 0 ]]; then
    crit "OpenClaw ${OC_VER_CLEAN}: ${UNPATCHED_CVES} unpatched Critical CVEs — upgrade immediately"
  else
    ok "OpenClaw ${OC_VER_CLEAN} — clear of all ${#CRITICAL_FIXES[@]} tracked Critical CVEs"
  fi
fi


# K. VPS HOST — pip-audit
header "K. VPS HOST — pip-audit"
if ! command -v pip-audit &>/dev/null; then
  ok "pip-audit not installed on host — skipping (install: sudo pip3 install pip-audit)"
else
  HOST_PIP_OUT=$(pip-audit --format json 2>/dev/null || true)
  if [[ -z "$HOST_PIP_OUT" ]]; then
    ok "pip-audit (host): no pip packages found to audit"
  elif echo "$HOST_PIP_OUT" | jq . >/dev/null 2>&1; then
    HOST_PIP_VULN=$(echo "$HOST_PIP_OUT" | \
      jq '(.dependencies // .) | [.[] | select(.vulns | length > 0)] | length' \
      2>/dev/null || echo 0)
    # Count individual vuln IDs — flatten nested vulns arrays across all packages
    HOST_PIP_TOTAL=$(echo "$HOST_PIP_OUT" | \
      jq '(.dependencies // .) | [.[] | .vulns // [] | .[]] | length' \
      2>/dev/null || echo 0)
    if [[ "$HOST_PIP_VULN" -gt 0 ]]; then
      if [[ "$HOST_PIP_TOTAL" -gt 0 ]]; then
        crit "pip-audit (host): ${HOST_PIP_VULN} vulnerable packages (${HOST_PIP_TOTAL} CVEs)"
      else
        # Packages flagged but no CVE IDs returned — common with yanked or deprecated packages
        crit "pip-audit (host): ${HOST_PIP_VULN} packages flagged (run pip-audit manually for details)"
      fi
      add_finding "host-python" "HIGH" "pip-packages-host" "pip-audit" \
        "${HOST_PIP_VULN} vulnerable packages on VPS host"
      (( TOTAL_HIGH += 1 )) || true
    else
      ok "pip-audit (host): Clean"
    fi
    echo "$HOST_PIP_OUT" > "${LOG_DIR}/${TIMESTAMP}-pip-audit-host.json" 2>/dev/null || true
  else
    warn "pip-audit (host): invalid output"
    (( SCAN_ERRORS++ )) || true
  fi
fi

# K.1 VPS HOST — npm audit (auto-discovers all global roots + project dirs)
header "K.1 VPS HOST — npm audit (multi-root)"

# Auto-install npm if missing
if ! command -v npm &>/dev/null; then
  warn "npm not found on host — attempting install..."
  if [[ "$IS_MACOS" == "true" ]]; then
    brew install node 2>/dev/null && ok "node/npm installed via brew" || \
      { warn "brew install node failed — npm audit skipped"; }
  else
    sudo apt-get install -y nodejs npm 2>/dev/null && ok "nodejs/npm installed via apt" || \
      { warn "apt install nodejs npm failed — npm audit skipped"; }
  fi
fi

_run_npm_audit() {
  local label="$1" dir="$2"
  local out
  out=$(cd "$dir" && npm audit --json 2>/dev/null; true)
  if echo "$out" | jq -e '.error.code == "ENOLOCK"' &>/dev/null; then
    ok "  npm audit ($label): ENOLOCK — no lockfile (global install CVEs covered by Trivy)"
  elif echo "$out" | jq . &>/dev/null 2>&1; then
    local nc nh
    nc=$(echo "$out" | jq -r '.metadata.vulnerabilities.critical // 0' 2>/dev/null | head -1)
    nh=$(echo "$out" | jq -r '.metadata.vulnerabilities.high // 0' 2>/dev/null | head -1)
    (( TOTAL_CRITICAL += nc )) || true
    (( TOTAL_HIGH += nh )) || true
    [[ $((nc + nh)) -gt 0 ]] && \
      crit "  npm audit ($label): CRITICAL=${nc} HIGH=${nh}" || \
      ok "  npm audit ($label): Clean"
    echo "$out" > "${LOG_DIR}/${TIMESTAMP}-npm-audit-host-$(echo "$label" | tr '/ ' '__').json" 2>/dev/null || true
  else
    warn "  npm audit ($label): no output or invalid JSON"
  fi
}

if command -v npm &>/dev/null; then
  # Discover all npm global roots — current user, sudo/root, nvm, common fixed paths
  declare -A _npm_seen=()
  _npm_roots=()

  _try_npm_root() {
    local r="$1"
    local parent
    parent="$(dirname "$r" 2>/dev/null)"
    [[ -z "$r" || ! -d "$r" || -v "_npm_seen[$r]" ]] && return
    _npm_seen["$r"]=1
    _npm_roots+=("$parent")  # audit the prefix dir, not the node_modules subdir
    log "  Found npm global root: $r"
  }

  _try_npm_root "$(npm root -g 2>/dev/null || true)"
  _try_npm_root "$(sudo npm root -g 2>/dev/null || true)"

  # nvm-managed versions
  for _nvm_mod in "$HOME/.nvm/versions/node"/*/lib/node_modules; do
    [[ -d "$_nvm_mod" ]] && _try_npm_root "$_nvm_mod"
  done

  # Common fixed locations (Linux + macOS)
  for _p in /usr/lib/node_modules /usr/local/lib/node_modules \
             /opt/homebrew/lib/node_modules /usr/share/npm/node_modules; do
    [[ -d "$_p" ]] && _try_npm_root "$_p"
  done

  if [[ ${#_npm_roots[@]} -gt 0 ]]; then
    for _root in "${_npm_roots[@]}"; do
      [[ -d "$_root" ]] && _run_npm_audit "global:$_root" "$_root"
    done
  else
    ok "npm audit (host): no global npm roots found — not applicable"
  fi

  # Project package.json files in user homes (up to 4 levels deep)
  while IFS= read -r _pj; do
    _pd="$(dirname "$_pj")"
    _run_npm_audit "project:$_pd" "$_pd"
  done < <(find "$ADMIN_HOME" "$OPENCLAW_HOME" \
    -maxdepth 4 -name "package.json" ! -path "*/node_modules/*" 2>/dev/null | head -10)
else
  warn "npm not available — skipping K.1 entirely"
fi

# ── CODE SCAN PATH DISCOVERY (shared by Sections M and N) ───────────────────
# Builds _code_scan_roots: known dirs + git repos auto-discovered in home dirs.
# Deduplicates and skips paths already covered by a parent root.
declare -A _cs_seen=()
_code_scan_roots=()

_try_cs_root() {
  local _d="$1"
  [[ -z "$_d" || ! -d "$_d" ]] && return
  [[ -v "_cs_seen[$_d]" ]] && return
  local _r
  for _r in "${!_cs_seen[@]}"; do
    # Skip if new path is a child of an existing root (already covered)
    [[ "$_d" == "${_r}/"* ]] && return
    # Skip if new path is a PARENT of an existing root — existing is more specific.
    # Prevents adding /home/openclaw when /home/openclaw/openclaw-docker is already in.
    # This stops semgrep/osv-scanner walking .local/share/containers (20GB Podman layers).
    [[ "$_r" == "${_d}/"* ]] && return
  done
  _cs_seen["$_d"]=1
  _code_scan_roots+=("$_d")
}

# Known roots
# Add OPENCLAW_DOCKER_DIR first — the bidirectional check then blocks OPENCLAW_HOME
# from being added as a parent root, preventing semgrep/osv-scanner from walking
# .local/share/containers (Podman overlay layers, 20GB+) and .npm cache (535MB).
# Skills, startup.sh, proxy-init.js etc. are covered via OPENCLAW_DOCKER_DIR.
_try_cs_root "$OPENCLAW_DOCKER_DIR"
_try_cs_root "$ADMIN_HOME"
# Current directory — only if not already under a known root
_cwd_covered=false
for _r in "${!_cs_seen[@]}"; do
  [[ "$PWD" == "${_r}" || "$PWD" == "${_r}/"* ]] && _cwd_covered=true && break
done
[[ "$_cwd_covered" == "false" ]] && _try_cs_root "$PWD"
# Auto-discover git repos in home dirs (each .git parent = a project root)
while IFS= read -r _gd; do
  _try_cs_root "$(dirname "$_gd")"
done < <(find "$ADMIN_HOME" "$OPENCLAW_HOME" -maxdepth 5 -name ".git" -type d \
  2>/dev/null | head -15)

if [[ ${#_code_scan_roots[@]} -gt 0 ]]; then
  log "Code scan roots: ${#_code_scan_roots[@]}"
  for _r in "${_code_scan_roots[@]}"; do log "  $_r"; done
fi

# M. DEPENDENCY SCAN — osv-scanner (multi-ecosystem)
header "M. DEPENDENCY SCAN — osv-scanner (multi-ecosystem)"
if ! command -v osv-scanner &>/dev/null; then
  warn "osv-scanner not found — run: sudo bash $0 --install  (will prompt to add)"
elif [[ ${#_code_scan_roots[@]} -eq 0 ]]; then
  warn "No scan roots discovered — osv-scanner skipped"
else
  _osv_grand=0
  for _osv_dir in "${_code_scan_roots[@]}"; do
    subheader "osv-scanner: $(basename "$_osv_dir") (${_osv_dir})"
    _osv_tmp=$(mktemp)
    # osv-scanner exits 1 when findings are present — that is expected, not a failure
    _sparkle_run "Scanning $(basename "$_osv_dir") dependencies..." \
      osv-scanner scan --format json -r "$_osv_dir" > "$_osv_tmp" 2>/dev/null || true
    _osv_n=$(jq '[.results[]?.packages[]?.vulnerabilities[]?] | length' \
      "$_osv_tmp" 2>/dev/null || echo 0)
    if [[ "$_osv_n" -gt 0 ]]; then
      warn "osv-scanner ($(basename "$_osv_dir")): ${_osv_n} vulnerabilities"
      # Strip the scan root prefix so the full relative path is visible.
      # Makes it clear when a finding comes from .claude/plugins vs the user's own code.
      jq -r --arg root "$_osv_dir" '
        .results[]? |
        .source.path as $src |
        ($src | ltrimstr($root + "/") | split("/") | .[:-1] | join("/")) as $rel |
        .packages[]? |
        .package.name as $pkg | .package.version as $ver |
        .vulnerabilities[]? |
        "  [\(.id)] \($pkg) \($ver // "") (\($rel)) — \(.summary // .details // "no summary" | .[0:75])"' \
        "$_osv_tmp" 2>/dev/null | head -20 | tee -a "$REPORT_TXT" || true
      (( TOTAL_HIGH += _osv_n )) || true
      add_finding "osv-scan" "HIGH" "$(basename "$_osv_dir")" "osv-scanner" \
        "${_osv_n} dependency vulnerabilities in ${_osv_dir}"
    else
      ok "osv-scanner ($(basename "$_osv_dir")): Clean"
    fi
    (( _osv_grand += _osv_n )) || true
    cp "$_osv_tmp" \
      "${LOG_DIR}/${TIMESTAMP}-osv-$(basename "$_osv_dir").json" 2>/dev/null || true
    rm -f "$_osv_tmp"
  done
  log "osv-scanner total: ${_osv_grand} vulnerabilities across ${#_code_scan_roots[@]} path(s)"
fi

# N. SAST — semgrep
header "N. SAST — semgrep (code security)"
if ! command -v semgrep &>/dev/null; then
  warn "semgrep not installed on host — run: sudo bash $0 --install  (will prompt to add)"
  warn "Note: semgrep is baked into the openclaw-agent container for in-container code scanning"
elif [[ ${#_code_scan_roots[@]} -eq 0 ]]; then
  warn "No scan roots discovered — semgrep skipped"
else
  _sg_e_total=0
  _sg_w_total=0
  for _sg_dir in "${_code_scan_roots[@]}"; do
    subheader "semgrep: $(basename "$_sg_dir") (${_sg_dir})"
    _sg_tmp=$(mktemp)
    _sparkle_run "Semgrep scanning $(basename "$_sg_dir")..." \
      semgrep scan \
        --config auto \
        --json \
        --severity ERROR \
        --severity WARNING \
        --timeout 120 \
        --max-target-bytes 1000000 \
        --no-git-ignore \
        --exclude '.local' \
        --exclude '.npm' \
        --exclude '.cache' \
        --exclude 'node_modules' \
        --exclude 'overlay' \
        --exclude 'overlay2' \
        --exclude 'openclaw-deps' \
        --exclude 'logs' \
        --exclude 'agent-logs' \
        --exclude '.claude' \
        --exclude '.ssh' \
        --exclude '.sshbak' \
        --exclude '*.jsonl' \
        --exclude 'plugin-runtime-deps' \
        --exclude 'memory' \
        --exclude 'workspace-dev' \
        --exclude 'workspace-files' \
        --exclude 'completions' \
        --exclude 'agents' \
        --exclude 'tasks' \
        --exclude 'flows' \
        --exclude 'cron' \
        --exclude 'media' \
        --exclude 'devices' \
        --exclude 'session-delivery-queue' \
        --exclude 'subagents' \
        --exclude 'browser' \
        --exclude 'qqbot' \
        "$_sg_dir" > "$_sg_tmp" 2>/dev/null || true
    _sg_e=$(jq '[.results[]? | select(.extra.severity=="ERROR")]   | length' \
      "$_sg_tmp" 2>/dev/null || echo 0)
    _sg_w=$(jq '[.results[]? | select(.extra.severity=="WARNING")] | length' \
      "$_sg_tmp" 2>/dev/null || echo 0)
    if [[ $(( _sg_e + _sg_w )) -gt 0 ]]; then
      [[ "$_sg_e" -gt 0 ]] && \
        crit "semgrep ($(basename "$_sg_dir")): ${_sg_e} errors, ${_sg_w} warnings" || \
        warn "semgrep ($(basename "$_sg_dir")): ${_sg_w} warnings"
      log " Top findings:"
      jq -r '.results[]? |
        select(.extra.severity=="ERROR" or .extra.severity=="WARNING") |
        "  [\(.extra.severity)] \(.check_id | split(".")[-1]) — \(.path | split("/")[-1]):\(.start.line) — \(.extra.message | .[0:90])"' \
        "$_sg_tmp" 2>/dev/null | head -15 | tee -a "$REPORT_TXT" || true
      (( TOTAL_HIGH += _sg_e + _sg_w )) || true
      [[ "$_sg_e" -gt 0 ]] && \
        add_finding "sast" "HIGH" "$(basename "$_sg_dir")" "semgrep" \
          "${_sg_e} semgrep errors in ${_sg_dir}"
    else
      ok "semgrep ($(basename "$_sg_dir")): No findings"
    fi
    (( _sg_e_total += _sg_e )) || true
    (( _sg_w_total += _sg_w )) || true
    cp "$_sg_tmp" \
      "${LOG_DIR}/${TIMESTAMP}-semgrep-$(basename "$_sg_dir").json" 2>/dev/null || true
    rm -f "$_sg_tmp"
  done
  log "semgrep total: ${_sg_e_total} errors, ${_sg_w_total} warnings"
fi

# ── FINAL SUMMARY (exact format you requested) ─────────────────────────────────
header "SUMMARY"
{
  echo " Scan completed: $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo ""
  echo " ┌─────────────────────────────────────┐"
  echo " │ CRITICAL : ${TOTAL_CRITICAL}"
  echo " │ HIGH : ${TOTAL_HIGH}"
  echo " │ MEDIUM : ${TOTAL_MEDIUM}"
  echo " │ LOW : ${TOTAL_LOW}"
  echo " │ ERRORS : ${SCAN_ERRORS} (scan failures, not vulns)"
  echo " └─────────────────────────────────────┘"
  echo ""
  echo " Report : $REPORT_TXT"
  echo " JSON : $REPORT_JSON"
  echo " Trivy : ${LOG_DIR}/${TIMESTAMP}-trivy-*.json"
} | tee -a "$REPORT_TXT"

cat > "$REPORT_JSON" <<EOF
{
  "scan_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$(hostname)",
  "summary": {
    "critical": ${TOTAL_CRITICAL},
    "high": ${TOTAL_HIGH},
    "medium": ${TOTAL_MEDIUM},
    "low": ${TOTAL_LOW},
    "scan_errors": ${SCAN_ERRORS}
  },
  "findings": ${FINDINGS_JSON_ARRAY},
  "soc2_evidence": {
    "control": "CC7.1",
    "result": "$([ $((TOTAL_CRITICAL + TOTAL_HIGH)) -eq 0 ] && echo "PASS" || echo "FINDINGS")",
    "report_path": "${REPORT_TXT}"
  }
}
EOF
ok "JSON evidence written: $REPORT_JSON"

# ── AGENTSHIELD CONTROL PLANE UPLOAD ──────────────────────────────────────────
# Uploads scan results to the AgentShield CP for trending, dashboards, and alerts.
# Set AGENTSHIELD_API_KEY in environment or Doppler to enable.
# Endpoint: https://api.agentshield.ai/v1/scans (not yet live — stub only)
#
# To enable: add AGENTSHIELD_API_KEY to Doppler oc1/prd and it will auto-inject.
# To test manually: AGENTSHIELD_API_KEY=your-key sudo bash scanwell.sh
header "L. AGENTSHIELD CONTROL PLANE — Upload"
AS_API_KEY="${AGENTSHIELD_API_KEY:-}"
AS_ENDPOINT="${AGENTSHIELD_API_ENDPOINT:-https://api.agentshield.ai/v1/scans}"

if [[ -z "$AS_API_KEY" ]]; then
  printf "\n"
  printf "  ✨  ScanWell free tier active. Findings stay local — no dashboard, no alerts, no trending.\n"
  printf "      Unlock the full stack at %s\n" \
    "$(_hyperlink 'https://agentshield.ai/signup' 'agentshield.ai/signup')"
  printf "      Live dashboard · auto-alerts · SOC2 evidence exports · CVE trending — Starter from \$39/month\n\n"
  log "AGENTSHIELD_API_KEY not set — CP upload skipped"
else
  log "Uploading scan results to AgentShield CP..."
  AS_HTTP_CODE=$(curl -s -o /tmp/as-upload-response.json -w "%{http_code}" \
    -X POST "$AS_ENDPOINT" \
    -H "Authorization: Bearer ${AS_API_KEY}" \
    -H "Content-Type: application/json" \
    -H "X-AgentShield-Host: $(hostname)" \
    -H "X-AgentShield-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --data-binary "@${REPORT_JSON}" \
    --max-time 15 \
    2>/dev/null || echo "000")

  case "$AS_HTTP_CODE" in
    200|201|202)
      ok "CP upload: accepted (HTTP ${AS_HTTP_CODE})"
      ;;
    000)
      warn "CP upload: connection failed — endpoint unreachable or curl error"
      ;;
    401|403)
      warn "CP upload: authentication failed (HTTP ${AS_HTTP_CODE}) — check AGENTSHIELD_API_KEY"
      ;;
    404)
      warn "CP upload: endpoint not found (HTTP ${AS_HTTP_CODE}) — control plane not yet live"
      ;;
    *)
      warn "CP upload: unexpected response (HTTP ${AS_HTTP_CODE})"
      ;;
  esac
  rm -f /tmp/as-upload-response.json
fi
# ── END CP UPLOAD ──────────────────────────────────────────────────────────────



ALERT_COUNT=$(( TOTAL_CRITICAL + TOTAL_HIGH ))
if [[ "$SCAN_ERRORS" -gt 0 ]] && [[ "$ALERT_COUNT" -eq 0 ]]; then
  warn "Scan completed with ${SCAN_ERRORS} tool error(s) — some layers may be incomplete"
  exit 2
elif [[ "$ALERT_COUNT" -gt 0 ]]; then
  [[ "$TOTAL_CRITICAL" -gt 0 ]] && crit "CRITICAL FINDINGS: ${TOTAL_CRITICAL} issues at CRITICAL threshold"
  [[ "$TOTAL_HIGH" -gt 0 ]]     && warn "HIGH FINDINGS: ${TOTAL_HIGH} issues at HIGH threshold"
  [[ "$TOTAL_MEDIUM" -gt 0 ]]   && log  "MEDIUM FINDINGS: ${TOTAL_MEDIUM} issues at MEDIUM threshold"
  blue_header "NEXT STEPS"
  # Item 1 — AgentShield CTA: plain to file, hyperlinked to terminal
  _cta=" 1. 🚀  agentshield.ai/signup — live dashboard, auto-alerts, SOC2 evidence exports & CVE trending (Starter \$39/month)"
  printf ' 1. 🚀  %s — live dashboard, auto-alerts, SOC2 evidence exports & CVE trending (Starter $39/month)\n' \
    "$(_hyperlink 'https://agentshield.ai/signup' 'agentshield.ai/signup')"
  echo "$_cta" >> "$REPORT_TXT"
  echo " 2. Review full report:   cat $REPORT_TXT" | tee -a "$REPORT_TXT"
  echo " 3. Review Trivy JSON:    cat ${LOG_DIR}/${TIMESTAMP}-trivy-*.json | jq ." | tee -a "$REPORT_TXT"
  echo " 4. pip-audit details:    cat ${LOG_DIR}/${TIMESTAMP}-pip-audit-*.json | jq '.dependencies // . | .[] | select(.vulns|length>0)'" | tee -a "$REPORT_TXT"
  if [[ "$IS_MACOS" == "true" ]]; then
    echo " 5. Update packages:      brew upgrade && rebuild containers with patched base images" | tee -a "$REPORT_TXT"
  else
    echo " 5. Update packages:      sudo apt-get upgrade && rebuild containers with patched base images" | tee -a "$REPORT_TXT"
  fi
  echo " 6. File this report as SOC2 CC7.1 evidence" | tee -a "$REPORT_TXT"
  _sparkle_burst 4
  exit 1
else
  ok "CLEAN — No findings at or above HIGH threshold"
  ok "SOC2 CC7.1 evidence recorded: $REPORT_JSON"
  printf ' 🚀  %s — live dashboard, auto-alerts, SOC2 evidence exports & CVE trending (Starter $39/month)\n' \
    "$(_hyperlink 'https://agentshield.ai/signup' 'agentshield.ai/signup')"
  exit 0
fi
