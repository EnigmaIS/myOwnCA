#!/usr/bin/env bash
# myOwnCA install script — run from the repository root.
# Sets up the Python environment, generates secrets, writes .env,
# bootstraps the administrator account(s), and optionally starts the service.
set -euo pipefail

# ── colours ──────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

info()    { echo -e "${CYAN}  →${RESET} $*"; }
ok()      { echo -e "${GREEN}  ✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}  !${RESET} $*"; }
die()     { echo -e "${RED}  ✗ ERROR:${RESET} $*" >&2; exit 1; }
heading() { echo -e "\n${BOLD}$*${RESET}"; }

# ── helpers ───────────────────────────────────────────────────────────────────
ask() {
  # ask <varname> <prompt> [default]
  local varname="$1" prompt="$2" default="${3:-}"
  local display_default=""
  [ -n "$default" ] && display_default=" [${default}]"
  while true; do
    printf "${BOLD}%s%s: ${RESET}" "$prompt" "$display_default"
    read -r value
    value="${value:-$default}"
    if [ -n "$value" ]; then
      printf -v "$varname" '%s' "$value"
      return
    fi
    warn "Value required."
  done
}

ask_secret() {
  # ask_secret <varname> <prompt> — reads without echo
  local varname="$1" prompt="$2"
  while true; do
    printf "${BOLD}%s: ${RESET}" "$prompt"
    read -rs value
    echo
    [ -n "$value" ] && { printf -v "$varname" '%s' "$value"; return; }
    warn "Value required."
  done
}

ask_password() {
  # ask_password <varname> <prompt> — reads without echo, enforces min length 16
  local varname="$1" prompt="$2"
  while true; do
    printf "${BOLD}%s (min 16 chars): ${RESET}" "$prompt"
    read -rs pw
    echo
    if [ "${#pw}" -lt 16 ]; then
      warn "Password must be at least 16 characters."
      continue
    fi
    printf "${BOLD}Confirm password: ${RESET}"
    read -rs pw2
    echo
    if [ "$pw" != "$pw2" ]; then
      warn "Passwords do not match."
      continue
    fi
    printf -v "$varname" '%s' "$pw"
    return
  done
}

ask_yn() {
  # ask_yn <prompt> [Y|N]  → returns 0 (yes) or 1 (no)
  local prompt="$1" default="${2:-Y}"
  local hint; [ "$default" = "Y" ] && hint="Y/n" || hint="y/N"
  printf "${BOLD}%s [%s]: ${RESET}" "$prompt" "$hint"
  read -r ans
  ans="${ans:-$default}"
  case "$ans" in [Yy]*) return 0;; *) return 1;; esac
}

gen_secret() {
  python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
}

require_python312() {
  for candidate in python3.12 python3.13 python3.14 python3; do
    if command -v "$candidate" &>/dev/null; then
      if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 12) else 1)' &>/dev/null; then
        echo "$candidate"; return 0
      fi
    fi
  done
  return 1
}

# ── banner ────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}╔══════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║       myOwnCA — Installer         ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════╝${RESET}"
echo

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"
info "Working directory: $REPO_ROOT"
warn "DEVELOPMENT SOURCE INSTALL: release integrity is not enforced."
warn "For production use signed packages and docs/release-signing.md."

# ── step 1 — Python ───────────────────────────────────────────────────────────
heading "Step 1 — Python environment"

PYTHON=$(require_python312) || die "Python 3.12 or newer is required. Install it and re-run."
ok "Using Python: $PYTHON ($($PYTHON --version))"

VENV="$REPO_ROOT/.venv"
if [ -d "$VENV" ]; then
  warn "Virtual environment already exists at .venv — reusing it."
else
  info "Creating virtual environment…"
  "$PYTHON" -m venv "$VENV"
  ok "Virtual environment created."
fi

PIP="$VENV/bin/pip"
BB_ONLINE="$VENV/bin/myownca-online"
BB_AUTH="$VENV/bin/myownca-auth-bootstrap"
BB_OFFLINE="$VENV/bin/myownca-offline"

info "Installing package (pip install -e .)…"
"$PIP" install --quiet -e .
ok "Package installed."

if ask_yn "Install optional dev tools (pytest, ruff)?"; then
  info "Installing dev extras…"
  "$PIP" install --quiet -e '.[dev]'
  ok "Dev extras installed."
fi

# ── step 1b — smartcard / HSM (optional) ──────────────────────────────────────
HSM_BACKEND=software
PKCS11_LIB=""
if ask_yn "Enable smartcard / HSM support (SmartCard-HSM, NitroKey HSM)?" "N"; then
  info "Installing HSM extra (python-pkcs11)…"
  "$PIP" install --quiet -e '.[hsm]'
  ok "python-pkcs11 installed."

  if command -v sc-hsm-tool &>/dev/null; then
    ok "Found sc-hsm-tool: $(command -v sc-hsm-tool)"
  else
    warn "sc-hsm-tool not found — install OpenSC for token init/DKEK management."
    warn "  Debian/Ubuntu: sudo apt-get install opensc"
  fi

  for cand in \
    /usr/lib/pkcs11/opensc-pkcs11.so \
    /usr/lib64/pkcs11/opensc-pkcs11.so \
    /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so \
    /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
    /usr/local/lib/opensc-pkcs11.so; do
    if [ -f "$cand" ]; then PKCS11_LIB="$cand"; break; fi
  done
  if [ -n "$PKCS11_LIB" ]; then
    ok "Found PKCS#11 module: $PKCS11_LIB"
  else
    warn "No opensc-pkcs11.so found — set MYOWNCA_PKCS11_LIB manually after installing OpenSC."
  fi

  if ask_yn "Make the smartcard the default signing backend at startup?" "N"; then
    HSM_BACKEND=pkcs11
  fi
  ask PKCS11_TOKEN_LABEL "PKCS#11 token label" "myOwnCA"
  ask DKEK_SHARE_DIR     "DKEK share directory" "./var/dkek-shares"
  info "You can also hot-switch backends from the admin portal at any time."
fi

# ── step 1c — ACME / service certificates (optional) ──────────────────────────
if ask_yn "Enable ACME (Let's Encrypt) support for service certificates?" "N"; then
  info "Installing ACME extra (acme, josepy)…"
  "$PIP" install --quiet -e '.[acme]'
  ok "ACME client installed."
  info "HTTP-01 validation needs port 80 reachable by the ACME server; DNS-01 is manual TXT mode."
fi

# ── step 1d — database backend (optional) ─────────────────────────────────────
DATABASE_URL=""
if ask_yn "Use an external MariaDB/MySQL database instead of the default SQLite file?" "N"; then
  info "Installing MariaDB driver (PyMySQL)…"
  "$PIP" install --quiet -e '.[mariadb]'
  ok "PyMySQL installed."
  ask DATABASE_URL "Database URL" "mysql+pymysql://myownca:password@127.0.0.1:3306/myownca"
  info "Ensure the database exists and the user can create tables; the schema is migrated on first start."
else
  info "Using the default embedded SQLite database."
fi

# ── step 2 — .env ─────────────────────────────────────────────────────────────
heading "Step 2 — Environment configuration (.env)"

ENV_FILE="$REPO_ROOT/.env"

if [ -f "$ENV_FILE" ]; then
  warn ".env already exists."
  if ! ask_yn "Overwrite it with new settings?"; then
    info "Keeping existing .env."
    set -a; . "$ENV_FILE"; set +a
    SKIP_ENV=1
  fi
fi

if [ "${SKIP_ENV:-0}" != "1" ]; then
  echo
  info "Generating cryptographic secrets…"
  KEY_PASS=$(gen_secret)
  AUTH_SECRET=$(gen_secret)
  OFFLINE_PASS=$(gen_secret)
  ok "Secrets generated."

  echo
  info "Database and key directory paths (press Enter to accept defaults):"
  ask DB_PATH   "Database path"         "./var/myownca.sqlite3"
  ask KEY_DIR   "Online key directory"  "./var/online-keys"
  ask IDENTITY  "Online source identity" "online-host"
  ask LAB_CN    "Lab CA common name"    "myOwnCA Lab Issuing CA"

  echo
  if ask_yn "Enable LAB_MODE (development issuer fallback)?"; then
    LAB_MODE=true
  else
    LAB_MODE=false
  fi

  echo
  if [ "$LAB_MODE" = "true" ]; then
    info "Lab installs default to single-admin governance."
    if ask_yn "Use dual control instead (two administrators required)?" "N"; then
      GOVERNANCE_MODE=dual_control
    else
      GOVERNANCE_MODE=single_admin
    fi
  else
    info "Dual control is recommended for production installs."
    if ask_yn "Use the recommended dual-control mode?" "Y"; then
      GOVERNANCE_MODE=dual_control
    else
      GOVERNANCE_MODE=single_admin
      warn "Single-admin mode allows any one administrator to apply privileged changes."
    fi
  fi

  echo
  info "TOTP is recommended for Administrator and Certificate Operator accounts."
  TOTP_REQUIRED_ROLES=""
  if ask_yn "Require TOTP for Administrators?" "Y"; then
    TOTP_REQUIRED_ROLES="admin"
  fi
  if ask_yn "Require TOTP for Certificate Operators?" "Y"; then
    [ -n "$TOTP_REQUIRED_ROLES" ] && TOTP_REQUIRED_ROLES+=","
    TOTP_REQUIRED_ROLES+="superuser"
  fi
  if ask_yn "Require TOTP for Auditors?" "N"; then
    [ -n "$TOTP_REQUIRED_ROLES" ] && TOTP_REQUIRED_ROLES+=","
    TOTP_REQUIRED_ROLES+="auditor"
  fi
  if ask_yn "Require TOTP for ordinary Users?" "N"; then
    [ -n "$TOTP_REQUIRED_ROLES" ] && TOTP_REQUIRED_ROLES+=","
    TOTP_REQUIRED_ROLES+="user"
  fi

  if ask_yn "Set SESSION_COOKIE_SECURE=true (requires HTTPS)?"; then
    COOKIE_SECURE=true
  else
    COOKIE_SECURE=false
  fi

  echo
  warn "The following secrets have been auto-generated and will be written to .env."
  warn "Record the passphrases — if you lose them you must reset local key state."
  echo

  cat > "$ENV_FILE" <<EOF
# Generated by install.sh on $(date -u '+%Y-%m-%dT%H:%M:%SZ')
MYOWNCA_DATABASE_PATH=${DB_PATH}
MYOWNCA_DATABASE_URL=${DATABASE_URL}
MYOWNCA_ONLINE_KEY_DIR=${KEY_DIR}
MYOWNCA_ONLINE_KEY_PASSPHRASE=${KEY_PASS}
MYOWNCA_ONLINE_SOURCE_IDENTITY=${IDENTITY}
MYOWNCA_AUTH_ENCRYPTION_SECRET=${AUTH_SECRET}
MYOWNCA_SESSION_COOKIE_SECURE=${COOKIE_SECURE}
MYOWNCA_LAB_MODE=${LAB_MODE}
MYOWNCA_GOVERNANCE_MODE=${GOVERNANCE_MODE}
MYOWNCA_TOTP_REQUIRED_ROLES=${TOTP_REQUIRED_ROLES}
MYOWNCA_LAB_COMMON_NAME="${LAB_CN}"
MYOWNCA_OFFLINE_KEY_PASSPHRASE=${OFFLINE_PASS}
MYOWNCA_HSM_BACKEND=${HSM_BACKEND}
MYOWNCA_PKCS11_LIB=${PKCS11_LIB}
MYOWNCA_PKCS11_TOKEN_LABEL="${PKCS11_TOKEN_LABEL:-myOwnCA}"
MYOWNCA_PKCS11_DKEK_SHARE_DIR=${DKEK_SHARE_DIR:-./var/dkek-shares}
MYOWNCA_SERVICE_KEY_DIR=./var/service-keys
EOF
  ok ".env written."

  set -a; . "$ENV_FILE"; set +a
fi

# ── step 3 — directories ──────────────────────────────────────────────────────
heading "Step 3 — Creating var directories"

mkdir -p \
  "$(dirname "${MYOWNCA_DATABASE_PATH:-./var/myownca.sqlite3}")" \
  "${MYOWNCA_ONLINE_KEY_DIR:-./var/online-keys}" \
  "${MYOWNCA_SERVICE_KEY_DIR:-./var/service-keys}"
ok "Directories ready."

# ── step 4 — bootstrap admins ─────────────────────────────────────────────────
heading "Step 4 — Bootstrap admin accounts"

if ! DB_EXISTS=$("$VENV/bin/python" -c '
from myownca.ca_auth.repository import AuthRepository
from myownca.config import Settings
from myownca.storage.database import Database

settings = Settings.from_env()
target = settings.database_url or settings.database_path
database = Database(target)
database.migrate()
print(1 if AuthRepository(database).has_any_users() else 0)
'); then
  die "Could not inspect the configured database before administrator bootstrap."
fi

if [ "$DB_EXISTS" = "1" ]; then
  warn "Users already exist in the configured database — skipping bootstrap."
else
  GOVERNANCE_MODE="${MYOWNCA_GOVERNANCE_MODE:-}"
  if [ -z "$GOVERNANCE_MODE" ]; then
    if [ "${MYOWNCA_LAB_MODE:-false}" = "true" ]; then
      GOVERNANCE_MODE=single_admin
      info "No governance mode is set; using the Lab single-admin default."
    else
      info "No governance mode is set. Dual control is recommended for production."
      if ask_yn "Use dual-control governance?" "Y"; then
        GOVERNANCE_MODE=dual_control
      else
        GOVERNANCE_MODE=single_admin
        warn "Single-admin mode allows one administrator to apply privileged changes."
      fi
    fi
  fi
  case "$GOVERNANCE_MODE" in
    single_admin|dual_control) ;;
    *) die "MYOWNCA_GOVERNANCE_MODE must be single_admin or dual_control." ;;
  esac

  echo
  if [ "$GOVERNANCE_MODE" = "dual_control" ]; then
    echo "  Dual control requires two administrator accounts."
  else
    echo "  Single-admin governance allows one administrator to apply privileged changes."
  fi
  echo "  Temporary passwords must be at least 16 characters."
  if [[ ",${MYOWNCA_TOTP_REQUIRED_ROLES:-admin,superuser}," == *,admin,* ]]; then
    echo "  Each administrator must change their password and enroll TOTP on first login."
  else
    echo "  Each administrator must change their password on first login; Administrator TOTP is disabled."
  fi
  echo

  ask        ADMIN1_ID    "Admin 1 — username ID"    "admin-1"
  ask        ADMIN1_EMAIL "Admin 1 — email"          "admin1@example.test"
  ask_password ADMIN1_PASS  "Admin 1 — temporary password"

  CREATE_ADMIN2=false
  if [ "$GOVERNANCE_MODE" = "dual_control" ]; then
    CREATE_ADMIN2=true
  else
    echo
    if ask_yn "Create an optional second administrator now?" "N"; then
      CREATE_ADMIN2=true
    fi
  fi

  if [ "$CREATE_ADMIN2" = "true" ]; then
    echo
    ask        ADMIN2_ID    "Admin 2 — username ID"    "admin-2"
    ask        ADMIN2_EMAIL "Admin 2 — email"          "admin2@example.test"
    ask_password ADMIN2_PASS  "Admin 2 — temporary password"
  fi

  echo
  info "Running myownca-auth-bootstrap…"
  BOOTSTRAP_ARGS=(
    --governance-mode "$GOVERNANCE_MODE"
    --totp-required-roles "${MYOWNCA_TOTP_REQUIRED_ROLES:-admin,superuser}"
    --admin-1-id "$ADMIN1_ID"
    --admin-1-email "$ADMIN1_EMAIL"
    --admin-1-password "$ADMIN1_PASS"
  )
  if [ "$CREATE_ADMIN2" = "true" ]; then
    BOOTSTRAP_ARGS+=(
      --admin-2-id "$ADMIN2_ID"
      --admin-2-email "$ADMIN2_EMAIL"
      --admin-2-password "$ADMIN2_PASS"
    )
  fi
  "$BB_AUTH" "${BOOTSTRAP_ARGS[@]}"
  ok "Administrator account(s) created in ${GOVERNANCE_MODE} mode."
fi

# ── step 5 — offline root (optional) ──────────────────────────────────────────
heading "Step 5 — Offline root CA (optional)"

if ask_yn "Create an offline root CA now (recommended for production)?"; then
  ask OFFLINE_CN  "Offline root CA common name" "myOwnCA Offline Root CA"
  ask OFFLINE_DIR "Offline state directory"     "./var/offline"
  ask OFFLINE_OUT "Offline export directory"    "./var/offline-export"

  mkdir -p "$OFFLINE_DIR" "$OFFLINE_OUT"

  info "Running myownca-offline root-create…"
  "$BB_OFFLINE" root-create \
    --state-dir  "$OFFLINE_DIR" \
    --common-name "$OFFLINE_CN" \
    --output-dir  "$OFFLINE_OUT"
  ok "Offline root created."
  echo
  info "Root certificate : ${OFFLINE_OUT}/root-ca.pem"
  info "Initial root CRL : ${OFFLINE_OUT}/root-crl-0001.pem"
  info "Use the admin portal to complete the offline→online sub-CA handoff."
else
  info "Skipping offline root — lab mode issuer will be used instead."
fi

# ── step 6 — start service ────────────────────────────────────────────────────
heading "Step 6 — Start the service"

echo
echo -e "  Admin portals will be at ${CYAN}http://127.0.0.1:8000/app/admin${RESET}"
echo -e "  Login page will be at    ${CYAN}http://127.0.0.1:8000/login${RESET}"
echo

if ask_yn "Start myownca-online now?"; then
  echo
  echo -e "${BOLD}Starting myOwnCA online service…${RESET}"
  echo -e "  Press ${BOLD}Ctrl-C${RESET} to stop.\n"
  exec "$BB_ONLINE"
else
  echo
  heading "Setup complete — next steps"
  echo
  echo "  1. Activate the environment and load .env in each new terminal:"
  echo
  echo "       . .venv/bin/activate"
  echo "       set -a && . ./.env && set +a"
  echo
  echo "  2. Start the service:"
  echo
  echo "       myownca-online"
  echo
  echo "  3. Open the login page:"
  echo
  echo -e "       ${CYAN}http://127.0.0.1:8000/login${RESET}"
  echo
  echo "  4. Sign in with each bootstrap administrator and change the temporary password."
  if [[ ",${MYOWNCA_TOTP_REQUIRED_ROLES:-admin,superuser}," == *,admin,* ]]; then
    echo "     Enroll TOTP when prompted before continuing."
  fi
  echo
  echo "  5. Optional — scheduled certificate notifications (expiring/expired):"
  echo "     configure templates and rules in the superuser portal (Settings),"
  echo "     then add a daily crontab entry (the rules' own periods gate sends):"
  echo
  echo "       15 7 * * * cd $(pwd) && set -a && . ./.env && set +a && .venv/bin/myownca-notify-run"
  echo
  ok "Installation complete."
fi
