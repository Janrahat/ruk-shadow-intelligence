# ---------------------------------------------------------------------------
# Kali Linux / Debian / Ubuntu installer for RUK SHADOW INTELLIGENCE
#
#   chmod +x install.sh && ./install.sh
#
# Creates a virtualenv, installs dependencies, prepares directories and
# generates a secret. It does NOT start the server - see the README.
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; DIM='\033[2m'; NC='\033[0m'
say()  { printf "${CYAN}[*]${NC} %s\n" "$1"; }
ok()   { printf "${GREEN}[+]${NC} %s\n" "$1"; }
fail() { printf "${RED}[!]${NC} %s\n" "$1" >&2; exit 1; }

printf "\n${CYAN}RUK SHADOW INTELLIGENCE${NC} ${DIM}installer${NC}\n\n"

# -- 1. python ---------------------------------------------------------------
say "Checking Python"
command -v python3 >/dev/null 2>&1 || fail "python3 not found. Install it: sudo apt install python3 python3-venv python3-pip"
PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info[0])')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info[1])')
[ "$PY_MAJOR" -eq 3 ] || fail "Python 3 is required (found $PY_MAJOR.$PY_MINOR)"
[ "$PY_MINOR" -ge 9 ] || fail "Python 3.9 or newer is required (found 3.$PY_MINOR)"
ok "Python 3.$PY_MINOR"

# -- 2. venv -----------------------------------------------------------------
say "Creating virtual environment"
if [ ! -d venv ]; then
  python3 -m venv venv || fail "venv creation failed. On Debian: sudo apt install python3-venv"
fi
# shellcheck disable=SC1091
source venv/bin/activate
ok "virtualenv active"

# -- 3. dependencies ---------------------------------------------------------
say "Installing Python dependencies"
python -m pip install --quiet --upgrade pip wheel
python -m pip install --quiet -r requirements.txt || fail "dependency installation failed"
ok "dependencies installed"

# -- 4. directories ----------------------------------------------------------
say "Preparing directories"
mkdir -p data reports qr_codes
chmod 700 data
ok "data/ reports/ qr_codes/ ready"

# -- 5. configuration --------------------------------------------------------
if [ ! -f .env ]; then
  say "Creating .env from .env.example"
  cp .env.example .env
  # 32 random bytes -> 64 hex characters
  SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  if grep -q '^SECRET_KEY=$' .env; then
    sed -i "s|^SECRET_KEY=$|SECRET_KEY=${SECRET}|" .env
  fi
  chmod 600 .env
  ok ".env created (mode 600) with a fresh secret"
else
  ok ".env already exists - left untouched"
fi

# -- 6. database -------------------------------------------------------------
say "Initialising the database"
python - <<'PY'
import os
from config import Config
from database import Database
cfg = Config.from_env()
db = Database(cfg.database_file)
print(f"    schema version {db.schema_version()}")
db.close()
PY
ok "database ready"

# -- 7. tests ----------------------------------------------------------------
say "Running the test suite"
if python -m pytest tests/ -q 2>&1 | tail -3; then
  ok "tests passed"
else
  printf "${RED}[!]${NC} tests reported failures - the install completed but review them\n"
fi

printf "\n"
printf "${GREEN}Installation complete.${NC}\n\n"
printf "  ${DIM}1. Create an administrator:${NC}\n"
printf "     source venv/bin/activate\n"
printf "     python terminal_dashboard.py --create-admin\n\n"
printf "  ${DIM}2. Start the server:${NC}\n"
printf "     python app.py\n\n"
printf "  ${DIM}3. Or use the terminal interface:${NC}\n"
printf "     python terminal_dashboard.py\n\n"
printf "  ${DIM}Before sharing links, set PUBLIC_BASE_URL in .env to your real address.${NC}\n\n"
