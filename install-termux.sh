# ---------------------------------------------------------------------------
# Termux (Android) installer for RUK SHADOW INTELLIGENCE
#
#   pkg install git -y && cd ruk-shadow-intelligence && bash install-termux.sh
#
# Termux has no systemd and no root, so this installs packages with pkg and
# runs everything inside a virtualenv in your home directory.
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; DIM='\033[2m'; NC='\033[0m'
say()  { printf "${CYAN}[*]${NC} %s\n" "$1"; }
ok()   { printf "${GREEN}[+]${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}[~]${NC} %s\n" "$1"; }
fail() { printf "${RED}[!]${NC} %s\n" "$1" >&2; exit 1; }

printf "\n${CYAN}RUK SHADOW INTELLIGENCE${NC} ${DIM}Termux installer${NC}\n\n"

# -- 0. confirm we are really in Termux --------------------------------------
if [ -z "${PREFIX:-}" ] || [ ! -d "${PREFIX:-}/bin" ]; then
  warn "PREFIX is not set - this does not look like Termux."
  warn "On a normal Linux system use ./install.sh instead."
  printf "Continue anyway? [y/N] "; read -r ANSWER
  case "$ANSWER" in [yY]*) ;; *) fail "aborted" ;; esac
fi

# -- 1. packages -------------------------------------------------------------
say "Installing system packages (this may take a few minutes)"
pkg update -y && pkg upgrade -y
# python: interpreter; libjpeg-turbo + libpng: Pillow wheels for qrcode
pkg install -y python python-pip libjpeg-turbo libpng || fail "pkg install failed"
ok "system packages installed"

# -- 2. venv -----------------------------------------------------------------
say "Creating virtual environment"
if [ ! -d venv ]; then
  python -m venv venv || fail "venv failed - try: pkg install python"
fi
# shellcheck disable=SC1091
source venv/bin/activate
python -m pip install --quiet --upgrade pip
ok "virtualenv active"

# -- 3. dependencies ---------------------------------------------------------
say "Installing Python dependencies"
# Pillow needs a compiler on some Termux builds; try the wheel first and fall
# back to a source build with the required headers.
if ! python -m pip install --quiet -r requirements.txt; then
  warn "wheel install failed - retrying Pillow from source"
  pkg install -y libjpeg-turbo-static libpng-static clang make
  python -m pip install --quiet --no-binary Pillow pillow \
    || fail "Pillow could not be built. Run: pkg install libjpeg-turbo libpng clang make"
  python -m pip install --quiet -r requirements.txt || fail "dependency install failed"
fi
ok "dependencies installed"

# -- 4. directories ----------------------------------------------------------
say "Preparing directories"
mkdir -p data reports qr_codes
chmod 700 data 2>/dev/null || true
ok "directories ready"

# -- 5. configuration --------------------------------------------------------
if [ ! -f .env ]; then
  say "Creating .env"
  cp .env.example .env
  SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  sed -i "s|^SECRET_KEY=$|SECRET_KEY=${SECRET}|" .env
  # Bind to localhost by default; open it up only when you mean to.
  sed -i 's|^BIND_HOST=127.0.0.1|BIND_HOST=127.0.0.1|' .env
  chmod 600 .env
  ok ".env created with a fresh secret"
else
  ok ".env already exists - left untouched"
fi

# -- 6. database -------------------------------------------------------------
say "Initialising the database"
python - <<'PY'
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
python -m pytest tests/ -q 2>&1 | tail -3 || warn "some tests failed - review them"

printf "\n"
printf "${GREEN}Installation complete.${NC}\n\n"
printf "  ${DIM}Create an administrator:${NC}\n"
printf "     source venv/bin/activate\n"
printf "     python terminal_dashboard.py --create-admin\n\n"
printf "  ${DIM}Start the server:${NC}\n"
printf "     python app.py\n\n"
printf "  ${DIM}Terminal interface:${NC}\n"
printf "     python terminal_dashboard.py\n\n"
printf "${YELLOW}Termux notes${NC}\n"
printf "  - Termux has no systemd. Use tmux to keep the server alive:\n"
printf "      pkg install tmux && tmux new -s ruk 'python app.py'\n"
printf "  - Battery optimisation may kill background sessions. Run\n"
printf "      termux-wake-lock\n"
printf "    before starting the server.\n"
printf "  - Links are only reachable from other devices once BIND_HOST and\n"
printf "    PUBLIC_BASE_URL are set to an address your phone actually has,\n"
printf "    or you expose it through a tunnel.\n\n"
