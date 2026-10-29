# Installation

## Requirements

| Component | Minimum | Notes |
|---|---|---|
| Python | 3.9 | 3.11 recommended; the suite is tested on 3.11 |
| SQLite | 3.24 | Bundled with Python |
| RAM | ~80 MB | Plus ~40 MB per concurrent SSE viewer |
| Disk | ~30 MB | Excluding the database |
| OS | Linux, Termux | Windows works but is untested |

## Kali Linux / Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git

git clone https://github.com/Janrahat/ruk-shadow-intelligence.git
cd ruk-shadow-intelligence

chmod +x install.sh
./install.sh
```

The installer checks the Python version, creates `venv/`, installs
dependencies, prepares `data/ reports/ qr_codes/`, copies `.env.example` to
`.env` with a freshly generated secret, initialises the database and runs the
test suite.

### Manual installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip wheel
pip install -r requirements.txt

mkdir -p data reports qr_codes
chmod 700 data

cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # paste into SECRET_KEY
chmod 600 .env
```

Initialise and confirm the schema:

```bash
python -c "from config import Config; from database import Database; \
cfg = Config.from_env(); db = Database(cfg.database_file); \
print('schema', db.schema_version()); db.close()"
```

## Termux on Android

Termux has no root and no `systemd`, and Pillow may need to compile from source.

```bash
pkg update -y && pkg upgrade -y
pkg install -y git python

git clone https://github.com/Janrahat/ruk-shadow-intelligence.git
cd ruk-shadow-intelligence

bash install-termux.sh
```

Step by step:

```bash
pkg install -y python python-pip libjpeg-turbo libpng
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

mkdir -p data reports qr_codes
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # paste into SECRET_KEY
```

If Pillow fails to build, install the headers and retry:

```bash
pkg install -y libjpeg-turbo-static libpng-static clang make
pip install --no-binary Pillow pillow
```

Keep the process alive across Android's battery throttling:

```bash
pkg install -y tmux
termux-wake-lock
tmux new -s ruk 'source venv/bin/activate && python app.py'
# detach: Ctrl-B then D      reattach: tmux attach -t ruk
```

> **Reachability on a phone.** Links created on a phone only reach other devices
> if `PUBLIC_BASE_URL` and `BIND_HOST` point at an address the phone actually has
> on the network (for example `http://192.168.1.42:8000`), or you expose the port
> through a tunnel. A phone on mobile data has no inbound address. That is a
> property of mobile networking, not a setting.

## Local development

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python terminal_dashboard.py --create-admin
python app.py
```

With `RUK_ENV=development` the app falls back to Werkzeug's development server
and prints a warning. That server is not hardened; do not expose it.

## Production with HTTPS

Tracking links carry a consent notice and session cookies, so they must be
served over HTTPS. Two supported arrangements.

### Caddy (automatic certificates)

```caddyfile
analytics.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8000
}
```

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name analytics.example.com;

    ssl_certificate     /etc/letsencrypt/live/analytics.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/analytics.example.com/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }

    # The live feed must not be buffered or it will not stream.
    location /admin/stream {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering    off;
        proxy_cache        off;
        proxy_read_timeout 24h;
    }
}
```

### Required `.env` for production

```ini
RUK_ENV=production
PUBLIC_BASE_URL=https://analytics.example.com
BIND_HOST=127.0.0.1
BIND_PORT=8000
REQUIRE_HTTPS_LINKS=true
SESSION_COOKIE_SECURE=true
TRUST_PROXY_HEADERS=true
SECRET_KEY=<64 hex characters>
```

`RUK_ENV=production` makes the app **refuse to start** when the secret is
missing or short, when `PUBLIC_BASE_URL` is not HTTPS, or when session cookies
are not marked secure. A misconfiguration becomes a startup error instead of a
silent weakness.

## First run

```bash
source venv/bin/activate
python terminal_dashboard.py --create-admin   # prompts twice for a password
python app.py
```

Expected output:

```
[RUK] Waitress serving on http://127.0.0.1:8000 (env=development)
```

Open `http://127.0.0.1:8000/admin/login`, sign in, and create a link from
**Links**. Open that link in a private window to see the visitor's notice page
and watch the event arrive on the dashboard.
