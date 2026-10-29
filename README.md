# RUK SHADOW INTELLIGENCE

Self-hosted, **consent-based** link analytics for Kali Linux, Termux and any
Linux distribution. A hacker-styled terminal interface, a live web dashboard,
real-time event streaming, and a privacy model where nothing about a visitor is
stored until that visitor has read a plain-language notice and chosen to allow it.

Full documentation lives in [`docs/`](docs/):

| Document | Contents |
|---|---|
| [Installation](docs/installation.md) | Kali/Debian, Termux, local dev, production HTTPS |
| [Consent model](docs/consent-and-data.md) | How the gateway works and exactly which fields are stored |
| [Security](docs/security.md) | Auth, CSRF, injection, SSRF, headers, rate limiting, secrets |
| [Configuration](docs/configuration.md) | Every environment variable and its default |
| [Testing](docs/testing.md) | How to run the suite and what it actually proves |
| [Operations](docs/operations.md) | Running, stopping, systemd, troubleshooting |
| [Design limits](docs/design-limits.md) | Bugs found by running it, and what is *not* verified |

## Quick start

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python terminal_dashboard.py --create-admin
python app.py
```

Then open `http://127.0.0.1:8000/admin/login`.

## What it is not

A tracking link is a normal web link. It cannot read passwords, messages, files,
contacts, camera or microphone data, and this project never asks for a GPS
position or fingerprints a device. Every guarantee above is asserted by a test.

## Licence and responsible use

Run this only on links you distribute yourself, to people whose attention you
legitimately have, with a notice that matches your jurisdiction's requirements.
The software gives you the mechanism to collect lawful, consented-to analytics;
it cannot make a deployment lawful.
