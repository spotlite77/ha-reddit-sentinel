# HA Reddit Sentinel

**Read-only monitoring of Reddit communities for Home Assistant users.**
Security advisories, vulnerability disclosures and breaking-change releases for the open-source software you self-host — delivered as notifications inside Home Assistant.

> 🚧 **Status: v0.1 — core engine working.** The polling, matching, deduplication and Home Assistant notification pipeline is implemented and covered by offline tests. Live use requires your own approved Reddit API app (see Reddit's Responsible Builder Policy).

## Why

The open-source projects behind a modern homelab (Home Assistant, Zigbee2MQTT, Jellyfin…) announce security advisories and breaking changes in their Reddit communities — often before anywhere else. If you don't browse those subreddits every day, you can miss a critical CVE for weeks. HA Reddit Sentinel watches them for you and only interrupts you when a post concerns software or devices you actually run.

## How it works

1. Every 30 minutes, the service polls the *new* listings of a small set of public subreddits via the official Reddit Data API (OAuth2, read-only).
2. Each new post (title + body) is matched locally against **your inventory** — the software and devices you declare in the configuration — combined with alert keywords (`security`, `vulnerability`, `CVE`, `breaking change`, `critical update`…).
3. On a match, the post's title, link, subreddit and timestamp are stored in a local SQLite database and a **notification is created in Home Assistant** through its API.
4. Posts that don't match are discarded immediately and never stored.

Default monitored subreddits: r/homeassistant, r/selfhosted, r/Zigbee2MQTT, r/jellyfin (fully configurable).

## Principles

- **Read-only, always.** The app never posts, comments, votes, follows or sends messages.
- **Your credentials, your instance.** Every user runs their own instance with their own Reddit API credentials.
- **Minimal data.** Only the title, link, subreddit and timestamp of matched posts are kept — on your own server. Nothing is redistributed.
- **Polite polling.** A few dozen requests per hour, far below the API rate limits.

## Example configuration

See [`config.example.yaml`](config.example.yaml).

## Quick start (Docker)

```bash
git clone https://github.com/spotlite77/ha-reddit-sentinel.git
cd ha-reddit-sentinel
mkdir data
cp config.example.yaml data/config.yaml
# edit data/config.yaml: your Reddit app credentials, your inventory,
# your Home Assistant URL and long-lived access token
docker compose -f docker-compose.example.yml up -d --build
```

On its very first run, the service silently records the posts that already match (no notification flood about old posts) — only new posts trigger alerts.

Without Docker, Python 3.11+ works too:

```bash
pip install -r requirements.txt
python sentinel.py --config config.yaml          # daemon mode
python sentinel.py --config config.yaml --once   # single pass (cron, tests)
```

## Development

Offline tests (matching, deduplication, notification payloads — no network, no credentials):

```bash
python -m unittest discover -s tests -v
```

## Roadmap

- [x] Polling engine + keyword/inventory matching
- [x] Home Assistant notifications (persistent notification + mobile push)
- [x] Deduplication and CVE identifier extraction
- [ ] Optional MQTT discovery sensors for Home Assistant
- [ ] Docker image on a public registry and HACS distribution

## Reddit API compliance

This project is developed under Reddit's Data API Terms and Responsible Builder Policy: non-commercial, open source, read-only access to public posts only.

## License

MIT — see [LICENSE](LICENSE).
