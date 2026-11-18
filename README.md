# HA Reddit Sentinel

**Read-only monitoring of Reddit communities for Home Assistant users.**
Security advisories, vulnerability disclosures and breaking-change releases for the open-source software you self-host — delivered as notifications inside Home Assistant.

> 🚧 **Status: in development.** Currently being tested on the author's own homelab. A first public release is planned once the core polling and matching engine is stable.

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

## Roadmap

- [ ] Polling engine + keyword/inventory matching
- [ ] Home Assistant notifications (persistent notification + mobile push)
- [ ] Deduplication and CVE identifier extraction
- [ ] Optional MQTT discovery sensors for Home Assistant
- [ ] Docker image and HACS distribution

## Reddit API compliance

This project is developed under Reddit's Data API Terms and Responsible Builder Policy: non-commercial, open source, read-only access to public posts only.

## License

MIT — see [LICENSE](LICENSE).
