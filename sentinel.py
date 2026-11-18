#!/usr/bin/env python3
"""
HA Reddit Sentinel — read-only monitoring of Reddit communities for
Home Assistant users.

Polls the "new" listings of a small set of public subreddits via the
official Reddit Data API (PRAW, OAuth2), matches each post against a
local inventory of software/devices combined with alert keywords, and
sends a Home Assistant notification when a post is relevant.

Read-only by design: this program never posts, comments, votes,
follows or sends messages on Reddit.

Usage:
    python sentinel.py [--config config.yaml] [--once]

Without --once, it runs forever, polling at the configured interval.
"""

from __future__ import annotations

import argparse
import logging
import re
import sqlite3
import sys
import time
from pathlib import Path

import praw
import requests
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("reddit-sentinel")

CVE_RE = re.compile(r"cve-\d{4}-\d{4,7}", re.IGNORECASE)
FETCH_LIMIT = 50  # posts read per subreddit and per poll


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def load_config(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    for section in ("reddit", "polling", "inventory", "home_assistant"):
        if section not in cfg:
            raise ValueError(f"Missing '{section}' section in config file")
    return cfg


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

def match_post(title: str, body: str, inventory: list[str],
               alert_keywords: list[str]) -> dict | None:
    """Return match details if the post concerns the user's stack AND
    looks like an alert (alert keyword or CVE identifier), else None."""
    text = f"{title}\n{body or ''}".lower()

    inv_hit = next((item for item in inventory if item.lower() in text), None)
    if inv_hit is None:
        return None

    kw_hit = next((kw for kw in alert_keywords if kw.lower() in text), None)
    cves = sorted({c.upper() for c in CVE_RE.findall(text)})
    if kw_hit is None and not cves:
        return None

    return {"inventory": inv_hit, "keyword": kw_hit, "cves": cves}


# --------------------------------------------------------------------------
# Storage (deduplication)
# --------------------------------------------------------------------------

class AlertStore:
    def __init__(self, db_path: str | Path):
        self.db = sqlite3.connect(db_path)
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                post_id    TEXT PRIMARY KEY,
                subreddit  TEXT NOT NULL,
                title      TEXT NOT NULL,
                url        TEXT NOT NULL,
                author     TEXT,
                created_utc REAL,
                matched    TEXT,
                notified   INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self.db.commit()

    def is_empty(self) -> bool:
        (count,) = self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()
        return count == 0

    def record(self, post, match: dict, notified: bool) -> bool:
        """Insert a matched post. Return True if it is new."""
        cur = self.db.execute(
            "INSERT OR IGNORE INTO alerts "
            "(post_id, subreddit, title, url, author, created_utc, matched, notified) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                post.id,
                str(post.subreddit),
                post.title,
                f"https://www.reddit.com{post.permalink}",
                str(post.author) if post.author else None,
                post.created_utc,
                match["inventory"],
                1 if notified else 0,
            ),
        )
        self.db.commit()
        return cur.rowcount == 1


# --------------------------------------------------------------------------
# Home Assistant notification
# --------------------------------------------------------------------------

def notify_home_assistant(cfg: dict, post, match: dict) -> None:
    ha = cfg["home_assistant"]
    base = ha["url"].rstrip("/")
    headers = {
        "Authorization": f"Bearer {ha['token']}",
        "Content-Type": "application/json",
    }
    reasons = [f"Concerne : {match['inventory']}"]
    if match["keyword"]:
        reasons.append(f"Mot-clé : {match['keyword']}")
    if match["cves"]:
        reasons.append("CVE : " + ", ".join(match["cves"]))
    title = f"Reddit Sentinel — r/{post.subreddit}"
    message = f"{post.title}\n" + " · ".join(reasons)
    link = f"https://www.reddit.com{post.permalink}"

    # Persistent notification inside Home Assistant (always).
    resp = requests.post(
        f"{base}/api/services/persistent_notification/create",
        headers=headers,
        json={
            "title": title,
            "message": f"{message}\n\n{link}",
            "notification_id": f"reddit_sentinel_{post.id}",
        },
        timeout=15,
    )
    resp.raise_for_status()

    # Mobile push, if a notify service is configured.
    service = (ha.get("notify_service") or "").removeprefix("notify.").strip()
    if service:
        resp = requests.post(
            f"{base}/api/services/notify/{service}",
            headers=headers,
            json={"title": title, "message": message, "data": {"url": link}},
            timeout=15,
        )
        resp.raise_for_status()


# --------------------------------------------------------------------------
# Reddit access + one polling pass
# --------------------------------------------------------------------------

def build_reddit(cfg: dict) -> praw.Reddit:
    rcfg = cfg["reddit"]
    kwargs = {
        "client_id": rcfg["client_id"],
        "client_secret": rcfg["client_secret"],
        "user_agent": rcfg["user_agent"],
    }
    # Optional user context, depending on the registered app type:
    # "script" apps use username/password, "web" apps a refresh token.
    # With neither, PRAW runs in app-only (read-only) mode, which is
    # enough to read public subreddit listings.
    if rcfg.get("refresh_token"):
        kwargs["refresh_token"] = rcfg["refresh_token"]
    elif rcfg.get("username") and rcfg.get("password"):
        kwargs["username"] = rcfg["username"]
        kwargs["password"] = rcfg["password"]
    return praw.Reddit(**kwargs)


def run_once(reddit: praw.Reddit, cfg: dict, store: AlertStore,
             seed: bool = False) -> int:
    """One polling pass over every configured subreddit.
    Returns the number of new alerts notified (0 in seed mode)."""
    inventory = cfg["inventory"]
    keywords = cfg["alert_keywords"]
    notified = 0

    for sub_name in cfg["polling"]["subreddits"]:
        try:
            posts = list(reddit.subreddit(sub_name).new(limit=FETCH_LIMIT))
        except Exception as exc:  # network error, 403/429, subreddit gone…
            log.warning("r/%s : lecture impossible (%s)", sub_name, exc)
            continue

        for post in posts:
            match = match_post(post.title, getattr(post, "selftext", ""),
                               inventory, keywords)
            if match is None:
                continue
            is_new = store.record(post, match, notified=not seed)
            if is_new and not seed:
                try:
                    notify_home_assistant(cfg, post, match)
                    notified += 1
                    log.info("Alerte : [%s] %s", sub_name, post.title)
                except Exception as exc:
                    log.warning("Notification HA échouée pour %s (%s)",
                                post.id, exc)
        log.info("r/%s : %d publications analysées", sub_name, len(posts))

    return notified


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="HA Reddit Sentinel")
    parser.add_argument("--config", default="config.yaml",
                        help="chemin du fichier de configuration")
    parser.add_argument("--once", action="store_true",
                        help="un seul passage, puis sortie (tests, cron)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    db_path = Path(args.config).resolve().parent / "sentinel.db"
    store = AlertStore(db_path)
    reddit = build_reddit(cfg)

    # First ever run: record existing matches silently, so the user is
    # not flooded with alerts about old posts. Only future posts notify.
    seed = store.is_empty()
    if seed:
        log.info("Premier lancement : initialisation silencieuse de la base.")

    interval = int(cfg["polling"].get("interval_minutes", 30)) * 60
    while True:
        try:
            n = run_once(reddit, cfg, store, seed=seed)
            if not seed:
                log.info("Passage terminé : %d nouvelle(s) alerte(s).", n)
            seed = False
        except Exception as exc:
            log.error("Passage interrompu : %s", exc)
        if args.once:
            return 0
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
