from __future__ import annotations
import time
import requests
from urllib.parse import quote

class GitHubClient:
    API = "https://api.github.com"
    def __init__(self, token=None, timeout=20):
        self.s = requests.Session()
        self.timeout = timeout
        self.s.headers.update({
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ZeroDayHunter/6.0"
        })
        if token:
            self.s.headers["Authorization"] = f"Bearer {token}"

    def get(self, path, params=None):
        for attempt in range(4):
            r = self.s.get(self.API + path, params=params, timeout=self.timeout)
            if r.status_code in (403, 429):
                retry = int(r.headers.get("Retry-After", "2"))
                time.sleep(min(30, retry * (attempt + 1)))
                continue
            r.raise_for_status()
            return r
        r.raise_for_status()

    def search_repositories(self, query, pages=1):
        out, seen = [], set()
        for page in range(1, pages + 1):
            r = self.get("/search/repositories", {
                "q": query, "sort": "updated", "order": "desc", "per_page": 100, "page": page
            })
            for x in r.json().get("items", []):
                if x["full_name"] not in seen:
                    seen.add(x["full_name"])
                    out.append(x)
            if len(r.json().get("items", [])) < 100:
                break
        return out
