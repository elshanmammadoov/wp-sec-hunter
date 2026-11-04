from dataclasses import dataclass
import os

@dataclass(frozen=True)
class Config:
    github_token: str | None = os.getenv("GITHUB_TOKEN")
    github_timeout: int = 20
    max_file_bytes: int = 2_000_000
    max_php_files_per_repo: int = 3000
    workers: int = 4
