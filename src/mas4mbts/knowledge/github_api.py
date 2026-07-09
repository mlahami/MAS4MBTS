"""Helpers for GitHub repository content collection."""

from __future__ import annotations

import base64
from typing import Any

from src.mas4mbts.knowledge.http_client import fetch_json, fetch_text


def github_contents(owner: str, repo: str, path: str = "", ref: str = "master") -> list[dict[str, Any]]:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}"
    payload = fetch_json(url)
    if isinstance(payload, dict):
        return [payload]
    return payload


def github_repo_metadata(owner: str, repo: str) -> dict[str, Any]:
    repo_payload = fetch_json(f"https://api.github.com/repos/{owner}/{repo}")
    branch = repo_payload.get("default_branch", "master")
    branch_payload = fetch_json(f"https://api.github.com/repos/{owner}/{repo}/branches/{branch}")
    return {
        "owner": owner,
        "repo": repo,
        "default_branch": branch,
        "commit_sha": branch_payload.get("commit", {}).get("sha"),
        "html_url": repo_payload.get("html_url"),
    }


def fetch_download_url(download_url: str) -> str:
    return fetch_text(download_url).text


def github_file_text(owner: str, repo: str, path: str, ref: str = "master") -> str:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}"
    payload = fetch_json(url)
    encoding = payload.get("encoding")
    content = payload.get("content", "")
    if encoding == "base64":
        return base64.b64decode(content).decode("utf-8")
    if "download_url" in payload and payload["download_url"]:
        return fetch_download_url(payload["download_url"])
    raise ValueError(f"Unsupported GitHub file payload for {owner}/{repo}/{path}")
