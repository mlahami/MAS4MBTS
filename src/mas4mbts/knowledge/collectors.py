"""Online collectors for raw knowledge sources."""

from __future__ import annotations

from io import BytesIO
import re
from pathlib import Path
from typing import Any
from zipfile import ZipFile

from src.mas4mbts.knowledge.github_api import github_contents, github_file_text, github_repo_metadata
from src.mas4mbts.knowledge.http_client import fetch_bytes, fetch_text
from src.mas4mbts.knowledge.paths import RAW_DIR, REGISTRY_DIR
from src.mas4mbts.knowledge.snapshot import sha256_bytes, utc_now, write_raw_text
from src.mas4mbts.utils.json_io import read_json


ERC_FILE_RE = re.compile(r"^erc-(\d+)\.md$", re.IGNORECASE)


def source_by_id(source_id: str) -> dict[str, Any]:
    sources = read_json(REGISTRY_DIR / "sources.json")["sources"]
    return next(source for source in sources if source["id"] == source_id)


def normalize_erc_number(value: str | int) -> str:
    text = str(value).strip().lower().replace("erc-", "")
    if not text.isdigit():
        raise ValueError(f"Invalid ERC number: {value}")
    return text


def collect_erc_specs(erc_numbers: list[str] | None = None, limit: int | None = None, ref: str | None = None) -> dict[str, Any]:
    """Collect ERC markdown specifications from ethereum/ERCs into raw/ercs."""
    source = source_by_id("ethereum_ercs_repo")
    repo_meta = github_repo_metadata("ethereum", "ERCs")
    branch = ref or repo_meta["default_branch"]
    raw_template = source["raw_url_template"].replace("/master/", f"/{branch}/")

    if erc_numbers:
        numbers = [normalize_erc_number(item) for item in erc_numbers]
    else:
        contents = github_contents("ethereum", "ERCs", "ERCS", ref=branch)
        numbers = []
        for item in contents:
            match = ERC_FILE_RE.match(item.get("name", ""))
            if match:
                numbers.append(match.group(1))
        numbers = sorted(numbers, key=lambda value: int(value))
        if limit is not None:
            numbers = numbers[:limit]

    files = []
    for number in numbers:
        url = raw_template.format(erc_number=number)
        content = fetch_text(url).text
        target = RAW_DIR / "ercs" / f"erc-{number}.md"
        file_record = write_raw_text(target, content)
        file_record.update({"erc": f"ERC-{number}", "url": url})
        files.append(file_record)

    return {
        "source_id": source["id"],
        "collected_at": utc_now(),
        "repo": repo_meta,
        "ref": branch,
        "files": files,
    }


def _collect_github_markdown_tree(
    owner: str,
    repo: str,
    source_id: str,
    raw_subdir: str,
    root_path: str = "",
    ref: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    repo_meta = github_repo_metadata(owner, repo)
    branch = ref or repo_meta["default_branch"]
    pending = [root_path]
    files = []

    while pending:
        current = pending.pop(0)
        for item in github_contents(owner, repo, current, ref=branch):
            item_type = item.get("type")
            item_path = item.get("path", "")
            if item_type == "dir":
                pending.append(item_path)
            elif item_type == "file" and item_path.lower().endswith((".md", ".json", ".yaml", ".yml")):
                if limit is not None and len(files) >= limit:
                    pending = []
                    break
                content = github_file_text(owner, repo, item_path, ref=branch)
                target = RAW_DIR / raw_subdir / item_path
                file_record = write_raw_text(target, content)
                file_record.update(
                    {
                        "repo_path": item_path,
                        "url": item.get("html_url", ""),
                        "api_url": item.get("url", ""),
                    }
                )
                files.append(file_record)

    return {
        "source_id": source_id,
        "collected_at": utc_now(),
        "repo": repo_meta,
        "ref": branch,
        "files": files,
    }


def collect_swc_registry(limit: int | None = None, ref: str | None = None) -> dict[str, Any]:
    """Collect raw SWC registry markdown/json/yaml files."""
    return _collect_github_markdown_tree(
        owner="SmartContractSecurity",
        repo="SWC-registry",
        source_id="swc_registry",
        raw_subdir="swc",
        root_path="",
        ref=ref,
        limit=limit,
    )


def collect_github_archive(
    owner: str,
    repo: str,
    source_id: str,
    raw_subdir: str,
    include_prefixes: list[str] | None = None,
    suffixes: tuple[str, ...] = (".md", ".json", ".yaml", ".yml"),
    file_name_pattern: str | None = None,
    ref: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Download a GitHub repository archive and extract matching files."""
    repo_meta = github_repo_metadata(owner, repo)
    branch = ref or repo_meta["default_branch"]
    archive_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
    archive_content, _, status = fetch_bytes(archive_url)
    archive_sha = sha256_bytes(archive_content)
    files = []
    file_name_re = re.compile(file_name_pattern, re.IGNORECASE) if file_name_pattern else None

    with ZipFile(BytesIO(archive_content)) as archive:
        members = sorted(member for member in archive.namelist() if not member.endswith("/"))
        for member in members:
            relative_parts = member.split("/", 1)
            if len(relative_parts) != 2:
                continue
            relative_path = relative_parts[1]
            if include_prefixes and not any(relative_path.startswith(prefix) for prefix in include_prefixes):
                continue
            if not relative_path.lower().endswith(suffixes):
                continue
            if file_name_re and not file_name_re.match(Path(relative_path).name):
                continue
            if limit is not None and len(files) >= limit:
                break
            content = archive.read(member)
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                continue
            target = RAW_DIR / raw_subdir / relative_path
            file_record = write_raw_text(target, text)
            file_record.update(
                {
                    "repo_path": relative_path,
                    "url": f"https://github.com/{owner}/{repo}/blob/{branch}/{relative_path}",
                }
            )
            files.append(file_record)

    return {
        "source_id": source_id,
        "collected_at": utc_now(),
        "repo": repo_meta,
        "ref": branch,
        "archive": {
            "url": archive_url,
            "status": status,
            "bytes": len(archive_content),
            "sha256": archive_sha,
        },
        "files": files,
    }


def collect_all_erc_specs(ref: str | None = None, limit: int | None = None) -> dict[str, Any]:
    return collect_github_archive(
        owner="ethereum",
        repo="ERCs",
        source_id="ethereum_ercs_repo",
        raw_subdir="ercs",
        include_prefixes=["ERCS/"],
        suffixes=(".md",),
        file_name_pattern=r"^erc-\d+\.md$",
        ref=ref,
        limit=limit,
    )


def collect_all_swc_registry(ref: str | None = None, limit: int | None = None) -> dict[str, Any]:
    return collect_github_archive(
        owner="SmartContractSecurity",
        repo="SWC-registry",
        source_id="swc_registry",
        raw_subdir="swc",
        include_prefixes=None,
        suffixes=(".md", ".json", ".yaml", ".yml"),
        ref=ref,
        limit=limit,
    )


def collect_owasp_pages(limit: int | None = None) -> dict[str, Any]:
    """Collect configured OWASP Smart Contract Security pages."""
    source = source_by_id("owasp_smart_contract_security")
    pages = source.get("pages", [])
    if limit is not None:
        pages = pages[:limit]

    files = []
    for page in pages:
        response = fetch_text(page["url"])
        target = RAW_DIR / "owasp" / f"{page['id']}.html"
        file_record = write_raw_text(target, response.text)
        file_record.update({"page_id": page["id"], "url": page["url"], "status": response.status})
        files.append(file_record)

    return {
        "source_id": source["id"],
        "collected_at": utc_now(),
        "files": files,
    }


def collect_all_owasp_scs(ref: str | None = None, limit: int | None = None) -> dict[str, Any]:
    return collect_github_archive(
        owner="OWASP",
        repo="owasp-scs",
        source_id="owasp_smart_contract_security",
        raw_subdir="owasp",
        include_prefixes=None,
        suffixes=(".md", ".json", ".yaml", ".yml"),
        ref=ref,
        limit=limit,
    )


def collect_configured_pages(source_id: str, raw_subdir: str, extension: str = "html", limit: int | None = None) -> dict[str, Any]:
    """Collect configured web pages from sources.json into a raw subdirectory."""
    source = source_by_id(source_id)
    pages = source.get("pages", [])
    if limit is not None:
        pages = pages[:limit]

    files = []
    for page in pages:
        response = fetch_text(page["url"])
        target = RAW_DIR / raw_subdir / f"{page['id']}.{extension}"
        file_record = write_raw_text(target, response.text)
        file_record.update({"page_id": page["id"], "url": page["url"], "status": response.status})
        files.append(file_record)

    return {
        "source_id": source["id"],
        "collected_at": utc_now(),
        "files": files,
    }


def collect_mitre_attack_pages(limit: int | None = None) -> dict[str, Any]:
    return collect_configured_pages("mitre_attack", "mitre_attack", limit=limit)


def collect_cvss_pages(limit: int | None = None) -> dict[str, Any]:
    return collect_configured_pages("first_cvss", "risk_models/cvss", limit=limit)


def collect_nist_pages(limit: int | None = None) -> dict[str, Any]:
    return collect_configured_pages("nist_sp_800_53", "nist", limit=limit)
