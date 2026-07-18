#!/usr/bin/env python3
"""sslctl 发布 manifest 与 releases.json 的确定性本地操作。"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


ASSETS = (
    "sslctl-linux-amd64.gz",
    "sslctl-linux-arm64.gz",
    "sslctl-windows-amd64.exe.gz",
)
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$"
)
SIGNATURE = re.compile(r"^ed25519:[0-9A-Za-z._-]+:[A-Za-z0-9+/]+={0,2}$")


def fail(message: str) -> None:
    raise SystemExit(message)


def parse_version(version: str) -> tuple[tuple[int, int, int], tuple[tuple[int, object], ...] | None]:
    match = SEMVER.fullmatch(version)
    if not match:
        fail(f"无效 SemVer: {version}")
    core = tuple(int(match.group(i)) for i in range(1, 4))
    pre = match.group(4)
    if pre is None:
        return core, None
    identifiers: list[tuple[int, object]] = []
    for item in pre.split("."):
        identifiers.append((0, int(item)) if item.isdigit() else (1, item))
    return core, tuple(identifiers)


def channel_for(version: str) -> str:
    _, pre = parse_version(version)
    return "dev" if pre is not None else "main"


def compare_versions(left: str, right: str) -> int:
    left_core, left_pre = parse_version(left)
    right_core, right_pre = parse_version(right)
    if left_core != right_core:
        return 1 if left_core > right_core else -1
    if left_pre is None and right_pre is None:
        return 0
    if left_pre is None:
        return 1
    if right_pre is None:
        return -1
    for l_item, r_item in zip(left_pre, right_pre):
        if l_item == r_item:
            continue
        if l_item[0] != r_item[0]:
            return -1 if l_item[0] < r_item[0] else 1
        return 1 if l_item[1] > r_item[1] else -1
    return (len(left_pre) > len(right_pre)) - (len(left_pre) < len(right_pre))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"无法读取 JSON {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"JSON 顶层必须是对象: {path}")
    return value


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temp, path)


def create_manifest(args: argparse.Namespace) -> None:
    version = args.version.removeprefix("v")
    channel = channel_for(version)
    assets_dir = Path(args.assets_dir)
    signatures = load_json(Path(args.signatures))
    if set(signatures) != set(ASSETS):
        fail("签名集合必须与三项正式资产完全一致")
    assets: dict[str, dict[str, object]] = {}
    for name in ASSETS:
        path = assets_dir / name
        if not path.is_file():
            fail(f"缺少正式资产: {path}")
        signature = signatures[name]
        if not isinstance(signature, str) or not SIGNATURE.fullmatch(signature):
            fail(f"无效 Ed25519 签名: {name}")
        assets[name] = {"sha256": sha256(path), "signature": signature, "size": path.stat().st_size}
    dirty = args.dirty == "true"
    if channel == "main" and dirty:
        fail("main bundle 不允许 dirty=true")
    manifest = {
        "schema": 1,
        "product": "sslctl",
        "version": version,
        "channel": channel,
        "source_commit": args.source_commit,
        "dirty": dirty,
        "created_at": args.created_at,
        "build_time": args.build_time,
        "go_version": args.go_version,
        "assets": assets,
    }
    write_json(Path(args.output), manifest)


def verify_manifest_data(manifest: dict, bundle: Path, expected_version: str | None = None) -> None:
    required = {"schema", "product", "version", "channel", "source_commit", "dirty", "created_at", "build_time", "go_version", "assets"}
    if set(manifest) != required or manifest["schema"] != 1 or manifest["product"] != "sslctl":
        fail("manifest schema 或字段集合无效")
    version = str(manifest["version"])
    if expected_version and version != expected_version.removeprefix("v"):
        fail(f"manifest 版本不匹配: {version}")
    channel = channel_for(version)
    if manifest["channel"] != channel:
        fail("manifest 通道与版本不匹配")
    if not re.fullmatch(r"[0-9a-f]{40}", str(manifest["source_commit"])):
        fail("manifest source_commit 必须是完整 Git SHA")
    if not isinstance(manifest["dirty"], bool) or channel == "main" and manifest["dirty"]:
        fail("manifest dirty 字段无效")
    assets = manifest["assets"]
    if not isinstance(assets, dict) or set(assets) != set(ASSETS):
        fail("manifest 正式资产集合发生漂移")
    assets_dir = bundle / "assets"
    actual_files = {path.name for path in assets_dir.iterdir() if path.is_file()} if assets_dir.is_dir() else set()
    if actual_files != set(ASSETS):
        fail("bundle/assets 必须且只能包含三项正式资产")
    for name in ASSETS:
        meta = assets[name]
        path = assets_dir / name
        if not isinstance(meta, dict) or set(meta) != {"sha256", "signature", "size"}:
            fail(f"manifest 资产字段无效: {name}")
        if meta["size"] != path.stat().st_size or meta["sha256"] != sha256(path):
            fail(f"资产大小或 SHA256 不匹配: {name}")
        if not isinstance(meta["signature"], str) or not SIGNATURE.fullmatch(meta["signature"]):
            fail(f"资产签名格式无效: {name}")


def verify_manifest(args: argparse.Namespace) -> None:
    bundle = Path(args.bundle)
    manifest = load_json(bundle / "manifest.json")
    verify_manifest_data(manifest, bundle, args.version)
    print(json.dumps({"version": manifest["version"], "channel": manifest["channel"], "assets": list(ASSETS)}))


def release_entry(manifest: dict) -> dict:
    assets = manifest["assets"]
    return {
        "version": manifest["version"],
        "released_at": manifest["created_at"][:10],
        "source_commit": manifest["source_commit"],
        "dirty": manifest["dirty"],
        "checksums": {name: assets[name]["sha256"] for name in ASSETS},
        "signatures": {name: assets[name]["signature"] for name in ASSETS},
    }


def update_index(args: argparse.Namespace) -> None:
    bundle = Path(args.bundle)
    manifest = load_json(bundle / "manifest.json")
    verify_manifest_data(manifest, bundle, args.version)
    index_path = Path(args.index)
    index = load_json(index_path) if index_path.exists() else {}
    channel = manifest["channel"]
    info = index.setdefault(channel, {"latest": "", "versions": []})
    if not isinstance(info, dict) or not isinstance(info.get("versions"), list):
        fail(f"索引通道结构无效: {channel}")
    versions = info["versions"]
    existing = [item for item in versions if isinstance(item, dict) and item.get("version") == manifest["version"]]
    if channel == "main":
        if existing:
            expected = release_entry(manifest)
            if args.allow_existing_main and len(existing) == 1 and existing[0] == expected and info.get("latest") == manifest["version"]:
                write_json(Path(args.output), index)
                return
            fail(f"main 版本已存在，不可覆盖: {manifest['version']}")
        latest = info.get("latest", "")
        if latest and compare_versions(manifest["version"], latest) <= 0:
            fail(f"main 版本必须高于当前 latest {latest}")
    versions = [item for item in versions if not isinstance(item, dict) or item.get("version") != manifest["version"]]
    info["versions"] = [release_entry(manifest), *versions][:5]
    info["latest"] = manifest["version"]
    write_json(Path(args.output), index)


def verify_index(args: argparse.Namespace) -> None:
    bundle = Path(args.bundle)
    manifest = load_json(bundle / "manifest.json")
    verify_manifest_data(manifest, bundle, args.version)
    index = load_json(Path(args.index))
    info = index.get(manifest["channel"])
    expected = release_entry(manifest)
    if not isinstance(info, dict) or info.get("latest") != manifest["version"]:
        fail("索引 latest 与 manifest 不一致")
    matches = [item for item in info.get("versions", []) if isinstance(item, dict) and item.get("version") == manifest["version"]]
    if len(matches) != 1 or matches[0] != expected:
        fail("索引版本条目与 manifest 不一致")


def check_new_main(args: argparse.Namespace) -> None:
    version = args.version.removeprefix("v")
    if channel_for(version) != "main":
        fail("main 正式版必须是稳定 SemVer")
    index = load_json(Path(args.index))
    info = index.get("main", {"latest": "", "versions": []})
    if not isinstance(info, dict) or not isinstance(info.get("versions", []), list):
        fail("main 索引结构无效")
    if any(isinstance(item, dict) and item.get("version") == version for item in info.get("versions", [])):
        fail(f"main 版本已存在，不可覆盖: {version}")
    latest = info.get("latest", "")
    if latest and compare_versions(version, latest) <= 0:
        fail(f"main 版本必须高于当前 latest {latest}")


def state_identity(args: argparse.Namespace) -> tuple[str, str, str]:
    version = args.version.removeprefix("v")
    if channel_for(version) != "main":
        fail("release-state 只用于 main 稳定版本")
    commit = args.source_commit
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("release-state source_commit 必须是完整 Git SHA")
    bundle = os.path.abspath(args.bundle)
    if not os.path.isabs(args.bundle) or bundle == os.path.sep:
        fail("release-state bundle 必须是非根绝对路径")
    return version, commit, bundle


def load_release_state(path: Path, args: argparse.Namespace) -> tuple[dict, str, str, str]:
    version, commit, bundle = state_identity(args)
    state = load_json(path)
    required = {"schema", "version", "source_commit", "bundle", "status", "attempt", "bundle_digest"}
    if set(state) != required or state["schema"] != 1:
        fail("release-state schema 或字段集合无效")
    if state["version"] != version or state["source_commit"] != commit:
        fail("release-state 与版本或 commit 不匹配")
    if not isinstance(state["attempt"], int) or state["attempt"] < 1:
        fail("release-state attempt 无效")
    return state, version, commit, bundle


@contextmanager
def release_state_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def state_begin(args: argparse.Namespace) -> None:
    path = Path(args.state)
    with release_state_lock(path):
        version, commit, bundle = state_identity(args)
        attempt = 1
        if path.exists():
            state, _, _, _ = load_release_state(path, args)
            if state["status"] != "aborted":
                fail(f"main prepare 已有持久状态 {state['status']}，禁止重复构建")
            attempt = state["attempt"] + 1
        write_json(path, {
            "schema": 1,
            "version": version,
            "source_commit": commit,
            "bundle": bundle,
            "status": "preparing",
            "attempt": attempt,
            "bundle_digest": "",
        })


def state_complete(args: argparse.Namespace) -> None:
    path = Path(args.state)
    with release_state_lock(path):
        state, _, _, bundle = load_release_state(path, args)
        if not re.fullmatch(r"sha256:[0-9A-Za-z._-]+", args.bundle_digest):
            fail("bundle digest 格式无效")
        if state["status"] == "prepared" and state["bundle"] == bundle and state["bundle_digest"] == args.bundle_digest:
            return
        if state["status"] != "preparing" or state["bundle"] != bundle:
            fail("只有当前 preparing bundle 可以完成")
        state["status"] = "prepared"
        state["bundle_digest"] = args.bundle_digest
        write_json(path, state)


def state_verify(args: argparse.Namespace) -> None:
    path = Path(args.state)
    with release_state_lock(path):
        state, _, _, bundle = load_release_state(path, args)
        if state["status"] != "prepared" or state["bundle"] != bundle or state["bundle_digest"] != args.bundle_digest:
            fail("release-state 与已准备 bundle 不一致")


def state_abort(args: argparse.Namespace) -> None:
    path = Path(args.state)
    with release_state_lock(path):
        if not path.exists():
            version, commit, bundle = state_identity(args)
            write_json(path, {
                "schema": 1,
                "version": version,
                "source_commit": commit,
                "bundle": bundle,
                "status": "aborted",
                "attempt": 1,
                "bundle_digest": "",
            })
            return
        state, _, _, bundle = load_release_state(path, args)
        if state["bundle"] != bundle or state["status"] not in {"preparing", "aborted"}:
            fail("只有尚未完成的当前 bundle 可以显式废弃")
        state["status"] = "aborted"
        state["bundle_digest"] = ""
        write_json(path, state)


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    version_parser = sub.add_parser("channel")
    version_parser.add_argument("version")

    manifest_parser = sub.add_parser("create-manifest")
    manifest_parser.add_argument("--version", required=True)
    manifest_parser.add_argument("--assets-dir", required=True)
    manifest_parser.add_argument("--signatures", required=True)
    manifest_parser.add_argument("--output", required=True)
    manifest_parser.add_argument("--source-commit", required=True)
    manifest_parser.add_argument("--dirty", choices=("true", "false"), required=True)
    manifest_parser.add_argument("--created-at", default=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    manifest_parser.add_argument("--build-time", required=True)
    manifest_parser.add_argument("--go-version", required=True)

    verify_parser = sub.add_parser("verify-manifest")
    verify_parser.add_argument("--bundle", required=True)
    verify_parser.add_argument("--version")

    update_parser = sub.add_parser("update-index")
    update_parser.add_argument("--index", required=True)
    update_parser.add_argument("--bundle", required=True)
    update_parser.add_argument("--version", required=True)
    update_parser.add_argument("--output", required=True)
    update_parser.add_argument("--allow-existing-main", action="store_true")

    index_parser = sub.add_parser("verify-index")
    index_parser.add_argument("--index", required=True)
    index_parser.add_argument("--bundle", required=True)
    index_parser.add_argument("--version", required=True)

    preflight_parser = sub.add_parser("check-new-main")
    preflight_parser.add_argument("--index", required=True)
    preflight_parser.add_argument("--version", required=True)

    for command in ("state-begin", "state-complete", "state-verify", "state-abort"):
        state_parser = sub.add_parser(command)
        state_parser.add_argument("--state", required=True)
        state_parser.add_argument("--version", required=True)
        state_parser.add_argument("--source-commit", required=True)
        state_parser.add_argument("--bundle", required=True)
        if command in {"state-complete", "state-verify"}:
            state_parser.add_argument("--bundle-digest", required=True)

    args = parser.parse_args()
    if args.command == "channel":
        print(channel_for(args.version.removeprefix("v")))
    elif args.command == "create-manifest":
        create_manifest(args)
    elif args.command == "verify-manifest":
        verify_manifest(args)
    elif args.command == "update-index":
        update_index(args)
    elif args.command == "verify-index":
        verify_index(args)
    elif args.command == "check-new-main":
        check_new_main(args)
    elif args.command == "state-begin":
        state_begin(args)
    elif args.command == "state-complete":
        state_complete(args)
    elif args.command == "state-verify":
        state_verify(args)
    else:
        state_abort(args)


if __name__ == "__main__":
    main()
