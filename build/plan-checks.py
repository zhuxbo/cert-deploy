#!/usr/bin/env python3
"""根据 Git 变更和 Go 依赖图生成 finish-check 执行计划。"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


MUTATION_EXCLUDED_PREFIXES = ("docker/test/mock-api/",)
CRITICAL_PACKAGE_PREFIXES = (
    "pkg/certops",
    "pkg/config",
    "pkg/fetcher",
    "pkg/upgrade",
    "pkg/validator",
    "internal/deployer",
    "internal/nginx",
    "internal/docker",
)
SHARED_CONTRACT_FILES = {
    "pkg/certops/types.go",
    "pkg/webserver/types.go",
}
MUTATION_INFRA_FILES = {
    "Makefile",
    "build/mutation-canaries.txt",
    "build/plan-checks.py",
    "build/run-changed-checks.sh",
    "build/run-mutation.sh",
    "build/test-check-planner.sh",
    "build/test-mutation.sh",
    ".github/workflows/mutation.yml",
}
DEPLOY_E2E_PREFIXES = (
    "cmd/daemon/",
    "cmd/deploy/",
    "cmd/setup/",
    "internal/apache/",
    "internal/deployer/",
    "internal/nginx/",
    "pkg/certops/",
)


def run(root: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        args,
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"命令失败 ({' '.join(args)}): {detail}")
    return result.stdout


def git_ref(root: Path, ref: str) -> str | None:
    result = subprocess.run(
        ("git", "rev-parse", "--verify", ref),
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def determine_base(root: Path, explicit: str | None) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if explicit:
        resolved = git_ref(root, explicit)
        if not resolved:
            raise RuntimeError(f"无法解析基线: {explicit}")
        return explicit, reasons

    upstream = run(root, "git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}", check=False).strip()
    if upstream:
        merge_base = run(root, "git", "merge-base", "HEAD", upstream).strip()
        head = run(root, "git", "rev-parse", "HEAD").strip()
        if merge_base != head:
            return merge_base, reasons

    has_worktree_changes = bool(
        run(root, "git", "status", "--porcelain", "--untracked-files=normal").strip()
    )
    if has_worktree_changes:
        return "HEAD", reasons

    if git_ref(root, "HEAD^"):
        reasons.append("工作区无变更，检查最近一次提交")
        return "HEAD^", reasons

    return "HEAD", reasons


def changed_files(root: Path, base: str) -> list[str]:
    paths: set[str] = set()
    head = run(root, "git", "rev-parse", "HEAD").strip()
    base_sha = run(root, "git", "rev-parse", base).strip()
    if base_sha != head:
        paths.update(run(root, "git", "diff", "--name-only", f"{base}...HEAD").splitlines())
    paths.update(run(root, "git", "diff", "--name-only").splitlines())
    paths.update(run(root, "git", "diff", "--cached", "--name-only").splitlines())
    paths.update(run(root, "git", "ls-files", "--others", "--exclude-standard").splitlines())
    return sorted(path for path in paths if path)


def load_go_packages(root: Path) -> list[dict[str, Any]]:
    output = run(root, "go", "list", "-json", "./...")
    decoder = json.JSONDecoder()
    packages: list[dict[str, Any]] = []
    offset = 0
    while offset < len(output):
        while offset < len(output) and output[offset].isspace():
            offset += 1
        if offset >= len(output):
            break
        package, offset = decoder.raw_decode(output, offset)
        packages.append(package)
    return packages


def relative_package(root: Path, directory: str) -> str | None:
    try:
        relative = Path(directory).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None
    return "." if relative == "." else f"./{relative}"


def package_graph(root: Path) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    packages: list[dict[str, Any]] = []
    by_import: dict[str, dict[str, Any]] = {}
    for raw in load_go_packages(root):
        target = relative_package(root, raw.get("Dir", ""))
        import_path = raw.get("ImportPath")
        if not target or not import_path or raw.get("Standard"):
            continue
        package = {
            "target": target,
            "import_path": import_path,
            "relative_dir": target.removeprefix("./") if target != "." else "",
            "deps": set(raw.get("Deps", [])),
            "weight": sum(
                (root / target.removeprefix("./") / filename).stat().st_size
                for filename in raw.get("GoFiles", []) + raw.get("CgoFiles", [])
                if (root / target.removeprefix("./") / filename).is_file()
            ),
        }
        packages.append(package)
        by_import[import_path] = package
    packages.sort(key=lambda item: item["target"])
    return packages, by_import


def package_for_file(packages: list[dict[str, Any]], path: str) -> dict[str, Any] | None:
    parent = Path(path).parent.as_posix()
    matches = [
        package
        for package in packages
        if parent == package["relative_dir"]
    ]
    return matches[0] if matches else None


def is_mutation_excluded(path: str) -> bool:
    return any(path == prefix.rstrip("/") or path.startswith(prefix) for prefix in MUTATION_EXCLUDED_PREFIXES)


def is_critical_package(target: str) -> bool:
    relative = target.removeprefix("./")
    return any(relative == prefix or relative.startswith(f"{prefix}/") for prefix in CRITICAL_PACKAGE_PREFIXES)


def has_build_constraint(root: Path, path: str) -> bool:
    if not path.endswith(".go"):
        return False
    name = Path(path).name
    if any(marker in name for marker in ("_windows.go", "_linux.go", "_darwin.go", "_unix.go")):
        return True
    file_path = root / path
    if not file_path.is_file():
        return False
    try:
        with file_path.open(encoding="utf-8") as handle:
            return any(line.startswith("//go:build") for _, line in zip(range(8), handle))
    except UnicodeDecodeError:
        return False


def build_plan(root: Path, base: str | None, force_full: bool) -> dict[str, Any]:
    selected_base, base_reasons = determine_base(root, base)
    files = changed_files(root, selected_base)
    packages, by_import = package_graph(root)

    changed_go = [path for path in files if path.endswith(".go")]
    changed_test_go = [path for path in changed_go if path.endswith("_test.go")]
    changed_prod_go = [path for path in changed_go if not path.endswith("_test.go")]
    direct_packages = {
        package["import_path"]
        for path in changed_go
        if (package := package_for_file(packages, path)) is not None
    }
    direct_prod_packages = {
        package["import_path"]
        for path in changed_prod_go
        if not is_mutation_excluded(path)
        if (package := package_for_file(packages, path)) is not None
    }
    direct_test_packages = {
        package["import_path"]
        for path in changed_test_go
        if not is_mutation_excluded(path)
        if (package := package_for_file(packages, path)) is not None
    }

    affected_imports = set(direct_packages)
    if direct_packages:
        affected_imports.update(
            package["import_path"]
            for package in packages
            if package["deps"].intersection(direct_packages)
        )

    test_targets = sorted(by_import[item]["target"] for item in affected_imports if item in by_import)
    mutation_targets = sorted(by_import[item]["target"] for item in direct_prod_packages if item in by_import)
    canary_targets = sorted(
        by_import[item]["target"]
        for item in direct_test_packages
        if item in by_import and is_critical_package(by_import[item]["target"])
    )

    reasons = list(base_reasons)
    full_reasons: list[str] = []
    if force_full:
        full_reasons.append("调用方显式要求全量检查")
    if any(path in {"go.mod", "go.sum"} for path in files):
        full_reasons.append("Go 依赖图发生变化")
    constrained_files = [path for path in changed_prod_go if has_build_constraint(root, path)]
    if constrained_files:
        full_reasons.append("平台或构建标签代码发生变化")
    if any(path in SHARED_CONTRACT_FILES for path in files):
        full_reasons.append("共享接口或核心配置契约发生变化")
    if len(direct_prod_packages) >= 4 or len(affected_imports) >= 10:
        full_reasons.append("变更影响面超过定向检查阈值")

    mutation_mode = "changed-lines" if mutation_targets else "none"
    if mutation_targets:
        reasons.append("生产代码发生变化，仅检查 changed-line 变异")
    if canary_targets:
        reasons.append("关键包测试发生变化，运行稳定变异哨兵")

    if full_reasons:
        test_targets = [package["target"] for package in packages]

    build_all = bool(
        full_reasons
        or any(path in {"go.mod", "go.sum"} for path in files)
        or constrained_files
        or any(path.startswith("cmd/") and path.endswith(".go") for path in files)
    )

    shell_files = sorted(path for path in files if path.endswith(".sh") and (root / path).is_file())
    return {
        "schema_version": 1,
        "root": str(root),
        "base": selected_base,
        "changed_files": files,
        "go": {
            "changed": bool(changed_go or any(path in {"go.mod", "go.sum"} for path in files)),
            "test_packages": test_targets,
            "lint_packages": test_targets,
            "build_all": build_all,
        },
        "contracts": {
            "shell_files": shell_files,
            "mutation": any(path in MUTATION_INFRA_FILES for path in files),
            "agent_config": any(
                path in {"AGENTS.md", "CLAUDE.md", "Makefile", "build/check-agent-config.sh"}
                or path.startswith("skills/")
                or path.startswith(".agents/skills/")
                or path.startswith(".github/workflows/")
                for path in files
            ),
            "release": any(
                path == "deploy-spec.md"
                or path == "build/test-release.sh"
                or path == "build/build.sh"
                or path.startswith("build/release")
                for path in files
            ),
            "docker_e2e": any(
                path.endswith(".go") and not path.endswith("_test.go")
                and any(path.startswith(prefix) for prefix in DEPLOY_E2E_PREFIXES)
                for path in files
            ),
        },
        "mutation": {
            "mode": mutation_mode,
            "packages": mutation_targets,
            "canary_packages": canary_targets,
        },
        "reasons": reasons + full_reasons,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--base", help="Git 对比基线；默认按 upstream、工作区和 HEAD^ 推导")
    parser.add_argument("--full", action="store_true", help="强制生成全量计划")
    args = parser.parse_args()

    root = args.root.resolve()
    try:
        plan = build_plan(root, args.base, args.full)
    except RuntimeError as error:
        print(f"生成检查计划失败: {error}", file=sys.stderr)
        return 1
    json.dump(plan, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
