"""按国家拆分 VPNGate Clash 订阅，保留完整配置及有效的节点组引用。"""

from __future__ import annotations

import argparse
import sys
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

import yaml

SOURCE_URL = "https://raw.githubusercontent.com/sdise/vpngate/main/vpngate-clash.yaml"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOWNLOAD_TIMEOUT_SECONDS = 30
PART_NAMES = ("JP1", "JP2", "KR", "US", "OTHER")
COUNTRY_BUCKETS = {
    "japan": "JP",
    "korea republic of": "KR",
    "united states": "US",
}
BUILTIN_NAMES = frozenset({"DIRECT", "REJECT", "REJECT-DROP", "PASS"})
QUALITY_FIELD_PREFIX = "纯净度:"
Config = dict[str, Any]


def named_entries(value: object, label: str) -> dict[str, Config]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} 必须是非空列表")
    entries = {}
    for entry in value:
        if not isinstance(entry, dict):
            raise TypeError(f"{label} 中的每一项必须是映射")
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"{label} 中存在缺失或无效的 name")
        if name in entries:
            raise ValueError(f"{label} 中存在重复名称：{name}")
        entries[name] = entry
    return entries


def validate_groups(groups: dict[str, Config], proxy_names: set[str]) -> None:
    available = proxy_names | set(groups) | BUILTIN_NAMES
    for name, group in groups.items():
        if group.get("use"):
            raise ValueError(f"{name} 引用了额外 provider，请先检查上游格式变化")
        members = group.get("proxies")
        if not isinstance(members, list) or not members:
            raise ValueError(f"{name} 必须包含非空 proxies 列表")
        if not all(isinstance(member, str) for member in members):
            raise ValueError(f"{name} 的节点引用必须是字符串")
        unknown = set(members) - available
        if unknown:
            raise ValueError(f"{name} 引用了不存在的节点或分组：{sorted(unknown)}")


def validate_source(source: object) -> Config:
    if not isinstance(source, dict):
        raise TypeError("上游必须是完整 Clash 配置映射")
    if source.get("proxy-providers"):
        raise ValueError("上游新增了 proxy-providers，请检查后再发布")
    proxies = named_entries(source.get("proxies"), "proxies")
    groups = named_entries(source.get("proxy-groups"), "proxy-groups")
    if set(proxies) & (set(groups) | BUILTIN_NAMES) or set(groups) & BUILTIN_NAMES:
        raise ValueError("节点、分组或内置策略之间存在名称冲突")
    rules = source.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("上游缺少非空 rules 列表")
    if not all(isinstance(rule, str) and rule.strip() for rule in rules):
        raise ValueError("rules 中的每一项必须是非空字符串")
    validate_groups(groups, set(proxies))
    return source


def country_field(name: str) -> str:
    fields = [field.strip() for field in name.split("|")]
    match fields:
        case [_, quality, country, *_] if quality.startswith(QUALITY_FIELD_PREFIX):
            # 家宽/机房 | 纯净度:评分 | 国家 | 延迟 | 落地地址
            return country
        case [country, _]:
            # 国家 | 延迟
            return country
        case [_, country, _, *_]:
            # vpngate | 国家 | 节点标识；保留旧格式兼容。
            return country
        case _:
            return ""


def country_bucket(name: str) -> str:
    return COUNTRY_BUCKETS.get(country_field(name).casefold(), "OTHER")


def partition_proxies(proxies: list[Config]) -> dict[str, list[Config]]:
    buckets = {name: [] for name in ("JP", "KR", "US", "OTHER")}
    for proxy in proxies:
        buckets[country_bucket(proxy["name"])].append(proxy)
    japanese = buckets.pop("JP")
    midpoint = (len(japanese) + 1) // 2
    return {"JP1": japanese[:midpoint], "JP2": japanese[midpoint:], **buckets}


def make_part(source: Config, selected: list[Config], part: str) -> Config:
    if not selected:
        raise ValueError(f"{part} 没有节点，停止发布并保留已有订阅")
    result = deepcopy(source)
    result["proxies"] = deepcopy(selected)
    removed = {node["name"] for node in source["proxies"]} - {
        node["name"] for node in selected
    }
    for group in result["proxy-groups"]:
        group["proxies"] = [name for name in group["proxies"] if name not in removed]
        if not group["proxies"]:
            raise ValueError(f"{part} 的分组 {group['name']} 为空，停止发布")
        if group.get("default-selected") not in group["proxies"]:
            group.pop("default-selected", None)
    return result


def split_config(source: object) -> dict[str, Config]:
    validated = validate_source(source)
    partitions = partition_proxies(validated["proxies"])
    return {
        part: make_part(validated, partitions[part], part)
        for part in PART_NAMES
    }


def render_documents(configurations: dict[str, Config]) -> dict[str, str]:
    documents = {}
    for part in PART_NAMES:
        config = configurations[part]
        header = (
            "# 自动生成，请通过拆分脚本更新。\n"
            f"# 分组：{part}；节点数：{len(config['proxies'])}\n"
        )
        body = yaml.safe_dump(
            config, allow_unicode=True, sort_keys=False, default_flow_style=False
        )
        documents[f"{part}.yaml"] = header + body
    return documents


def write_configurations(configurations: dict[str, Config], output_dir: Path) -> None:
    # 先生成全部内容，再逐文件原子替换；CI 仅在全部检查通过后提交。
    documents = render_documents(configurations)
    output_dir.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".vpngate-split-", dir=output_dir) as temporary:
        staged = Path(temporary)
        for filename, content in documents.items():
            (staged / filename).write_text(content, encoding="utf-8")
        for filename in documents:
            (staged / filename).replace(output_dir / filename)


def fetch_source() -> str:
    request = Request(SOURCE_URL, headers={"User-Agent": "vpngate-split"})
    with urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
        return response.read().decode("utf-8-sig")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="使用已下载的上游 YAML 快照")
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT)
    args = parser.parse_args(argv)
    try:
        content = args.input.read_text(encoding="utf-8-sig") if args.input else fetch_source()
        configurations = split_config(yaml.safe_load(content))
        write_configurations(configurations, args.output_dir)
    except (OSError, URLError, TypeError, ValueError, yaml.YAMLError) as error:
        print(f"订阅生成失败：{error}", file=sys.stderr)
        return 1
    for part in PART_NAMES:
        print(f"{part}.yaml: {len(configurations[part]['proxies'])} nodes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
