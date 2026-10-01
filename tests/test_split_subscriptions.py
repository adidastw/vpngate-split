"""覆盖分类边界、引用完整性和失败时保留已有输出。"""

import io
import unittest
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.error import URLError

import yaml

from scripts import split_subscriptions as splitter


def node(country: str, identifier: str) -> dict:
    return {
        "name": f"vpngate | {country} | {identifier}",
        "type": "http", "server": "127.0.0.1", "port": 8080,
    }


def fixture(japan_count: int = 5) -> dict:
    proxies = [node("Japan", f"jp-{index}") for index in range(japan_count)]
    proxies += [node("Korea Republic of", "kr"), node("United States", "us")]
    proxies += [node("Thailand", "th"), {**node("unknown", "other"), "name": "未标注节点"}]
    return {
        "mixed-port": 7890,
        "dns": {"enable": True, "nameserver": ["1.1.1.1"]},
        "proxies": proxies,
        "proxy-groups": [{"name": "选择", "type": "select", "proxies": [p["name"] for p in proxies]}],
        "rules": ["MATCH,选择"],
    }


class PartitionTests(unittest.TestCase):
    def test_japan_even_odd_and_small_counts(self):
        for count in range(8):
            with self.subTest(count=count):
                groups = splitter.partition_proxies(fixture(count)["proxies"])
                self.assertEqual(len(groups["JP1"]), (count + 1) // 2)
                self.assertEqual(len(groups["JP2"]), count // 2)

    def test_country_is_a_complete_field_not_a_substring(self):
        cases = {
            "vpngate | Japan | jp": "JP",
            "vpngate|  jApAn  | jp": "JP",
            "vpngate | Korea Republic of | kr": "KR",
            "vpngate | United States | us": "US",
            "vpngate | Not Japan | jp": "OTHER",
            "vpngate | Canada | Japan-US": "OTHER",
            "Japan": "OTHER", "vpngate | Japan": "OTHER",
            "vpngate | | unnamed": "OTHER",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(splitter.country_bucket(name), expected)

    def test_every_node_appears_exactly_once_in_order(self):
        source = fixture()
        parts = splitter.split_config(source)
        names = [p["name"] for config in parts.values() for p in config["proxies"]]
        self.assertEqual(Counter(names), Counter(p["name"] for p in source["proxies"]))
        self.assertEqual(list(parts), list(splitter.PART_NAMES))
        self.assertEqual(parts["JP1"]["proxies"], source["proxies"][:3])
        self.assertEqual(parts["JP2"]["proxies"], source["proxies"][3:5])
        self.assertEqual(len(parts["KR"]["proxies"]), 1)
        self.assertEqual(len(parts["US"]["proxies"]), 1)
        self.assertEqual(len(parts["OTHER"]["proxies"]), 2)

    def test_groups_only_reference_their_own_nodes(self):
        for part, config in splitter.split_config(fixture()).items():
            with self.subTest(part=part):
                self.assertEqual(config["proxy-groups"][0]["proxies"], [p["name"] for p in config["proxies"]])
                self.assertEqual(config["rules"], ["MATCH,选择"])

    def test_nested_groups_and_builtin_policies_are_preserved(self):
        source = fixture()
        source["proxy-groups"][0]["proxies"].append("DIRECT")
        source["proxy-groups"].append({"name": "入口", "type": "select", "proxies": ["选择", "REJECT"]})
        for config in splitter.split_config(source).values():
            self.assertIn("DIRECT", config["proxy-groups"][0]["proxies"])
            self.assertEqual(config["proxy-groups"][1], source["proxy-groups"][1])

    def test_source_and_outputs_have_independent_nested_data(self):
        source = fixture()
        source["proxies"][0]["ws-opts"] = {"headers": {"Host": "example.com"}}
        original = deepcopy(source)
        parts = splitter.split_config(source)
        self.assertEqual(source, original)
        parts["JP1"]["proxies"][0]["ws-opts"]["headers"]["Host"] = "changed"
        parts["JP1"]["dns"]["nameserver"].append("8.8.8.8")
        self.assertEqual(source, original)
        self.assertEqual(parts["JP2"]["dns"], original["dns"])
        self.assertEqual(parts["JP1"]["mixed-port"], 7890)

    def test_removed_default_selection_is_cleared(self):
        source = fixture()
        selected = source["proxies"][0]["name"]
        source["proxy-groups"][0]["default-selected"] = selected
        parts = splitter.split_config(source)
        self.assertEqual(parts["JP1"]["proxy-groups"][0]["default-selected"], selected)
        self.assertNotIn("default-selected", parts["KR"]["proxy-groups"][0])


class ValidationTests(unittest.TestCase):
    def test_invalid_root_and_named_entries(self):
        for value in (None, [], "html error", 42):
            with self.subTest(value=value), self.assertRaises(TypeError):
                splitter.split_config(value)
        with self.assertRaises(TypeError):
            splitter.named_entries([None], "test")
        for value in (None, [], {}, [{}], [{"name": " "}], [{"name": 7}]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                splitter.named_entries(value, "test")

    def test_duplicate_proxy_and_group_names_are_rejected(self):
        for key in ("proxies", "proxy-groups"):
            source = fixture()
            source[key].append(deepcopy(source[key][0]))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "重复名称"):
                splitter.split_config(source)

    def test_proxy_group_and_builtin_name_collisions_are_rejected(self):
        for name in ("选择", "DIRECT"):
            source = fixture()
            source["proxies"][0]["name"] = name
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "名称冲突"):
                splitter.split_config(source)

    def test_invalid_rules_are_rejected(self):
        for rules in (None, [], "MATCH,选择", [None], [""]):
            source = fixture()
            source["rules"] = rules
            with self.subTest(rules=rules), self.assertRaises(ValueError):
                splitter.split_config(source)

    def test_invalid_or_dangling_group_references_are_rejected(self):
        for members in (None, [], "选择", [None], ["missing-node"]):
            source = fixture()
            source["proxy-groups"][0]["proxies"] = members
            with self.subTest(members=members), self.assertRaises(ValueError):
                splitter.split_config(source)

    def test_external_providers_are_rejected(self):
        source = fixture()
        source["proxy-providers"] = {"remote": {"type": "http"}}
        with self.assertRaisesRegex(ValueError, "proxy-providers"):
            splitter.split_config(source)
        source = fixture()
        source["proxy-groups"][0]["use"] = ["remote"]
        with self.assertRaisesRegex(ValueError, "provider"):
            splitter.split_config(source)

    def test_empty_partitions_stop_publication(self):
        for japan_count in (0, 1):
            with self.subTest(count=japan_count), self.assertRaisesRegex(ValueError, "没有节点"):
                splitter.split_config(fixture(japan_count))

    def test_group_that_becomes_empty_stops_publication(self):
        source = fixture()
        source["proxy-groups"].append({"name": "仅日本", "type": "select", "proxies": [source["proxies"][0]["name"]]})
        with self.assertRaisesRegex(ValueError, "分组.*为空"):
            splitter.split_config(source)


class PublicationTests(unittest.TestCase):
    def test_rendering_is_deterministic_unicode_yaml(self):
        parts = splitter.split_config(fixture())
        first = splitter.render_documents(parts)
        self.assertEqual(first, splitter.render_documents(parts))
        self.assertEqual(set(first), {f"{part}.yaml" for part in splitter.PART_NAMES})
        for part in splitter.PART_NAMES:
            self.assertIn("选择", first[f"{part}.yaml"])
            self.assertEqual(yaml.safe_load(first[f"{part}.yaml"]), parts[part])

    def test_cli_generates_all_five_files_from_a_snapshot(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "source.yaml"
            snapshot.write_text(yaml.safe_dump(fixture()), encoding="utf-8")
            output = root / "output"
            with redirect_stdout(io.StringIO()):
                status = splitter.main(["--input", str(snapshot), "--output-dir", str(output)])
            self.assertEqual(status, 0)
            self.assertEqual({p.name for p in output.iterdir()}, {f"{part}.yaml" for part in splitter.PART_NAMES})
            self.assertEqual(len(yaml.safe_load((output / "JP1.yaml").read_text())["proxies"]), 3)

    def test_download_failure_preserves_previous_files(self):
        with TemporaryDirectory() as temporary:
            output = Path(temporary)
            old = output / "JP1.yaml"
            old.write_text("previous", encoding="utf-8")
            with patch.object(splitter, "fetch_source", side_effect=URLError("offline")), redirect_stderr(io.StringIO()):
                status = splitter.main(["--output-dir", str(output)])
            self.assertEqual(status, 1)
            self.assertEqual(old.read_text(), "previous")

    def test_bad_yaml_empty_partition_and_unsafe_tags_preserve_files(self):
        invalid_inputs = [
            "proxies: [", "!!python/object:builtins.dict {}",
            yaml.safe_dump(fixture(1)), "html error", "42",
        ]
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "source.yaml"
            previous = root / "JP1.yaml"
            previous.write_text("previous", encoding="utf-8")
            for content in invalid_inputs:
                snapshot.write_text(content, encoding="utf-8")
                with self.subTest(content=content), redirect_stderr(io.StringIO()):
                    self.assertEqual(splitter.main(["--input", str(snapshot), "--output-dir", str(root)]), 1)
                self.assertEqual(previous.read_text(), "previous")

    def test_network_download_uses_a_timeout_and_handles_utf8_bom(self):
        with patch.object(splitter, "urlopen") as opening:
            opening.return_value.__enter__.return_value.read.return_value = b"\xef\xbb\xbfproxies: []"
            self.assertEqual(splitter.fetch_source(), "proxies: []")
            self.assertEqual(opening.call_args.kwargs["timeout"], splitter.DOWNLOAD_TIMEOUT_SECONDS)

    def test_workflow_tests_and_validates_before_committing(self):
        path = Path(__file__).resolve().parents[1] / ".github/workflows/split.yml"
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.assertIn("workflow_dispatch", workflow["on"])
        self.assertEqual(workflow["permissions"], {"contents": "write"})
        self.assertFalse(workflow["concurrency"]["cancel-in-progress"])
        steps = workflow["jobs"]["update"]["steps"]
        ids = [step.get("id") for step in steps]
        self.assertLess(ids.index("tests"), ids.index("generate"))
        self.assertLess(ids.index("generate"), ids.index("validate"))
        self.assertLess(ids.index("validate"), ids.index("publish"))
        for step in steps:
            if "uses" in step:
                self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")
        self.assertIn("sha256sum --check", next(step["run"] for step in steps if step.get("id") == "validate"))


if __name__ == "__main__":
    unittest.main()
