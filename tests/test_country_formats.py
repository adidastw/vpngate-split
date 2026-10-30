"""回归覆盖 2026-10 上游改名，以及新旧名称混合时的完整拆分。"""

import unittest
from collections import Counter
from copy import deepcopy

from scripts import split_subscriptions as splitter


def current_configuration(names: list[str]) -> dict:
    proxies = [
        {"name": name, "type": "http", "server": "127.0.0.1", "port": 8080}
        for name in names
    ]
    return {
        "dns": {"enable": True, "nameserver": ["1.1.1.1"]},
        "proxies": proxies,
        "proxy-groups": [
            {"name": "手动", "type": "select", "proxies": [*names, "DIRECT"]},
            {
                "name": "自动", "type": "url-test", "proxies": names.copy(),
                "url": "http://www.gstatic.com/generate_204", "interval": 300,
            },
        ],
        "rules": ["GEOIP,CN,DIRECT", "MATCH,手动"],
    }


class CurrentNameFormatTests(unittest.TestCase):
    def test_home_and_datacenter_quality_names(self):
        cases = {
            "家宽|纯净度:8|Japan|707.58|落地:192.0.2.1": "JP",
            "家宽|纯净度:7|Korea Republic of|8.71|落地:192.0.2.2": "KR",
            "家宽|纯净度:1|United States|81.92|落地:192.0.2.3": "US",
            "机房|纯净度:5|Japan|89.69|落地:192.0.2.4": "JP",
            "机房|纯净度:9|Korea Republic of|15.22|落地:192.0.2.5": "KR",
            "机房|纯净度:2|United States|28.33|落地:192.0.2.6": "US",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(splitter.country_bucket(name), expected)

    def test_short_country_latency_names(self):
        cases = {
            "Japan|216.17": "JP",
            "Korea Republic of|8.71": "KR",
            "United States|56.23": "US",
            "Russian Federation|318.23": "OTHER",
            "Viet Nam|159.66": "OTHER",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(splitter.country_bucket(name), expected)

    def test_new_names_allow_whitespace_and_country_case(self):
        cases = {
            " 家宽 | 纯净度:8 | jApAn | 707.58 | 落地:192.0.2.1 ": "JP",
            " 机房 | 纯净度:5 | KOREA REPUBLIC OF | 15.22 ": "KR",
            " UNITED STATES | 56.23 ": "US",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(splitter.country_bucket(name), expected)

    def test_metadata_never_overrides_the_actual_country(self):
        cases = (
            "家宽|纯净度:7|Mexico|81.92|落地:192.0.2.1",
            "家宽|纯净度:0|Canada|Japan|落地:192.0.2.2",
            "机房|纯净度:5|United Kingdom|United States|落地:192.0.2.3",
            "vpngate | Canada | Japan-US",
            "Not Japan|216.17", "Japan VPN|216.17", "|216.17",
            "Japan", "vpngate | Japan", "vpngate | | node",
        )
        for name in cases:
            with self.subTest(name=name):
                self.assertEqual(splitter.country_bucket(name), "OTHER")

    def test_old_format_remains_supported(self):
        cases = {
            "vpngate | Japan | vpn-old": "JP",
            "vpngate | Korea Republic of | vpn-old": "KR",
            "vpngate | United States | vpn-old": "US",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(splitter.country_bucket(name), expected)

    def test_latest_names_generate_all_five_parts(self):
        names = [
            "家宽|纯净度:8|Japan|707.58|落地:192.0.2.1",
            "机房|纯净度:5|Japan|89.69|落地:192.0.2.2",
            "Japan|216.17", "Korea Republic of|8.71",
            "家宽|纯净度:1|United States|81.92|落地:192.0.2.3",
            "家宽|纯净度:7|Mexico|81.92|落地:192.0.2.4",
        ]
        parts = splitter.split_config(current_configuration(names))
        self.assertEqual(
            {part: len(config["proxies"]) for part, config in parts.items()},
            {"JP1": 2, "JP2": 1, "KR": 1, "US": 1, "OTHER": 1},
        )

    def test_mixed_formats_preserve_nodes_groups_dns_and_rules(self):
        names = [
            "vpngate | Japan | old-jp", "Japan|216.17",
            "家宽|纯净度:8|Japan|707.58|落地:192.0.2.1",
            "vpngate | Korea Republic of | old-kr", "Korea Republic of|8.71",
            "机房|纯净度:2|United States|28.33|落地:192.0.2.2",
            "vpngate | United States | old-us", "United States|56.23",
            "家宽|纯净度:7|Mexico|81.92|落地:192.0.2.3", "未知节点",
        ]
        source = current_configuration(names)
        original = deepcopy(source)
        parts = splitter.split_config(source)
        published = [p["name"] for config in parts.values() for p in config["proxies"]]
        self.assertEqual(Counter(published), Counter(names))
        self.assertEqual(source, original)
        for config in parts.values():
            selected = [p["name"] for p in config["proxies"]]
            self.assertEqual(config["proxy-groups"][0]["proxies"], [*selected, "DIRECT"])
            self.assertEqual(config["proxy-groups"][1]["proxies"], selected)
            self.assertEqual(config["dns"], original["dns"])
            self.assertEqual(config["rules"], original["rules"])
            for proxy in config["proxies"]:
                self.assertEqual(proxy, next(p for p in original["proxies"] if p["name"] == proxy["name"]))


if __name__ == "__main__":
    unittest.main()
