import importlib.util
import json
import os
import subprocess
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARSER_DIR = os.path.join(_HERE, "..", "parsers", "shcheck")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(_PARSER_DIR, filename)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


headers = _load("shcheck_headers", "headers.py")
shcheck = _load("shcheck_parser", "shcheck.py")


def codes(findings):
    return sorted(f.code for f in findings)


class TestParseCsp(unittest.TestCase):
    def test_splits_directives_and_sources(self):
        self.assertEqual(
            headers.parse_csp("default-src 'self'; script-src 'self' cdn.example.com"),
            {
                "default-src": ["'self'"],
                "script-src": ["'self'", "cdn.example.com"],
            },
        )

    def test_directive_names_are_lowercased(self):
        self.assertEqual(
            headers.parse_csp("DEFAULT-SRC 'none'"), {"default-src": ["'none'"]}
        )

    def test_source_case_is_preserved(self):
        self.assertEqual(
            headers.parse_csp("img-src CDN.Example.COM/Path"),
            {"img-src": ["CDN.Example.COM/Path"]},
        )

    def test_duplicate_directive_ignored_per_spec(self):
        self.assertEqual(
            headers.parse_csp("script-src 'self'; script-src *"),
            {"script-src": ["'self'"]},
        )

    def test_empty_segments_and_trailing_semicolon(self):
        self.assertEqual(
            headers.parse_csp("default-src 'self';;"), {"default-src": ["'self'"]}
        )

    def test_valueless_directive(self):
        self.assertEqual(
            headers.parse_csp("upgrade-insecure-requests"),
            {"upgrade-insecure-requests": []},
        )


class TestCspRules(unittest.TestCase):
    # A policy with nothing wrong with it, used as the baseline for each rule.
    CLEAN = (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )

    def test_clean_policy_has_no_findings(self):
        self.assertEqual(headers.analyze("Content-Security-Policy", self.CLEAN), [])

    def test_unsafe_inline_in_script_src(self):
        value = self.CLEAN.replace("script-src 'self'", "script-src 'unsafe-inline'")
        self.assertIn(
            "csp-unsafe-inline",
            codes(headers.analyze("Content-Security-Policy", value)),
        )

    def test_unsafe_inline_in_style_src(self):
        value = self.CLEAN.replace("style-src 'self'", "style-src 'unsafe-inline'")
        self.assertIn(
            "csp-unsafe-inline",
            codes(headers.analyze("Content-Security-Policy", value)),
        )

    def test_unsafe_inline_reported_once_for_both_directives(self):
        value = self.CLEAN.replace("script-src 'self'", "script-src 'unsafe-inline'")
        value = value.replace("style-src 'self'", "style-src 'unsafe-inline'")
        found = [
            f
            for f in headers.analyze("Content-Security-Policy", value)
            if f.code == "csp-unsafe-inline"
        ]
        self.assertEqual(len(found), 1)
        self.assertIn("script-src", found[0].message)
        self.assertIn("style-src", found[0].message)

    def test_unsafe_inline_inherited_through_default_src(self):
        # script-src absent, so it falls back to default-src.
        value = "default-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        self.assertIn(
            "csp-unsafe-inline",
            codes(headers.analyze("Content-Security-Policy", value)),
        )

    def test_unsafe_inline_not_inherited_when_script_src_overrides(self):
        value = (
            "default-src 'unsafe-inline'; script-src 'self'; style-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
        self.assertNotIn(
            "csp-unsafe-inline",
            codes(headers.analyze("Content-Security-Policy", value)),
        )

    def test_unsafe_eval(self):
        value = self.CLEAN.replace("script-src 'self'", "script-src 'unsafe-eval'")
        self.assertIn(
            "csp-unsafe-eval", codes(headers.analyze("Content-Security-Policy", value))
        )

    def test_keyword_source_matching_is_case_insensitive(self):
        value = self.CLEAN.replace("script-src 'self'", "script-src 'UNSAFE-EVAL'")
        self.assertIn(
            "csp-unsafe-eval", codes(headers.analyze("Content-Security-Policy", value))
        )

    def test_wildcard_source(self):
        value = self.CLEAN.replace("script-src 'self'", "script-src *")
        self.assertIn(
            "csp-wildcard", codes(headers.analyze("Content-Security-Policy", value))
        )

    def test_wildcard_subdomain_is_not_a_bare_wildcard(self):
        value = self.CLEAN.replace("script-src 'self'", "script-src *.example.com")
        self.assertNotIn(
            "csp-wildcard", codes(headers.analyze("Content-Security-Policy", value))
        )

    def test_no_default_src_and_no_script_src(self):
        value = "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        self.assertIn(
            "csp-no-default-src",
            codes(headers.analyze("Content-Security-Policy", value)),
        )

    def test_no_frame_ancestors(self):
        value = "default-src 'none'; object-src 'none'; base-uri 'none'"
        self.assertIn(
            "csp-no-frame-ancestors",
            codes(headers.analyze("Content-Security-Policy", value)),
        )

    def test_no_object_src_without_default_src(self):
        value = "script-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        self.assertIn(
            "csp-no-object-src",
            codes(headers.analyze("Content-Security-Policy", value)),
        )

    def test_object_src_covered_by_default_src(self):
        value = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        self.assertNotIn(
            "csp-no-object-src",
            codes(headers.analyze("Content-Security-Policy", value)),
        )

    def test_no_base_uri(self):
        value = "default-src 'none'; object-src 'none'; frame-ancestors 'none'"
        self.assertIn(
            "csp-no-base-uri", codes(headers.analyze("Content-Security-Policy", value))
        )

    def test_header_name_matching_is_case_insensitive(self):
        self.assertEqual(headers.analyze("CONTENT-SECURITY-POLICY", self.CLEAN), [])

    def test_unknown_header_returns_nothing(self):
        self.assertEqual(headers.analyze("X-Whatever", "value"), [])

    def test_none_value_returns_nothing(self):
        self.assertEqual(headers.analyze("Content-Security-Policy", None), [])

    def test_finding_header_field_is_the_canonical_name(self):
        value = self.CLEAN.replace("script-src 'self'", "script-src 'unsafe-eval'")
        found = headers.analyze("content-security-policy", value)
        self.assertEqual(found[0].header, "Content-Security-Policy")


class TestHstsRules(unittest.TestCase):
    def test_clean_hsts(self):
        value = "max-age=31536000; includeSubDomains"
        self.assertEqual(headers.analyze("Strict-Transport-Security", value), [])

    def test_max_age_zero(self):
        found = codes(
            headers.analyze("Strict-Transport-Security", "max-age=0; includeSubDomains")
        )
        self.assertIn("hsts-max-age-zero", found)
        self.assertNotIn("hsts-max-age-short", found)

    def test_short_max_age(self):
        found = codes(
            headers.analyze(
                "Strict-Transport-Security", "max-age=3600; includeSubDomains"
            )
        )
        self.assertIn("hsts-max-age-short", found)
        self.assertNotIn("hsts-max-age-zero", found)

    def test_six_months_exactly_is_acceptable(self):
        value = "max-age=15768000; includeSubDomains"
        self.assertEqual(headers.analyze("Strict-Transport-Security", value), [])

    def test_missing_include_subdomains(self):
        found = codes(headers.analyze("Strict-Transport-Security", "max-age=31536000"))
        self.assertEqual(found, ["hsts-no-include-subdomains"])

    def test_include_subdomains_is_case_insensitive(self):
        value = "max-age=31536000; INCLUDESUBDOMAINS"
        self.assertEqual(headers.analyze("Strict-Transport-Security", value), [])

    def test_no_max_age_at_all(self):
        self.assertEqual(
            codes(headers.analyze("Strict-Transport-Security", "includeSubDomains")),
            ["hsts-malformed"],
        )

    def test_non_numeric_max_age(self):
        self.assertEqual(
            codes(headers.analyze("Strict-Transport-Security", "max-age=forever")),
            ["hsts-malformed"],
        )

    def test_quoted_max_age(self):
        value = 'max-age="31536000"; includeSubDomains'
        self.assertEqual(headers.analyze("Strict-Transport-Security", value), [])


class TestSimpleHeaderRules(unittest.TestCase):
    def test_xfo_deny_is_clean(self):
        self.assertEqual(headers.analyze("X-Frame-Options", "DENY"), [])

    def test_xfo_sameorigin_is_clean_and_case_insensitive(self):
        self.assertEqual(headers.analyze("X-Frame-Options", "sameorigin"), [])

    def test_xfo_allow_from(self):
        found = codes(
            headers.analyze("X-Frame-Options", "ALLOW-FROM https://example.com")
        )
        self.assertEqual(found, ["xfo-allow-from"])

    def test_xfo_garbage(self):
        self.assertEqual(
            codes(headers.analyze("X-Frame-Options", "yes please")), ["xfo-invalid"]
        )

    def test_xcto_nosniff_is_clean(self):
        self.assertEqual(headers.analyze("X-Content-Type-Options", "nosniff"), [])

    def test_xcto_other_value(self):
        self.assertEqual(
            codes(headers.analyze("X-Content-Type-Options", "sniff")), ["xcto-invalid"]
        )

    def test_referrer_policy_clean(self):
        self.assertEqual(
            headers.analyze("Referrer-Policy", "strict-origin-when-cross-origin"), []
        )

    def test_referrer_policy_unsafe_url(self):
        self.assertEqual(
            codes(headers.analyze("Referrer-Policy", "unsafe-url")),
            ["referrer-unsafe-url"],
        )

    def test_referrer_policy_unsafe_url_in_a_token_list(self):
        value = "no-referrer, unsafe-url"
        self.assertIn(
            "referrer-unsafe-url", codes(headers.analyze("Referrer-Policy", value))
        )

    def test_referrer_policy_unrecognised(self):
        self.assertEqual(
            codes(headers.analyze("Referrer-Policy", "whatever")), ["referrer-invalid"]
        )

    def test_coop_same_origin_is_clean(self):
        self.assertEqual(
            headers.analyze("Cross-Origin-Opener-Policy", "same-origin"), []
        )

    def test_coop_unsafe_none(self):
        self.assertEqual(
            codes(headers.analyze("Cross-Origin-Opener-Policy", "unsafe-none")),
            ["coop-unsafe-none"],
        )

    def test_coop_invalid_value_is_treated_as_unsafe_none(self):
        # Browsers fall back to unsafe-none for unrecognised values, so this is
        # the same defect, not a separate one.
        self.assertEqual(
            codes(headers.analyze("Cross-Origin-Opener-Policy", "bogus")),
            ["coop-unsafe-none"],
        )

    def test_coep_valid_values(self):
        for value in ("unsafe-none", "require-corp", "credentialless"):
            self.assertEqual(
                headers.analyze("Cross-Origin-Embedder-Policy", value), [], value
            )

    def test_coep_invalid(self):
        self.assertEqual(
            codes(headers.analyze("Cross-Origin-Embedder-Policy", "nope")),
            ["coep-invalid"],
        )

    def test_corp_valid_values(self):
        for value in ("same-site", "same-origin", "cross-origin"):
            self.assertEqual(
                headers.analyze("Cross-Origin-Resource-Policy", value), [], value
            )

    def test_corp_invalid(self):
        self.assertEqual(
            codes(headers.analyze("Cross-Origin-Resource-Policy", "nope")),
            ["corp-invalid"],
        )

    def test_permissions_policy_is_presence_only(self):
        self.assertEqual(headers.analyze("Permissions-Policy", "geolocation=*"), [])


class TestAnalyzeAll(unittest.TestCase):
    NO_ANCESTORS = "default-src 'none'; object-src 'none'; base-uri 'none'"

    def test_runs_every_header(self):
        found = codes(
            headers.analyze_all(
                {
                    "Content-Security-Policy": TestCspRules.CLEAN,
                    "X-Content-Type-Options": "sniff",
                    "Strict-Transport-Security": "max-age=1",
                }
            )
        )
        self.assertEqual(
            found, ["hsts-max-age-short", "hsts-no-include-subdomains", "xcto-invalid"]
        )

    def test_frame_ancestors_suppressed_by_valid_xfo(self):
        found = codes(
            headers.analyze_all(
                {
                    "Content-Security-Policy": self.NO_ANCESTORS,
                    "X-Frame-Options": "DENY",
                }
            )
        )
        self.assertNotIn("csp-no-frame-ancestors", found)

    def test_frame_ancestors_reported_when_xfo_absent(self):
        found = codes(
            headers.analyze_all({"Content-Security-Policy": self.NO_ANCESTORS})
        )
        self.assertIn("csp-no-frame-ancestors", found)

    def test_frame_ancestors_reported_when_xfo_is_invalid(self):
        # A broken X-Frame-Options protects nothing, so it cannot excuse the
        # missing frame-ancestors directive.
        found = codes(
            headers.analyze_all(
                {
                    "Content-Security-Policy": self.NO_ANCESTORS,
                    "X-Frame-Options": "ALLOW-FROM https://x.example",
                }
            )
        )
        self.assertIn("csp-no-frame-ancestors", found)

    def test_empty_input(self):
        self.assertEqual(headers.analyze_all({}), [])

    def test_none_header_value_does_not_crash(self):
        # analyze() tolerates a None value, so analyze_all must too -- the
        # suppression path reaches _analyze_xfo without going through analyze().
        found = codes(
            headers.analyze_all(
                {"Content-Security-Policy": self.NO_ANCESTORS, "X-Frame-Options": None}
            )
        )
        self.assertIn("csp-no-frame-ancestors", found)


class TestNormalizeJson(unittest.TestCase):
    FORK = {
        "https://example.com/app": {
            "present": {"X-Frame-Options": "DENY"},
            "missing": ["Content-Security-Policy"],
            "unsafe": {"Strict-Transport-Security": "max-age=0"},
            "deprecated": {"X-XSS-Protection": "1; mode=block"},
            "information_disclosure": {"Server": "nginx/1.10.3"},
            "caching": {"ETag": "abc"},
        }
    }
    ORIGINAL = {
        "https://example.com/app": {
            "present": {"X-Frame-Options": "DENY", "X-XSS-Protection": "1; mode=block"},
            "missing": [
                "Content-Security-Policy",
                "Expect-CT",
                "X-Permitted-Cross-Domain-Policies",
            ],
            "information_disclosure": {"Server": "nginx/1.10.3"},
        }
    }

    def test_fork_record(self):
        [record] = shcheck.normalize_json(self.FORK, [])
        self.assertEqual(record["url"], "https://example.com/app")
        self.assertEqual(record["present"], {"X-Frame-Options": "DENY"})
        self.assertEqual(record["missing"], ["Content-Security-Policy"])
        self.assertEqual(record["unsafe"], {"Strict-Transport-Security": "max-age=0"})
        self.assertEqual(record["deprecated"], {"X-XSS-Protection": "1; mode=block"})
        self.assertEqual(record["info_disclosure"], {"Server": "nginx/1.10.3"})

    def test_caching_is_discarded(self):
        [record] = shcheck.normalize_json(self.FORK, [])
        self.assertNotIn("caching", record)

    def test_original_deprecated_headers_leave_missing(self):
        [record] = shcheck.normalize_json(self.ORIGINAL, [])
        self.assertEqual(record["missing"], ["Content-Security-Policy"])

    def test_original_deprecated_headers_move_out_of_present(self):
        [record] = shcheck.normalize_json(self.ORIGINAL, [])
        self.assertEqual(record["present"], {"X-Frame-Options": "DENY"})
        self.assertEqual(record["deprecated"], {"X-XSS-Protection": "1; mode=block"})

    def test_original_has_no_unsafe_map(self):
        [record] = shcheck.normalize_json(self.ORIGINAL, [])
        self.assertEqual(record["unsafe"], {})

    def test_both_variants_normalize_alike(self):
        [fork] = shcheck.normalize_json(self.FORK, [])
        [original] = shcheck.normalize_json(self.ORIGINAL, [])
        for key in ("url", "present", "missing", "deprecated", "info_disclosure"):
            self.assertEqual(fork[key], original[key], key)

    def test_info_disclosure_none_when_check_not_run(self):
        data = {"https://x.example": {"present": {}, "missing": [], "unsafe": {}}}
        [record] = shcheck.normalize_json(data, [])
        self.assertIsNone(record["info_disclosure"])

    def test_info_disclosure_empty_dict_when_check_ran_clean(self):
        data = {
            "https://x.example": {
                "present": {},
                "missing": [],
                "unsafe": {},
                "information_disclosure": {},
            }
        }
        [record] = shcheck.normalize_json(data, [])
        self.assertEqual(record["info_disclosure"], {})

    def test_evidence_is_decoded(self):
        data = {
            "https://x.example": {
                "present": {},
                "missing": [],
                "unsafe": {},
                "request": "SEVBRCAv",
                "response": "SFRUUC8xLjEgMjAwIE9L",
            }
        }
        [record] = shcheck.normalize_json(data, [])
        self.assertEqual(record["request"], b"HEAD /")
        self.assertEqual(record["response"], b"HTTP/1.1 200 OK")

    def test_absent_evidence_is_none(self):
        [record] = shcheck.normalize_json(self.ORIGINAL, [])
        self.assertIsNone(record["request"])
        self.assertIsNone(record["response"])

    def test_undecodable_evidence_is_dropped_with_a_warning(self):
        data = {
            "https://x.example": {
                "present": {},
                "missing": [],
                "unsafe": {},
                "response": "!!!not base64!!!",
            }
        }
        warnings = []
        [record] = shcheck.normalize_json(data, warnings)
        self.assertIsNone(record["response"])
        self.assertEqual(len(warnings), 1)
        self.assertIn("response", warnings[0])

    def test_malformed_entry_is_skipped_but_siblings_survive(self):
        data = {
            "https://good.example": {
                "present": {},
                "missing": ["X-Frame-Options"],
                "unsafe": {},
            },
            "https://bad.example": "not an object",
        }
        warnings = []
        records = shcheck.normalize_json(data, warnings)
        self.assertEqual([r["url"] for r in records], ["https://good.example"])
        self.assertEqual(len(warnings), 1)
        self.assertIn("bad.example", warnings[0])

    def test_multiple_urls_preserve_input_order(self):
        data = {
            "https://b.example": {"present": {}, "missing": [], "unsafe": {}},
            "https://a.example": {"present": {}, "missing": [], "unsafe": {}},
        }
        records = shcheck.normalize_json(data, [])
        self.assertEqual(
            [r["url"] for r in records], ["https://b.example", "https://a.example"]
        )

    def test_missing_as_string_is_treated_as_malformed_not_coerced(self):
        # list("X-Frame-Options") would silently explode into 15 single-
        # character "missing" entries with no warning -- a wrong-typed field
        # must be treated the same as any other malformed entry: skip that
        # URL, warn, keep the rest.
        data = {
            "https://good.example": {
                "present": {},
                "missing": ["X-Frame-Options"],
                "unsafe": {},
            },
            "https://bad.example": {
                "present": {},
                "missing": "X-Frame-Options",
                "unsafe": {},
            },
        }
        warnings = []
        records = shcheck.normalize_json(data, warnings)
        self.assertEqual([r["url"] for r in records], ["https://good.example"])
        self.assertEqual(len(warnings), 1)
        self.assertIn("bad.example", warnings[0])


_FIXTURES = os.path.join(_HERE, "fixtures", "shcheck")


def read_fixture(name):
    with open(os.path.join(_FIXTURES, name), "r", encoding="utf-8") as handle:
        return handle.read()


class TestStripAnsi(unittest.TestCase):
    def test_removes_colour_codes(self):
        self.assertEqual(shcheck.strip_ansi("\033[94mhttps://x\033[0m"), "https://x")

    def test_leaves_plain_text_alone(self):
        self.assertEqual(shcheck.strip_ansi("plain"), "plain")


class TestNormalizeTextFork(unittest.TestCase):
    def setUp(self):
        self.warnings = []
        [self.record] = shcheck.normalize_text(read_fixture("fork.txt"), self.warnings)

    def test_url(self):
        self.assertEqual(self.record["url"], "https://example.com/app")

    def test_present_header_with_value(self):
        self.assertEqual(self.record["present"]["X-Frame-Options"], "DENY")

    def test_insecure_header_lands_in_present_and_unsafe(self):
        self.assertEqual(
            self.record["present"]["Strict-Transport-Security"], "max-age=0"
        )
        self.assertIn("Strict-Transport-Security", self.record["unsafe"])

    def test_policy_header_value_recovered_from_indented_block(self):
        self.assertEqual(
            self.record["present"]["Content-Security-Policy"],
            "default-src 'self' 'unsafe-inline'",
        )
        self.assertIn("Content-Security-Policy", self.record["unsafe"])

    def test_missing(self):
        self.assertEqual(self.record["missing"], ["Referrer-Policy"])

    def test_deprecated(self):
        self.assertEqual(
            self.record["deprecated"], {"X-XSS-Protection": "1; mode=block"}
        )

    def test_information_disclosure(self):
        self.assertEqual(self.record["info_disclosure"], {"Server": "nginx/1.10.3"})

    def test_caching_is_ignored(self):
        self.assertNotIn("ETag", self.record["present"])

    def test_raw_evidence_recovered(self):
        self.assertIn(b"HEAD /app HTTP/1.1", self.record["request"])
        self.assertIn(b"HTTP/1.1 200 OK", self.record["response"])
        self.assertIn(b"\r\n", self.record["request"])


class TestNormalizeTextOriginal(unittest.TestCase):
    def setUp(self):
        self.warnings = []
        [self.record] = shcheck.normalize_text(
            read_fixture("original.txt"), self.warnings
        )

    def test_effective_url_wins_over_target(self):
        self.assertEqual(self.record["url"], "https://example.com/app")

    def test_present_header_with_value(self):
        self.assertEqual(self.record["present"]["X-Frame-Options"], "DENY")

    def test_csp_value_recovered_from_indented_block(self):
        # FINDING 1: the original tool pretty-prints this line as
        # "default-src: 'self' 'unsafe-inline'" (with a colon after the
        # directive name -- see fixtures/shcheck/original.txt). Before the
        # fix, this test asserted that colon form verbatim, which is exactly
        # what made parse_csp key the directive as "default-src:" and match
        # nothing. _collect_indented now normalizes it to the same canonical
        # form the fork emits.
        self.assertEqual(
            self.record["present"]["Content-Security-Policy"],
            "default-src 'self' 'unsafe-inline'",
        )

    def test_deprecated_header_moved_out_of_present(self):
        self.assertNotIn("X-XSS-Protection", self.record["present"])
        self.assertEqual(
            self.record["deprecated"], {"X-XSS-Protection": "1; mode=block"}
        )

    def test_deprecated_header_removed_from_missing(self):
        self.assertEqual(self.record["missing"], ["Referrer-Policy"])

    def test_insecure_header_lands_in_present_and_unsafe(self):
        self.assertEqual(
            self.record["present"]["Strict-Transport-Security"], "max-age=0"
        )
        self.assertIn("Strict-Transport-Security", self.record["unsafe"])

    def test_information_disclosure(self):
        self.assertEqual(self.record["info_disclosure"], {"Server": "nginx/1.10.3"})

    def test_no_evidence_available(self):
        self.assertIsNone(self.record["request"])
        self.assertIsNone(self.record["response"])


class TestNormalizeTextEdgeCases(unittest.TestCase):
    def test_ansi_coloured_input_is_handled(self):
        text = read_fixture("fork.txt").replace(
            "https://example.com/app", "\033[94mhttps://example.com/app\033[0m"
        )
        [record] = shcheck.normalize_text(text, [])
        self.assertEqual(record["url"], "https://example.com/app")

    def test_info_disclosure_none_when_check_not_run(self):
        text = "\n".join(
            line
            for line in read_fixture("fork.txt").splitlines()
            if "information disclosure" not in line
        )
        [record] = shcheck.normalize_text(text, [])
        self.assertIsNone(record["info_disclosure"])

    def test_original_no_disclosure_line_means_check_ran_clean(self):
        text = read_fixture("original.txt").replace(
            "[!] Possible information disclosure: header Server is present! (Value: nginx/1.10.3)",
            "[*] No information disclosure headers detected",
        )
        [record] = shcheck.normalize_text(text, [])
        self.assertEqual(record["info_disclosure"], {})

    def test_two_urls_produce_two_records(self):
        text = read_fixture("fork.txt")
        doubled = text + text.replace("example.com", "other.example")
        records = shcheck.normalize_text(doubled, [])
        self.assertEqual(
            [r["url"] for r in records],
            ["https://example.com/app", "https://other.example/app"],
        )

    def test_unrecognised_lines_produce_one_counted_warning(self):
        text = (
            read_fixture("fork.txt") + "\n[?] something entirely new\n[?] and another\n"
        )
        warnings = []
        shcheck.normalize_text(text, warnings)
        self.assertEqual(len(warnings), 1)
        self.assertIn("2", warnings[0])

    def test_text_with_no_target_line_yields_nothing(self):
        self.assertEqual(shcheck.normalize_text("banner only\n", []), [])


class TestCollectIndented(unittest.TestCase):
    """_collect_indented must normalize the original variant's colon-suffixed

    directive names (`default-src: 'self'`) to the same canonical form the
    fork already emits (`default-src 'self'`), without touching a colon that
    is part of the *value* -- a https:// scheme or a report-uri target.
    """

    def test_strips_colon_after_directive_name(self):
        lines = ["\tdefault-src: 'self' 'unsafe-inline'"]
        text, index = shcheck._collect_indented(lines, 0)
        self.assertEqual(text, "default-src 'self' 'unsafe-inline'")
        self.assertEqual(index, 1)

    def test_leaves_fork_format_unchanged(self):
        lines = ["\tdefault-src 'self' 'unsafe-inline';"]
        text, index = shcheck._collect_indented(lines, 0)
        self.assertEqual(text, "default-src 'self' 'unsafe-inline'")

    def test_preserves_colon_inside_a_source_expression(self):
        lines = ["\tdefault-src: https://cdn.example.com"]
        text, index = shcheck._collect_indented(lines, 0)
        self.assertEqual(text, "default-src https://cdn.example.com")

    def test_preserves_colon_in_report_uri_value(self):
        lines = ["\treport-uri: https://example.com/csp-report"]
        text, index = shcheck._collect_indented(lines, 0)
        self.assertEqual(text, "report-uri https://example.com/csp-report")

    def test_valueless_directive_with_trailing_colon(self):
        lines = ["\tupgrade-insecure-requests:"]
        text, index = shcheck._collect_indented(lines, 0)
        self.assertEqual(text, "upgrade-insecure-requests")

    def test_multiple_directives_across_lines(self):
        lines = [
            "\tdefault-src: 'self'",
            "\tobject-src: 'none'",
        ]
        text, index = shcheck._collect_indented(lines, 0)
        self.assertEqual(text, "default-src 'self'; object-src 'none'")


class TestOriginalTextCspFindingParity(unittest.TestCase):
    """FINDING 1 (Critical): the original variant's console CSP pretty-printer

    inserts a colon after the directive name (`default-src: 'self' ...`)
    where the fork does not (`default-src 'self' ...;`). Before the fix,
    parse_csp keyed the directive as "default-src:", which matches nothing,
    so the original fixture produced two false findings (csp-no-default-src,
    csp-no-object-src) and missed the real csp-unsafe-inline. Both fixtures
    describe the same policy, so both must yield the same finding codes.
    """

    def test_original_and_fork_text_yield_the_same_csp_findings(self):
        [fork_record] = shcheck.normalize_text(read_fixture("fork.txt"), [])
        [original_record] = shcheck.normalize_text(read_fixture("original.txt"), [])

        fork_csp = fork_record["present"]["Content-Security-Policy"]
        original_csp = original_record["present"]["Content-Security-Policy"]

        fork_codes = codes(headers.analyze("Content-Security-Policy", fork_csp))
        original_codes = codes(headers.analyze("Content-Security-Policy", original_csp))

        self.assertEqual(fork_codes, original_codes)
        self.assertIn("csp-unsafe-inline", original_codes)
        self.assertNotIn("csp-no-default-src", original_codes)
        self.assertNotIn("csp-no-object-src", original_codes)


class TestFourWayAdapterEquivalence(unittest.TestCase):
    """FINDING 4: the same logical scan, expressed in all four input shapes,

    must normalize to equivalent records -- modulo evidence availability
    (only the fork's -r text and JSON carry request/response) and the
    'unsafe' map (the original variant has no such concept in either shape).
    fork.txt and original.txt are already a matched pair describing one scan;
    FORK_JSON and ORIGINAL_JSON below describe that identical scan in JSON.
    """

    FORK_JSON = {
        "https://example.com/app": {
            "present": {
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=0",
                "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
            },
            "missing": ["Referrer-Policy"],
            "unsafe": {
                "Strict-Transport-Security": "max-age=0",
                "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
            },
            "deprecated": {"X-XSS-Protection": "1; mode=block"},
            "information_disclosure": {"Server": "nginx/1.10.3"},
        }
    }
    ORIGINAL_JSON = {
        "https://example.com/app": {
            "present": {
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=0",
                "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
                "X-XSS-Protection": "1; mode=block",
            },
            "missing": ["Referrer-Policy", "Expect-CT"],
            "information_disclosure": {"Server": "nginx/1.10.3"},
        }
    }

    # Fields compared across all four shapes. "unsafe" and evidence are
    # excluded per the spec's "modulo evidence availability and text-mode
    # value fidelity" -- the original variant never emits an unsafe map in
    # either shape, and only the fork's text/JSON carry raw HTTP evidence.
    COMPARABLE_FIELDS = ("url", "present", "missing", "deprecated", "info_disclosure")

    def setUp(self):
        [self.fork_json] = shcheck.normalize_json(self.FORK_JSON, [])
        [self.original_json] = shcheck.normalize_json(self.ORIGINAL_JSON, [])
        [self.fork_text] = shcheck.normalize_text(read_fixture("fork.txt"), [])
        [self.original_text] = shcheck.normalize_text(read_fixture("original.txt"), [])

    def test_all_four_shapes_agree(self):
        records = {
            "fork json": self.fork_json,
            "original json": self.original_json,
            "fork text": self.fork_text,
            "original text": self.original_text,
        }
        baseline_name, baseline = next(iter(records.items()))
        for name, record in records.items():
            for field in self.COMPARABLE_FIELDS:
                self.assertEqual(
                    record[field],
                    baseline[field],
                    "%s.%s != %s.%s" % (name, field, baseline_name, field),
                )

    def test_all_four_shapes_produce_the_same_finding_codes(self):
        for label, record in (
            ("fork json", self.fork_json),
            ("original json", self.original_json),
            ("fork text", self.fork_text),
            ("original text", self.original_text),
        ):
            found = codes(headers.analyze_all(record["present"]))
            self.assertIn("csp-unsafe-inline", found, label)
            self.assertNotIn("csp-no-default-src", found, label)


_PARSER = os.path.join(_PARSER_DIR, "shcheck.py")


def run_parser(payload):
    """Run the parser as the engine does: stdin in, JSON array out."""
    result = subprocess.run(
        [sys.executable, _PARSER],
        input=payload,
        capture_output=True,
        text=True,
    )
    return result


class TestSplitUrl(unittest.TestCase):
    def test_path_present(self):
        self.assertEqual(
            shcheck.split_url("https://example.com/app"),
            ("https://example.com", "/app"),
        )

    def test_no_path_becomes_root(self):
        self.assertEqual(
            shcheck.split_url("https://example.com"), ("https://example.com", "/")
        )

    def test_query_is_kept_on_the_path(self):
        self.assertEqual(
            shcheck.split_url("https://example.com/a?b=c"),
            ("https://example.com", "/a?b=c"),
        )

    def test_port_stays_on_the_host(self):
        self.assertEqual(
            shcheck.split_url("https://example.com:8443/x"),
            ("https://example.com:8443", "/x"),
        )


class TestBuildIssues(unittest.TestCase):
    def _record(self, **overrides):
        record = shcheck.new_record("https://example.com/app")
        record.update(overrides)
        return record

    def test_missing_headers_produce_a_low_issue(self):
        [issue] = shcheck.build_issues(
            self._record(missing=["Content-Security-Policy"]), []
        )
        self.assertEqual(issue["template"], "missing_security_headers")
        self.assertEqual(issue["tools"], ["shcheck"])
        self.assertEqual(issue["severity"], "low")
        self.assertEqual(issue["affects"], ["https://example.com/app"])
        self.assertEqual(issue["issues"][0]["host"], "https://example.com")
        self.assertEqual(issue["issues"][0]["path"], "/app")
        self.assertEqual(
            issue["issues"][0]["details"], ["Content-Security-Policy - missing"]
        )

    def test_hsts_max_age_zero_escalates_to_medium(self):
        record = self._record(
            present={"Strict-Transport-Security": "max-age=0; includeSubDomains"}
        )
        [issue] = shcheck.build_issues(record, [])
        self.assertEqual(issue["severity"], "medium")

    def test_severity_is_the_max_across_details(self):
        record = self._record(
            missing=["Content-Security-Policy"],
            present={"Strict-Transport-Security": "max-age=0; includeSubDomains"},
        )
        [issue] = shcheck.build_issues(record, [])
        details = issue["issues"][0]["details"]
        # A low detail and a medium detail both landed, and the issue took the max.
        # Asserted on content rather than count: a count assertion breaks every time
        # a header rule is added or tuned, without indicating anything is wrong.
        self.assertEqual(issue["severity"], "medium")
        self.assertIn("Content-Security-Policy - missing", details)
        self.assertTrue(any("max-age=0" in d for d in details))

    def test_deprecated_headers_are_reported_as_removable(self):
        record = self._record(deprecated={"X-XSS-Protection": "1; mode=block"})
        [issue] = shcheck.build_issues(record, [])
        self.assertEqual(issue["severity"], "low")
        self.assertIn("deprecated", issue["issues"][0]["details"][0])
        self.assertIn("X-XSS-Protection", issue["issues"][0]["details"][0])

    def test_analysis_details_are_header_dash_message(self):
        record = self._record(present={"X-Content-Type-Options": "sniff"})
        [issue] = shcheck.build_issues(record, [])
        self.assertTrue(
            issue["issues"][0]["details"][0].startswith(
                "X-Content-Type-Options - present but "
            )
        )

    def test_details_are_sorted_and_unique(self):
        record = self._record(
            missing=["X-Frame-Options", "Content-Security-Policy", "X-Frame-Options"]
        )
        [issue] = shcheck.build_issues(record, [])
        self.assertEqual(
            issue["issues"][0]["details"],
            ["Content-Security-Policy - missing", "X-Frame-Options - missing"],
        )

    def test_evidence_is_re_encoded_as_base64(self):
        record = self._record(
            missing=["X-Frame-Options"], request=b"HEAD /", response=b"HTTP/1.1 200 OK"
        )
        [issue] = shcheck.build_issues(record, [])
        self.assertEqual(issue["issues"][0]["request"], "SEVBRCAv")
        self.assertEqual(issue["issues"][0]["response"], "SFRUUC8xLjEgMjAwIE9L")

    def test_evidence_keys_absent_when_unavailable(self):
        [issue] = shcheck.build_issues(self._record(missing=["X-Frame-Options"]), [])
        self.assertNotIn("request", issue["issues"][0])
        self.assertNotIn("response", issue["issues"][0])

    def test_clean_record_produces_no_issue(self):
        record = self._record(present={"X-Frame-Options": "DENY"}, info_disclosure={})
        self.assertEqual(shcheck.build_issues(record, []), [])

    def test_shcheck_disagreement_is_noted(self):
        # shcheck flagged it, our analysis cleared it: worth a note, not a finding.
        record = self._record(
            present={"X-Content-Type-Options": "nosniff"},
            unsafe={"X-Content-Type-Options": "nosniff"},
        )
        warnings = []
        shcheck.build_issues(record, warnings)
        self.assertEqual(len(warnings), 1)
        self.assertIn("X-Content-Type-Options", warnings[0])

    def test_self_only_disagreement_is_silent(self):
        # shcheck flags any policy containing "self"; that is its bug, not a finding.
        record = self._record(
            present={"Content-Security-Policy": TestCspRules.CLEAN},
            unsafe={"Content-Security-Policy": TestCspRules.CLEAN},
        )
        warnings = []
        shcheck.build_issues(record, warnings)
        self.assertEqual(warnings, [])


class TestSniff(unittest.TestCase):
    def test_json_object(self):
        self.assertEqual(
            shcheck.sniff(
                '{"https://x": {"present": {}, "missing": [], "unsafe": {}}}'
            ),
            "json",
        )

    def test_fork_text(self):
        self.assertEqual(
            shcheck.sniff("[!] Headers analysis results for https://x"), "text"
        )

    def test_original_text(self):
        self.assertEqual(shcheck.sniff("[!] Analyzing headers for https://x"), "text")

    def test_target_line_alone_is_enough(self):
        self.assertEqual(shcheck.sniff("[*] Analyzing headers of https://x"), "text")

    def test_json_array_is_rejected(self):
        with self.assertRaises(ValueError):
            shcheck.sniff("[1, 2, 3]")

    def test_unrelated_text_is_rejected(self):
        with self.assertRaises(ValueError):
            shcheck.sniff("this is a shopping list")

    def test_dict_of_strings_is_rejected(self):
        # Real shcheck output never produces string-valued entries, and
        # normalize_json discards them as malformed anyway -- so accepting
        # this shape here meant such a file exited 0 with no findings
        # instead of the exit(1) the spec requires, bypassing --on-error.
        with self.assertRaises(ValueError):
            shcheck.sniff('{"https://x": "not an object"}')


class TestParserSubprocess(unittest.TestCase):
    def test_json_input_round_trip(self):
        payload = json.dumps(
            {
                "https://example.com/app": {
                    "present": {},
                    "missing": ["X-Frame-Options"],
                    "unsafe": {},
                }
            }
        )
        result = run_parser(payload)
        self.assertEqual(result.returncode, 0, result.stderr)
        [issue] = json.loads(result.stdout)
        self.assertEqual(issue["template"], "missing_security_headers")

    def test_text_input_round_trip(self):
        result = run_parser(read_fixture("fork.txt"))
        self.assertEqual(result.returncode, 0, result.stderr)
        issues = json.loads(result.stdout)
        self.assertTrue(issues)

    def test_unrecognised_input_exits_nonzero(self):
        result = run_parser("this is a shopping list")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")

    def test_json_array_exits_nonzero(self):
        result = run_parser("[1, 2, 3]")
        self.assertEqual(result.returncode, 1)

    def test_dict_of_strings_exits_nonzero(self):
        result = run_parser('{"https://x": "not an object"}')
        self.assertEqual(result.returncode, 1)

    def test_clean_scan_emits_empty_array_and_exits_zero(self):
        payload = json.dumps(
            {
                "https://example.com": {
                    "present": {"X-Frame-Options": "DENY"},
                    "missing": [],
                    "unsafe": {},
                }
            }
        )
        result = run_parser(payload)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), [])
        self.assertIn("no findings", result.stderr.lower())


_ROOT = os.path.join(_HERE, "..")
_TEMPLATE_DIR = os.path.join(_ROOT, "templates", "shcheck")


class TestInfoDisclosureTemplate(unittest.TestCase):
    def test_all_four_files_exist(self):
        for name in (
            "information_disclosure_headers.json5",
            "information_disclosure_headers.es.json5",
            "information_disclosure_headers.schema.json",
            "information_disclosure_headers.py",
        ):
            self.assertTrue(os.path.exists(os.path.join(_TEMPLATE_DIR, name)), name)

    def test_template_has_the_required_keys(self):
        import json5

        with open(
            os.path.join(_TEMPLATE_DIR, "information_disclosure_headers.json5")
        ) as handle:
            data = json5.load(handle)
        for key in ("title", "summary", "description", "recommendations", "details"):
            self.assertIn(key, data)
        self.assertNotIn("\n", data["summary"])

    def test_spanish_template_has_the_required_keys(self):
        import json5

        with open(
            os.path.join(_TEMPLATE_DIR, "information_disclosure_headers.es.json5")
        ) as handle:
            data = json5.load(handle)
        for key in ("title", "summary", "description", "recommendations", "details"):
            self.assertIn(key, data)

    def test_emitted_issue_validates_against_the_schema(self):
        import jsonschema

        with open(
            os.path.join(_TEMPLATE_DIR, "information_disclosure_headers.schema.json")
        ) as handle:
            schema = json.load(handle)
        record = shcheck.new_record("https://example.com/app")
        record["info_disclosure"] = {"Server": "nginx/1.10.3"}
        issues = [
            i
            for i in shcheck.build_issues(record, [])
            if i["template"] == "information_disclosure_headers"
        ]
        self.assertEqual(len(issues), 1)
        jsonschema.validate(issues[0], schema)

    def test_missing_security_headers_issue_validates_against_burp_schema(self):
        import jsonschema

        path = os.path.join(
            _ROOT, "templates", "burp", "missing_security_headers.schema.json"
        )
        with open(path) as handle:
            schema = json.load(handle)
        record = shcheck.new_record("https://example.com/app")
        record["missing"] = ["X-Frame-Options"]
        record["response"] = b"HTTP/1.1 200 OK"
        [issue] = shcheck.build_issues(record, [])
        jsonschema.validate(issue, schema)


class TestInfoDisclosureMerger(unittest.TestCase):
    def _run_merger(self, issues):
        script = os.path.join(_TEMPLATE_DIR, "information_disclosure_headers.py")
        env = dict(os.environ, MAGENTA_HOME=os.path.abspath(_ROOT))
        result = subprocess.run(
            [sys.executable, script],
            input=json.dumps(issues),
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def _issue(self, url, headers):
        host, path = shcheck.split_url(url)
        return {
            "template": "information_disclosure_headers",
            "tools": ["shcheck"],
            "severity": "low",
            "affects": [url],
            "issues": [{"host": host, "path": path, "headers": headers}],
        }

    def test_headers_are_unioned_for_the_same_url(self):
        merged = self._run_merger(
            [
                self._issue("https://example.com/app", {"Server": "nginx"}),
                self._issue("https://example.com/app", {"X-Powered-By": "PHP/7.4"}),
            ]
        )
        self.assertEqual(len(merged["issues"]), 1)
        self.assertEqual(
            merged["issues"][0]["headers"],
            {"Server": "nginx", "X-Powered-By": "PHP/7.4"},
        )

    def test_different_urls_stay_separate(self):
        merged = self._run_merger(
            [
                self._issue("https://a.example/", {"Server": "nginx"}),
                self._issue("https://b.example/", {"Server": "apache"}),
            ]
        )
        self.assertEqual(len(merged["issues"]), 2)


class TestParserMetadata(unittest.TestCase):
    def test_metadata_validates(self):
        import json5
        import jsonschema

        sys.path.insert(0, os.path.abspath(_ROOT))
        from libmagenta.engine import MagentaReporter

        with open(os.path.join(_PARSER_DIR, "shcheck.json5")) as handle:
            data = json5.load(handle)
        jsonschema.validate(data, MagentaReporter.SCHEMA_PARSER)

    def test_formats_cover_both_extensions(self):
        import json5

        with open(os.path.join(_PARSER_DIR, "shcheck.json5")) as handle:
            data = json5.load(handle)
        self.assertEqual(sorted(data["formats"]), ["json", "txt"])


class TestEndToEnd(unittest.TestCase):
    def test_engine_renders_a_report_from_the_fixture(self):
        import tempfile

        sys.path.insert(0, os.path.abspath(_ROOT))
        os.environ["MAGENTA_HOME"] = os.path.abspath(_ROOT)
        from libmagenta.engine import MagentaReporter

        with tempfile.TemporaryDirectory() as workdir:
            target = os.path.join(workdir, "shcheck.json")
            with open(target, "w") as handle:
                handle.write(read_fixture("shcheck.json"))

            magenta = MagentaReporter()
            magenta.set_language("en")
            result = magenta.process_files(workdir)

        # process_files returns a dict, not a tuple:
        # {"metadata", "issues", "sections", "report", "skipped"}
        self.assertEqual(result["skipped"], 0)
        report = result["report"]
        self.assertIn("Missing Security Headers", report)
        self.assertIn("Information Disclosure in HTTP Headers", report)
        # The engine's Jinja environment renders Markdown with autoescape=True
        # and escape_func=escapemd (libmagenta/template.py escapemd, wired in
        # libmagenta/engine.py around lines 327-338), which backslash-escapes
        # "-" among other Markdown metacharacters in any interpolated value.
        # Header names inserted into the bullet list go through that filter,
        # so "Referrer-Policy" renders as "Referrer\-Policy" in the report.
        self.assertIn("Referrer\\-Policy", report)
        self.assertIn("nginx/1.10.3", report)

    def test_both_issue_types_survive_validation(self):
        import tempfile

        sys.path.insert(0, os.path.abspath(_ROOT))
        os.environ["MAGENTA_HOME"] = os.path.abspath(_ROOT)
        from libmagenta.engine import MagentaReporter

        with tempfile.TemporaryDirectory() as workdir:
            with open(os.path.join(workdir, "shcheck.json"), "w") as handle:
                handle.write(read_fixture("shcheck.json"))
            magenta = MagentaReporter()
            magenta.set_language("en")
            result = magenta.process_files(workdir)

        templates = sorted(issue["template"] for issue in result["issues"])
        self.assertEqual(
            templates, ["information_disclosure_headers", "missing_security_headers"]
        )

    def test_both_templates_resolve(self):
        sys.path.insert(0, os.path.abspath(_ROOT))
        os.environ["MAGENTA_HOME"] = os.path.abspath(_ROOT)
        from libmagenta.engine import MagentaReporter

        magenta = MagentaReporter()
        magenta.set_language("en")
        self.assertIn("missing_security_headers", magenta.templates)
        self.assertIn("information_disclosure_headers", magenta.templates)


class TestEndToEndText(unittest.TestCase):
    """FINDING 4: the `.txt` half of the parser's declared `formats` must also

    reach the real engine -- TestEndToEnd above only drives shcheck.json.
    Using original.txt doubles as an end-to-end guard for Finding 1: the
    false "neither default-src nor script-src" / "neither object-src nor
    default-src" findings must not appear, and the real unsafe-inline finding
    must.
    """

    def test_engine_renders_a_report_from_text_input(self):
        import tempfile

        sys.path.insert(0, os.path.abspath(_ROOT))
        os.environ["MAGENTA_HOME"] = os.path.abspath(_ROOT)
        from libmagenta.engine import MagentaReporter

        with tempfile.TemporaryDirectory() as workdir:
            target = os.path.join(workdir, "shcheck.txt")
            with open(target, "w") as handle:
                handle.write(read_fixture("original.txt"))

            magenta = MagentaReporter()
            magenta.set_language("en")
            result = magenta.process_files(workdir)

        self.assertEqual(result["skipped"], 0)
        report = result["report"]
        self.assertIn("Missing Security Headers", report)
        self.assertIn("Information Disclosure in HTTP Headers", report)
        # The engine's Jinja environment backslash-escapes "-" (escapemd, see
        # TestEndToEnd above), so the rendered text reads "unsafe\-inline" and
        # "neither default\-src nor script\-src", not the unescaped forms.
        self.assertIn("unsafe\\-inline", report)
        self.assertNotIn("neither default\\-src nor script\\-src", report)
        self.assertNotIn("neither object\\-src nor default\\-src", report)

    def test_engine_renders_a_report_from_fork_text_input(self):
        import tempfile

        sys.path.insert(0, os.path.abspath(_ROOT))
        os.environ["MAGENTA_HOME"] = os.path.abspath(_ROOT)
        from libmagenta.engine import MagentaReporter

        with tempfile.TemporaryDirectory() as workdir:
            with open(os.path.join(workdir, "shcheck.txt"), "w") as handle:
                handle.write(read_fixture("fork.txt"))

            magenta = MagentaReporter()
            magenta.set_language("en")
            result = magenta.process_files(workdir)

        self.assertEqual(result["skipped"], 0)
        templates = sorted(issue["template"] for issue in result["issues"])
        self.assertEqual(
            templates, ["information_disclosure_headers", "missing_security_headers"]
        )


if __name__ == "__main__":
    unittest.main()
