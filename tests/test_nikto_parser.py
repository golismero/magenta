import contextlib
import importlib.util
import io as _io
import json
import os
import subprocess
import sys as _sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARSER = os.path.join(_HERE, "..", "parsers", "nikto", "nikto.py")
_spec = importlib.util.spec_from_file_location("nikto_parser", _PARSER)
nikto = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nikto)


class TestClassifyCore(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(
            nikto.classify_references(""),
            {"cve": [], "taxonomy": [], "references": []},
        )

    def test_single_cve(self):
        out = nikto.classify_references("CVE-2002-0764")
        self.assertEqual(out["cve"], ["CVE-2002-0764"])
        self.assertEqual(out["taxonomy"], [])
        self.assertEqual(out["references"], [])

    def test_comma_and_space_tokenization(self):
        out = nikto.classify_references("CVE-2000-0413,CVE-2000-0709 CVE-2000-0710")
        self.assertEqual(
            out["cve"], ["CVE-2000-0413", "CVE-2000-0709", "CVE-2000-0710"]
        )

    def test_trailing_punctuation_stripped(self):
        out = nikto.classify_references("CVE-2000-0538.")
        self.assertEqual(out["cve"], ["CVE-2000-0538"])

    def test_cwe_goes_to_taxonomy_not_cve(self):
        out = nikto.classify_references("CWE-79")
        self.assertEqual(out["cve"], [])
        self.assertEqual(out["taxonomy"], ["CWE-79"])

    def test_url_goes_to_references(self):
        out = nikto.classify_references("https://example.com/x")
        self.assertEqual(out["references"], ["https://example.com/x"])
        self.assertEqual(out["cve"], [])

    def test_mixed_cve_url(self):
        out = nikto.classify_references(
            "CVE-2002-0599,https://sourceforge.net/projects/blahzdns/"
        )
        self.assertEqual(out["cve"], ["CVE-2002-0599"])
        self.assertEqual(out["references"], ["https://sourceforge.net/projects/blahzdns/"])

    def test_dedup_preserves_order(self):
        out = nikto.classify_references("CVE-2001-0001 CVE-2001-0001 CVE-2001-0002")
        self.assertEqual(out["cve"], ["CVE-2001-0001", "CVE-2001-0002"])


class TestOsvdb(unittest.TestCase):
    def test_mapped_osvdb_becomes_cve(self):
        # OSVDB:11144 -> CVE-2002-0764 is present in osvdb2cve.json.
        out = nikto.classify_references("OSVDB-11144")
        self.assertEqual(out["cve"], ["CVE-2002-0764"])

    def test_unmapped_osvdb_keeps_raw_tag(self):
        out = nikto.classify_references("OSVDB-999999999")
        self.assertEqual(out["cve"], ["OSVDB-999999999"])

    def test_osvdb_0_is_informational(self):
        # OSVDB-0 is Nikto's "no specific vulnerability" marker, not a real id.
        out = nikto.classify_references("OSVDB-0")
        self.assertEqual(out, {"cve": [], "taxonomy": [], "references": []})

    def test_osvdb_0_does_not_count_toward_hitrate_guard(self):
        import io as _io
        import contextlib
        nikto.reset_osvdb_stats()
        for _ in range(12):
            nikto.classify_references("OSVDB-0")  # informational, not a lookup
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            nikto.osvdb_hitrate_warning()
        self.assertEqual(buf.getvalue(), "")

    def test_hitrate_guard_warns_when_none_map(self):
        import io as _io
        import contextlib
        nikto.reset_osvdb_stats()
        for n in range(12):
            nikto.classify_references("OSVDB-99000%d" % n)  # all unmapped
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            nikto.osvdb_hitrate_warning()
        self.assertIn("OSVDB", buf.getvalue())
        self.assertIn("none", buf.getvalue().lower())

    def test_hitrate_guard_silent_when_some_map(self):
        import io as _io
        import contextlib
        nikto.reset_osvdb_stats()
        nikto.classify_references("OSVDB-11144")  # maps
        for n in range(5):
            nikto.classify_references("OSVDB-99000%d" % n)
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            nikto.osvdb_hitrate_warning()
        self.assertEqual(buf.getvalue(), "")


class TestSpecialTokens(unittest.TestCase):
    def test_phorum_corrupted_token(self):
        out = nikto.classify_references("OSVCVE-2011-339244")
        self.assertEqual(out["cve"], ["CVE-2002-0764"])

    def test_phorum_wrong_cve_override(self):
        out = nikto.classify_references("CVE-2011-3392")
        self.assertEqual(out["cve"], ["CVE-2002-0764"])

    def test_ca_advisory_becomes_cwe79(self):
        out = nikto.classify_references("CA-2000-02")
        self.assertEqual(out["cve"], [])
        self.assertEqual(out["taxonomy"], ["CWE-79"])

    def test_ws_ftp_log_dropped_silently_on_known_id(self):
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            out = nikto.classify_references("WS_FTP.LOG", nikto_id="001353")
        self.assertEqual(out, {"cve": [], "taxonomy": [], "references": []})
        self.assertEqual(buf.getvalue(), "")

    def test_ws_ftp_log_warns_on_other_id(self):
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            nikto.classify_references("WS_FTP.LOG", nikto_id="000001")
        self.assertIn("WS_FTP.LOG", buf.getvalue())

    def test_rfc_dash_normalized_to_space(self):
        out = nikto.classify_references("RFC-5785")
        self.assertEqual(out["taxonomy"], ["RFC 5785"])

    def test_mskb_normalized_to_kb(self):
        out = nikto.classify_references("MSKB:Q231368")
        self.assertEqual(out["taxonomy"], ["KB231368"])

    def test_ms_bulletin_is_cve_bucket(self):
        out = nikto.classify_references("MS00-078")
        self.assertEqual(out["cve"], ["MS00-078"])

    def test_cnvd_is_cve_bucket(self):
        out = nikto.classify_references("CNVD-C-2019-48814")
        self.assertEqual(out["cve"], ["CNVD-C-2019-48814"])

    def test_bid_dropped_silently(self):
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            out = nikto.classify_references("BID-4684")
        self.assertEqual(out, {"cve": [], "taxonomy": [], "references": []})
        self.assertEqual(buf.getvalue(), "")

    def test_unknown_token_warns_and_drops(self):
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            out = nikto.classify_references("FROBNICATE-42", nikto_id="012345")
        self.assertEqual(out["cve"], [])
        self.assertIn("FROBNICATE-42", buf.getvalue())
        self.assertIn("012345", buf.getvalue())


class TestReadCsv(unittest.TestCase):
    OLD = (
        '"Nikto - v2.1.5"\n'
        '"victim.example","10.0.0.1","80","","","","Apache/2.2.3"\n'
        '"victim.example","10.0.0.1","80","OSVDB-3268","GET","/icons/","Directory indexing found."\n'
    )
    NEW = (
        '"Nikto - v2.5.0"\n'
        '"victim.example","10.0.0.1","443","","","","Apache"\n'
        '"victim.example","10.0.0.1","443","CVE-2002-0764","GET","/phorum/admin/footer.php","XSS"\n'
        '"victim.example","10.0.0.1","443","000137","GET","/","SSL Certificate Subject: CN=x"\n'
    )

    def test_old_csv_host_and_finding(self):
        f = nikto.read_csv(self.OLD)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].host_url, "http://victim.example:80")
        self.assertEqual(f[0].path, "/icons/")
        self.assertEqual(f[0].method, "GET")
        self.assertEqual(f[0].refs_str, "OSVDB-3268")
        self.assertEqual(f[0].msg, "Directory indexing found.")

    def test_new_csv_https_and_skips_ssl_row(self):
        f = nikto.read_csv(self.NEW)
        self.assertEqual(len(f), 1)  # SSL 000137 row skipped
        self.assertEqual(f[0].host_url, "https://victim.example:443")
        self.assertEqual(f[0].refs_str, "CVE-2002-0764")

    def test_csv_injection_apostrophe_stripped(self):
        data = (
            '"Nikto - v2.6.0"\n'
            '"h","1.2.3.4","80","\'=CVE-2021-1","GET","/x","msg"\n'
        )
        f = nikto.read_csv(data)
        self.assertEqual(f[0].refs_str, "=CVE-2021-1")

    def test_empty_csv_returns_empty(self):
        self.assertEqual(nikto.read_csv('"Nikto - v2.1.5"\n'), [])


class TestReadXml(unittest.TestCase):
    OLD = (
        '<?xml version="1.0" ?>\n'
        '<niktoscan nxmlversion="1.2">'
        '<scandetails targetip="10.0.0.1" targethostname="victim.example" targetport="80">'
        '<item id="000823" osvdbid="11144" osvdblink="http://osvdb.org/11144" method="GET">'
        "<description><![CDATA[Phorum XSS]]></description>"
        "<uri><![CDATA[/phorum/admin/footer.php]]></uri>"
        "<namelink><![CDATA[http://victim.example:80/phorum/admin/footer.php]]></namelink>"
        "<iplink><![CDATA[http://10.0.0.1:80/phorum/admin/footer.php]]></iplink>"
        "</item></scandetails></niktoscan>"
    )
    NEW_MULTIHOST = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<niktoscans>"
        '<niktoscan nxmlversion="1.2"><scandetails targetip="10.0.0.1" targethostname="a.example" targetport="443">'
        '<item id="000100" method="GET"><description><![CDATA[d1]]></description>'
        "<uri><![CDATA[/a]]></uri><namelink><![CDATA[https://a.example:443/a]]></namelink>"
        "<iplink><![CDATA[https://10.0.0.1:443/a]]></iplink>"
        "<references><![CDATA[CVE-2021-1]]></references></item></scandetails></niktoscan>"
        '<niktoscan nxmlversion="1.2"><scandetails targetip="10.0.0.2" targethostname="b.example" targetport="80">'
        '<item id="000200" method="GET"><description><![CDATA[d2]]></description>'
        "<uri><![CDATA[/b]]></uri><namelink><![CDATA[http://b.example:80/b]]></namelink>"
        "<iplink><![CDATA[http://10.0.0.2:80/b]]></iplink>"
        "<references><![CDATA[CVE-2021-2]]></references></item></scandetails></niktoscan>"
        "</niktoscans>"
    )

    def test_old_xml_osvdblink(self):
        f = nikto.read_xml(self.OLD)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].host_url, "http://victim.example:80")
        self.assertEqual(f[0].path, "/phorum/admin/footer.php")
        self.assertEqual(f[0].refs_str, "OSVDB-11144")
        self.assertEqual(f[0].nikto_id, "000823")

    def test_new_xml_references_child_multihost(self):
        f = nikto.read_xml(self.NEW_MULTIHOST)
        self.assertEqual(len(f), 2)
        hosts = sorted(x.host_url for x in f)
        self.assertEqual(hosts, ["http://b.example:80", "https://a.example:443"])
        self.assertEqual(
            sorted(x.refs_str for x in f), ["CVE-2021-1", "CVE-2021-2"]
        )

    def test_doubled_niktoscan_wrapper(self):
        doubled = self.OLD.replace(
            '<niktoscan nxmlversion="1.2">',
            '<niktoscan><niktoscan nxmlversion="1.2">',
        ).replace("</scandetails></niktoscan>", "</scandetails></niktoscan></niktoscan>")
        f = nikto.read_xml(doubled)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].path, "/phorum/admin/footer.php")


class TestReadJson(unittest.TestCase):
    MODERN = json.dumps([
        {
            "host": "a.example", "ip": "10.0.0.1", "port": "443",
            "server_banner": "Apache",
            "vulnerabilities": [
                {"id": "000100", "references": "CVE-2021-1",
                 "method": "GET", "url": "https://a.example:443/a", "msg": "m1"},
            ],
        },
        {
            "host": "b.example", "ip": "10.0.0.2", "port": "80",
            "server_banner": "nginx",
            "vulnerabilities": [
                {"id": "000200", "references": "", "method": "GET",
                 "url": "http://b.example:80/b", "msg": "m2"},
            ],
        },
    ])
    # 2.5.0 hand-built, multi-host -> invalid JSON (two objects, no array/commas)
    OLD_FRAGMENT = (
        '{"host":"a.example","ip":"10.0.0.1","port":"443","banner":"Apache",'
        '"vulnerabilities":[{"id": "000100","references": "CVE-2021-1",'
        '"method":"GET","url":"https://a.example:443/a","msg":"m1"}]}'
        '{"host":"b.example","ip":"10.0.0.2","port":"80","banner":"nginx",'
        '"vulnerabilities":[{"id": "000200","method":"GET",'
        '"url":"http://b.example:80/b","msg":"m2"}]}'
    )

    def test_modern_array(self):
        f = nikto.read_json(self.MODERN)
        self.assertEqual(len(f), 2)
        a = [x for x in f if x.host_url == "https://a.example:443"][0]
        self.assertEqual(a.path, "/a")
        self.assertEqual(a.refs_str, "CVE-2021-1")
        self.assertEqual(a.nikto_id, "000100")

    def test_old_fragment_repaired(self):
        f = nikto.read_json(self.OLD_FRAGMENT)
        self.assertEqual(len(f), 2)
        self.assertEqual(sorted(x.path for x in f), ["/a", "/b"])

    def test_unrepairable_warns_and_returns_empty(self):
        import io as _io2
        import contextlib as _cl2
        buf = _io2.StringIO()
        with _cl2.redirect_stderr(buf):
            out = nikto.read_json("{ totally not json ][")
        self.assertEqual(out, [])
        self.assertIn("JSON", buf.getvalue())


class TestBuildIssues(unittest.TestCase):
    def _f(self, host, path, refs, msg, nid=None, method="GET"):
        return nikto.Finding(host, path, method, refs, nid, msg)

    def test_basic_issue_shape(self):
        findings = [self._f("http://h:80", "/a", "CVE-2021-1", "m1")]
        issues = nikto.build_issues(findings)
        self.assertEqual(len(issues), 1)
        iss = issues[0]
        self.assertEqual(iss["tools"], ["nikto"])
        self.assertEqual(iss["template"], "multiple_nikto_issues")
        self.assertEqual(iss["severity"], "high")
        self.assertEqual(iss["affects"], ["http://h:80/a"])
        self.assertEqual(iss["taxonomy"], ["CVE-2021-1"])
        self.assertEqual(iss["issues"], {"http://h:80": [
            {"path": "/a", "cve": ["CVE-2021-1"], "msg": "m1"}]})

    def test_untagged_finding_dropped_by_default(self):
        findings = [self._f("http://h:80", "/x", "", "interesting file", nid="000001")]
        self.assertEqual(nikto.build_issues(findings), [])

    def test_ca_finding_reported_with_cwe_taxonomy_empty_cve_column(self):
        findings = [self._f("http://h:80", "/y.aspx", "CA-2000-02", "xss", nid="000767")]
        issues = nikto.build_issues(findings)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["taxonomy"], ["CWE-79"])
        # per-finding cve column is empty (CWE is a concept, not a specific vuln id)
        self.assertEqual(issues[0]["issues"]["http://h:80"][0]["cve"], [])

    def test_url_reference_goes_to_issue_references(self):
        findings = [self._f("http://h:80", "/z", "CVE-2021-9 https://ref.example/x", "m")]
        issues = nikto.build_issues(findings)
        self.assertEqual(issues[0]["references"], ["https://ref.example/x"])

    def test_multi_host_grouping_and_dedup(self):
        findings = [
            self._f("http://h:80", "/a", "CVE-2021-1", "m1"),
            self._f("http://h:80", "/a", "CVE-2021-1", "m1"),  # dup
            self._f("https://k:443", "/b", "CVE-2021-2", "m2"),
        ]
        issues = nikto.build_issues(findings)
        self.assertEqual(set(issues[0]["issues"].keys()), {"http://h:80", "https://k:443"})
        self.assertEqual(len(issues[0]["issues"]["http://h:80"]), 1)


class TestMainDispatch(unittest.TestCase):
    def _run(self, stdin_text):
        p = subprocess.run(
            [_sys.executable, _PARSER],
            input=stdin_text, capture_output=True, text=True,
        )
        return p

    def test_xml_end_to_end(self):
        p = self._run(TestReadXml.OLD)
        out = json.loads(p.stdout)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["template"], "multiple_nikto_issues")
        self.assertIn("CVE-2002-0764", out[0]["taxonomy"])

    def test_csv_end_to_end(self):
        p = self._run(TestReadCsv.NEW)
        out = json.loads(p.stdout)
        self.assertEqual(out[0]["issues"]["https://victim.example:443"][0]["cve"],
                         ["CVE-2002-0764"])

    def test_json_end_to_end(self):
        p = self._run(TestReadJson.MODERN)
        out = json.loads(p.stdout)
        self.assertEqual(len(out), 1)

    def test_empty_input(self):
        p = self._run("")
        self.assertEqual(json.loads(p.stdout), [])

    def test_garbage_input(self):
        p = self._run("this is not nikto output\n")
        self.assertEqual(json.loads(p.stdout), [])
        self.assertIn("nikto", p.stderr.lower())


class TestSchema(unittest.TestCase):
    def test_cve_is_array_in_schema(self):
        path = os.path.join(_HERE, "..", "templates", "nikto",
                            "multiple_nikto_issues.schema.json")
        with open(path) as fd:
            schema = json.load(fd)
        cve = (schema["properties"]["issues"]["additionalProperties"]
               ["items"]["properties"]["cve"])
        self.assertEqual(cve["type"], "array")
        self.assertEqual(cve["items"]["type"], "string")


class TestXmlHardening(unittest.TestCase):
    def test_truncated_xml_returns_empty_with_warning(self):
        import io as _io3
        import contextlib as _cl3
        bad = '<?xml version="1.0" ?><niktoscan><scandetails><item><uri>/x'
        buf = _io3.StringIO()
        with _cl3.redirect_stderr(buf):
            out = nikto.read_xml(bad)
        self.assertEqual(out, [])
        self.assertIn("XML", buf.getvalue())

    def test_entity_expansion_neutralized(self):
        payload = (
            '<?xml version="1.0"?>\n'
            "<!DOCTYPE niktoscans [\n"
            '  <!ENTITY a "aaaaaaaaaa">\n'
            '  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
            '  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">\n'
            "]>\n"
            '<niktoscans><niktoscan><scandetails targetip="1.1.1.1" targetport="80">'
            '<item id="1" method="GET"><uri>&c;</uri>'
            "<references>CVE-2021-1</references></item></scandetails></niktoscan></niktoscans>"
        )
        # Must not hang or expand the entity; with DTD/entity resolution disabled
        # the undefined entity yields no findings.
        out = nikto.read_xml(payload)
        self.assertEqual(out, [])


class TestTokenRobustness(unittest.TestCase):
    def test_override_applies_with_trailing_punctuation(self):
        out = nikto.classify_references("CVE-2011-3392.")
        self.assertEqual(out["cve"], ["CVE-2002-0764"])

    def test_hardcode_applies_with_trailing_punctuation(self):
        out = nikto.classify_references("CA-2000-02:")
        self.assertEqual(out["taxonomy"], ["CWE-79"])


class TestNiktoMerger(unittest.TestCase):
    def test_merge_preserves_issues_key(self):
        merger = os.path.join(_HERE, "..", "templates", "nikto",
                              "multiple_nikto_issues.py")
        issue = {
            "tools": ["nikto"], "template": "multiple_nikto_issues",
            "severity": "high", "affects": ["http://h:80/a"],
            "taxonomy": ["CVE-2021-1"],
            "issues": {"http://h:80": [{"path": "/a", "cve": ["CVE-2021-1"], "msg": "m"}]},
        }
        env = dict(os.environ, MAGENTA_HOME=os.path.abspath(os.path.join(_HERE, "..")))
        p = subprocess.run(
            [_sys.executable, merger], input=json.dumps([issue]),
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertIn("issues", out)
        self.assertEqual(out["issues"]["http://h:80"][0]["cve"], ["CVE-2021-1"])


if __name__ == "__main__":
    unittest.main()
