import base64
import json
import os
import tempfile
import unittest
import zipfile
from xml.etree import ElementTree as ET

try:
    import pypandoc
    pypandoc.get_pandoc_version()
    PANDOC_AVAILABLE = True
except Exception:
    PANDOC_AVAILABLE = False

from libmagenta.dradis import markdown_to_dradis_textile
from libmagenta.dradis import (
    load_mapping,
    render_section_body,
    InvalidMappingError,
)
from libmagenta.dradis import build_repository_xml


@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestMarkdownToDradisTextile(unittest.TestCase):
    def test_intraword_underscore_not_escaped(self):
        # pandoc tends to write "pay\_Q5qo" — we want clean "pay_Q5qo"
        md = "Transaction id `pay_Q5qoUpiHgdmOF` was processed.\n"
        result = markdown_to_dradis_textile(md)
        self.assertNotIn("\\_", result)

    def test_ampersand_not_html_encoded(self):
        # pandoc's textile writer emits &amp; — we want literal &
        md = "Use Foo & Bar together.\n"
        result = markdown_to_dradis_textile(md)
        self.assertIn("&", result)
        self.assertNotIn("&amp;", result)

    def test_less_than_not_html_encoded(self):
        md = "If x < 5 then halt.\n"
        result = markdown_to_dradis_textile(md)
        self.assertNotIn("&lt;", result)

    def test_asterisk_in_code_not_escaped(self):
        md = "Use the `*` wildcard.\n"
        result = markdown_to_dradis_textile(md)
        # Either the asterisk survives literally or pandoc preserves it
        # inside the textile code span — but it must not be backslash-escaped
        self.assertNotIn("\\*", result)

    def test_link_list_survives(self):
        md = "- https://example.com/foo\n- https://example.org/bar\n"
        result = markdown_to_dradis_textile(md)
        self.assertIn("example.com", result)
        self.assertIn("example.org", result)

    def test_code_fence_block_preserved(self):
        md = "```\nfoo bar\nbaz\n```\n"
        result = markdown_to_dradis_textile(md)
        self.assertIn("foo bar", result)
        self.assertIn("baz", result)

    def test_simple_gfm_table_becomes_textile_table(self):
        md = "| Col A | Col B |\n|-------|-------|\n| a1    | b1    |\n| a2    | b2    |\n"
        result = markdown_to_dradis_textile(md)
        # Textile tables use pipe delimiters too — just check we have cell values
        # and that pandoc did NOT fall back to <table> HTML
        self.assertIn("a1", result)
        self.assertIn("b2", result)
        self.assertNotIn("<table", result)

    def test_multiline_table_cell_uses_textile_linebreak(self):
        # GFM cell with a <br>: depending on pandoc version, the output is
        # either a raw <table> HTML block (handled by _re_convert_html_table)
        # or a native Textile table with the <br> surviving inline (handled
        # by the _BR_PATTERN pass). Either way, the result must be valid
        # Textile — meaning the linebreak inside the cell must use Textile's
        # "\<newline>" escape, not a bare newline that would terminate the
        # row early.
        md = (
            "| Field | Notes |\n"
            "|-------|-------|\n"
            "| A     | line 1<br>line 2 |\n"
        )
        result = markdown_to_dradis_textile(md)
        self.assertNotIn("<table", result)
        self.assertNotIn("<br", result)
        self.assertIn("line 1", result)
        self.assertIn("line 2", result)
        # The key check: "line 2" must NOT start a new line at column 0 with
        # a bare newline before it — that would mean the table row was
        # terminated and "line 2" is now an orphan paragraph or new row.
        # Either form is acceptable:
        #   (a) Textile linebreak inside cell: "line 1\\\nline 2" (preferred)
        #   (b) Both lines kept on the same line with a separator
        # What's NOT acceptable: "line 1\nline 2" with a bare newline.
        self.assertNotIn("line 1\nline 2", result)

    def test_unsplit_double_backslash(self):
        # Pandoc may emit `\\` in some contexts — we want this collapsed to `\`
        md = "Path: `C:\\Users\\foo`\n"
        result = markdown_to_dradis_textile(md)
        # Either the backslashes are preserved literally inside code span,
        # or they're collapsed — but not doubled
        self.assertNotIn("\\\\\\\\", result)  # No quadrupled backslashes


class TestLoadMapping(unittest.TestCase):
    def test_loads_valid_mapping(self):
        mapping_text = """
{
  evidence_nodes: true,
  issue_sections: [{ name: "Title", value: "{{ title }}" }],
  evidence_sections: [{ name: "Location", value: "{{ affected }}" }],
  project_properties: { "k": "{{ x }}" },
}
"""
        with tempfile.NamedTemporaryFile("w", suffix=".json5", delete=False) as fd:
            fd.write(mapping_text)
            path = fd.name
        try:
            m = load_mapping(path)
            self.assertEqual(m["evidence_nodes"], True)
            self.assertEqual(len(m["issue_sections"]), 1)
            self.assertEqual(m["issue_sections"][0]["name"], "Title")
        finally:
            os.unlink(path)

    def test_missing_required_key_raises(self):
        # Missing evidence_nodes
        bad = '{ issue_sections: [], evidence_sections: [], project_properties: {} }'
        with tempfile.NamedTemporaryFile("w", suffix=".json5", delete=False) as fd:
            fd.write(bad)
            path = fd.name
        try:
            with self.assertRaises(InvalidMappingError):
                load_mapping(path)
        finally:
            os.unlink(path)

    def test_wrong_type_for_issue_sections_raises(self):
        bad = """
{ evidence_nodes: true, issue_sections: {}, evidence_sections: [],
  project_properties: {} }
"""
        with tempfile.NamedTemporaryFile("w", suffix=".json5", delete=False) as fd:
            fd.write(bad)
            path = fd.name
        try:
            with self.assertRaises(InvalidMappingError):
                load_mapping(path)
        finally:
            os.unlink(path)


class TestRenderSectionBody(unittest.TestCase):
    def test_simple_variable_substitution(self):
        result = render_section_body("{{ title }}", {"title": "SQL Injection"})
        self.assertEqual(result, "SQL Injection")

    def test_literal_string_passes_through(self):
        result = render_section_body("Internal | External", {})
        self.assertEqual(result, "Internal | External")

    def test_loop_over_list(self):
        ctx = {"references": ["https://a", "https://b"]}
        expr = "{% for url in references %}* {{ url }}\n{% endfor %}"
        result = render_section_body(expr, ctx)
        self.assertIn("* https://a", result)
        self.assertIn("* https://b", result)

    def test_missing_variable_yields_empty_string(self):
        # Jinja2 default behavior: undefined → empty when used in expression.
        # Our wrapper uses StrictUndefined? Let's pick lenient (empty) so a
        # missing field in one issue doesn't break the whole report.
        result = render_section_body("{{ missing }}", {})
        self.assertEqual(result, "")

    def test_jinja_raw_passes_through_unevaluated(self):
        # Liquid escape: {% raw %}...{% endraw %} should preserve content
        # verbatim so it survives into the Dradis output.
        expr = "{% raw %}{% assign x = 1 %}{% endraw %}"
        result = render_section_body(expr, {})
        self.assertIn("{% assign x = 1 %}", result)


def _minimal_mapping():
    """Bare mapping for XML structure tests — section bodies don't matter here."""
    return {
        "evidence_nodes": True,
        "issue_sections": [{"name": "Title", "value": "{{ title }}"}],
        "evidence_sections": [
            {"name": "Location", "value": "{{ affected }}"},
            {"name": "Output", "value": "{{ details }}"},
        ],
        "project_properties": {
            "dradis.productname": "{{ product_name }}",
            "dradis.businessunit": "{{ client_name }}",
        },
    }


def _minimal_report(issues=None):
    """Bare report dict for XML structure tests."""
    return {
        "metadata": {
            "project_info": {
                "product_name": "VoiceTools",
                "client_name": "Acme",
                "start_date": "2026-05-11",
                "end_date": "2026-05-15",
                "report_date": "2026-05-20",
                "test_type": "MPT",
                "report_team": "Magenta",
                "report_author": "tester@example.com",
            },
        },
        "issues": issues or [],
        "sections": {"issues": {}},
    }


@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestBuildRepositoryXmlSkeleton(unittest.TestCase):
    def test_root_element_is_dradis_template_v4(self):
        xml_str = build_repository_xml(_minimal_report(), _minimal_mapping())
        root = ET.fromstring(xml_str)
        self.assertEqual(root.tag, "dradis-template")
        self.assertEqual(root.attrib.get("version"), "4")

    def test_report_content_node_present_with_properties(self):
        xml_str = build_repository_xml(_minimal_report(), _minimal_mapping())
        root = ET.fromstring(xml_str)
        report_content = None
        for node in root.findall(".//nodes/node"):
            if node.findtext("label") == "Report content":
                report_content = node
                break
        self.assertIsNotNone(report_content, "Report content node missing")
        self.assertEqual(report_content.findtext("type-id"), "4")
        props_text = report_content.findtext("properties")
        self.assertIsNotNone(props_text)
        props = json.loads(props_text)
        self.assertEqual(props["dradis.productname"], "VoiceTools")
        self.assertEqual(props["dradis.businessunit"], "Acme")

    def test_empty_property_value_is_omitted(self):
        # If project_info lacks `client_name`, the dradis.businessunit key
        # should not appear in the JSON (not even with an empty string).
        report = _minimal_report()
        del report["metadata"]["project_info"]["client_name"]
        xml_str = build_repository_xml(report, _minimal_mapping())
        root = ET.fromstring(xml_str)
        for node in root.findall(".//nodes/node"):
            if node.findtext("label") == "Report content":
                props = json.loads(node.findtext("properties"))
                self.assertNotIn("dradis.businessunit", props)
                return
        self.fail("Report content node missing")

    def test_targets_node_with_per_host_children(self):
        report = _minimal_report(issues=[
            {"title": "X", "affects": ["host-a", "host-b"], "details": "",
             "description": "", "recommendations": "", "severity": "low",
             "taxonomy": [], "references": [], "tools": [], "vulnid": "1.1"},
            {"title": "Y", "affects": ["host-b", "host-c"], "details": "",
             "description": "", "recommendations": "", "severity": "low",
             "taxonomy": [], "references": [], "tools": [], "vulnid": "1.2"},
        ])
        xml_str = build_repository_xml(report, _minimal_mapping())
        root = ET.fromstring(xml_str)

        targets = None
        for node in root.findall(".//nodes/node"):
            if node.findtext("label") == "Targets":
                targets = node
                break
        self.assertIsNotNone(targets, "Targets node missing")
        targets_id = targets.findtext("id")

        # Find child nodes whose parent-id == targets_id
        children = [
            n for n in root.findall(".//nodes/node")
            if n.findtext("parent-id") == targets_id
        ]
        labels = sorted(n.findtext("label") for n in children)
        self.assertEqual(labels, ["host-a", "host-b", "host-c"])

    def test_empty_top_level_elements(self):
        xml_str = build_repository_xml(_minimal_report(), _minimal_mapping())
        root = ET.fromstring(xml_str)
        self.assertIsNotNone(root.find("tags"))
        self.assertIsNotNone(root.find("methodologies"))
        self.assertIsNotNone(root.find("categories"))

    def test_archive_ids_are_unique(self):
        report = _minimal_report(issues=[
            {"title": "X", "affects": ["a"], "details": "", "description": "",
             "recommendations": "", "severity": "low", "taxonomy": [],
             "references": [], "tools": [], "vulnid": "1.1"},
        ])
        xml_str = build_repository_xml(report, _minimal_mapping())
        root = ET.fromstring(xml_str)
        all_ids = [el.text for el in root.iter("id")]
        self.assertEqual(len(all_ids), len(set(all_ids)),
                         "Duplicate <id> values in archive: %r" % all_ids)


@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestBuildRepositoryXmlIssues(unittest.TestCase):
    def _report_with_one_issue(self):
        return {
            "metadata": {"project_info": {}},
            "issues": [{
                "title": "SQL Injection",
                "description": "The login form is vulnerable.",
                "recommendations": "Use parameterized queries.",
                "details": "The `username` parameter accepts SQL.",
                "severity": "high",
                "affects": ["api.example.com"],
                "taxonomy": [],
                "references": ["https://owasp.org/sqli"],
                "tools": [],
                "vulnid": "1.1",
            }],
            "sections": {"issues": {}},
        }

    def test_one_issue_emitted(self):
        mapping = _minimal_mapping()
        xml_str = build_repository_xml(self._report_with_one_issue(), mapping)
        root = ET.fromstring(xml_str)
        issues = root.findall("issues/issue")
        self.assertEqual(len(issues), 1)

    def test_issue_text_has_section_markers_in_order(self):
        mapping = {
            "evidence_nodes": False,
            "issue_sections": [
                {"name": "Title", "value": "{{ title }}"},
                {"name": "Description", "value": "{{ description }}"},
                {"name": "Solution", "value": "{{ recommendations }}"},
            ],
            "evidence_sections": [],
            "project_properties": {},
        }
        xml_str = build_repository_xml(self._report_with_one_issue(), mapping)
        root = ET.fromstring(xml_str)
        text = root.findtext("issues/issue/text")
        self.assertIsNotNone(text)
        # Markers must appear in the configured order
        title_idx = text.index("#[Title]#")
        desc_idx = text.index("#[Description]#")
        sol_idx = text.index("#[Solution]#")
        self.assertLess(title_idx, desc_idx)
        self.assertLess(desc_idx, sol_idx)
        # Bodies are populated
        self.assertIn("SQL Injection", text)
        self.assertIn("login form is vulnerable", text)
        self.assertIn("parameterized queries", text)

    def test_issue_has_required_fields(self):
        mapping = _minimal_mapping()
        report = self._report_with_one_issue()
        report["metadata"]["project_info"]["report_author"] = "alice@x.com"
        xml_str = build_repository_xml(report, mapping)
        root = ET.fromstring(xml_str)
        issue = root.find("issues/issue")
        self.assertEqual(issue.findtext("state"), "published")
        self.assertEqual(issue.findtext("author"), "alice@x.com")
        self.assertIsNotNone(issue.findtext("id"))

    def test_issue_author_falls_back_to_magenta(self):
        mapping = _minimal_mapping()
        report = self._report_with_one_issue()
        report["metadata"]["project_info"] = {}  # No report_author
        xml_str = build_repository_xml(report, mapping)
        root = ET.fromstring(xml_str)
        self.assertEqual(root.findtext("issues/issue/author"), "magenta")

    def test_empty_section_value_keeps_marker(self):
        # When a section's Jinja expression evaluates to empty (e.g. an issue
        # has no taxonomy and the value is a for-loop), the #[Section]#
        # marker is still emitted (matches the standard Dradis convention).
        mapping = {
            "evidence_nodes": False,
            "issue_sections": [
                {"name": "Title", "value": "{{ title }}"},
                {"name": "CVSSv4.BaseScore", "value": ""},
            ],
            "evidence_sections": [],
            "project_properties": {},
        }
        xml_str = build_repository_xml(self._report_with_one_issue(), mapping)
        text = ET.fromstring(xml_str).findtext("issues/issue/text")
        self.assertIn("#[CVSSv4.BaseScore]#", text)


@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestBuildRepositoryXmlEvidence(unittest.TestCase):
    def _two_host_report(self):
        return {
            "metadata": {"project_info": {"report_author": "tester@x.com"}},
            "issues": [{
                "title": "Open Port",
                "description": "Port is open.",
                "recommendations": "Close it.",
                "details": "Detected on port 22 via nmap.",
                "severity": "low",
                "affects": ["host-a", "host-b"],
                "taxonomy": [], "references": [], "tools": [],
                "vulnid": "1.1",
            }],
            "sections": {"issues": {}},
        }

    def test_evidence_nodes_true_emits_evidence_under_host(self):
        mapping = _minimal_mapping()  # evidence_nodes: True
        xml_str = build_repository_xml(self._two_host_report(), mapping)
        root = ET.fromstring(xml_str)

        host_a = None
        host_b = None
        for node in root.findall(".//nodes/node"):
            if node.findtext("label") == "host-a":
                host_a = node
            elif node.findtext("label") == "host-b":
                host_b = node
        self.assertIsNotNone(host_a)
        self.assertIsNotNone(host_b)

        evidence_a = host_a.findall("evidence/evidence")
        evidence_b = host_b.findall("evidence/evidence")
        self.assertEqual(len(evidence_a), 1)
        self.assertEqual(len(evidence_b), 1)

        # Each evidence content should reference its host
        self.assertIn("host-a", evidence_a[0].findtext("content"))
        self.assertIn("host-b", evidence_b[0].findtext("content"))

    def test_evidence_has_required_author_element(self):
        # dradis-projects v4 importer SKIPS evidence without an <author> element.
        # This is a load-bearing field for our archive to actually import.
        mapping = _minimal_mapping()
        xml_str = build_repository_xml(self._two_host_report(), mapping)
        root = ET.fromstring(xml_str)
        all_evidence = root.findall(".//nodes/node/evidence/evidence")
        self.assertEqual(len(all_evidence), 2)
        for ev in all_evidence:
            author = ev.findtext("author")
            self.assertIsNotNone(author, "<author> element required on every <evidence>")
            self.assertTrue(author.strip(), "<author> must not be empty")

    def test_evidence_issue_id_references_an_existing_issue(self):
        # <issue-id> must reference an archive ID that is the ID of one of
        # the <issue> elements in this document — otherwise the importer's
        # lookup_table[:issues][evidence.issue_id] will be nil.
        mapping = _minimal_mapping()
        xml_str = build_repository_xml(self._two_host_report(), mapping)
        root = ET.fromstring(xml_str)

        issue_ids = {issue.findtext("id") for issue in root.findall("issues/issue")}
        self.assertEqual(len(issue_ids), 1)

        for ev in root.findall(".//nodes/node/evidence/evidence"):
            ref = ev.findtext("issue-id")
            self.assertIsNotNone(ref, "<issue-id> element required on every <evidence>")
            self.assertIn(ref, issue_ids,
                          "<issue-id> %r does not match any <issue><id> in the document" % ref)

    def test_evidence_author_falls_back_to_magenta(self):
        mapping = _minimal_mapping()
        report = self._two_host_report()
        report["metadata"]["project_info"] = {}  # No report_author
        xml_str = build_repository_xml(report, mapping)
        root = ET.fromstring(xml_str)
        for ev in root.findall(".//nodes/node/evidence/evidence"):
            self.assertEqual(ev.findtext("author"), "magenta")

    def test_evidence_nodes_false_emits_no_evidence_items(self):
        mapping = _minimal_mapping()
        mapping["evidence_nodes"] = False
        xml_str = build_repository_xml(self._two_host_report(), mapping)
        root = ET.fromstring(xml_str)
        all_evidence_items = root.findall(".//nodes/node/evidence/evidence")
        self.assertEqual(
            len(all_evidence_items), 0,
            "evidence_nodes: false must not emit any <evidence><evidence> items"
        )

    def test_evidence_content_uses_section_markers(self):
        mapping = _minimal_mapping()
        xml_str = build_repository_xml(self._two_host_report(), mapping)
        root = ET.fromstring(xml_str)
        for node in root.findall(".//nodes/node"):
            if node.findtext("label") == "host-a":
                content = node.findtext("evidence/evidence/content")
                self.assertIn("#[Location]#", content)
                self.assertIn("#[Output]#", content)
                self.assertIn("host-a", content)
                self.assertIn("port 22", content)
                return
        self.fail("host-a evidence not found")


@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestChartAttachmentAndZip(unittest.TestCase):
    def _report_with_chart(self):
        # Minimal valid PNG header (8 bytes) — enough for the byte plumbing.
        png_bytes = b"\x89PNG\r\n\x1a\n"
        return {
            "metadata": {
                "project_info": {"product_name": "X"},
                "chart": base64.b64encode(png_bytes).decode("ascii"),
            },
            "issues": [],
            "sections": {"issues": {}},
        }

    def test_chart_node_present_when_chart_in_metadata(self):
        from libmagenta.dradis import build_repository_xml
        xml_str = build_repository_xml(self._report_with_chart(), _minimal_mapping())
        root = ET.fromstring(xml_str)
        labels = [n.findtext("label") for n in root.findall(".//nodes/node")]
        self.assertIn("Uploaded files", labels)

    def test_no_chart_node_when_chart_absent(self):
        from libmagenta.dradis import build_repository_xml
        xml_str = build_repository_xml(_minimal_report(), _minimal_mapping())
        root = ET.fromstring(xml_str)
        labels = [n.findtext("label") for n in root.findall(".//nodes/node")]
        self.assertNotIn("Uploaded files", labels)

    def test_package_zip_writes_xml_and_attachments(self):
        from libmagenta.dradis import package_zip
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as fd:
            zip_path = fd.name
        try:
            xml = "<?xml version=\"1.0\"?><dradis-template version=\"4\"/>"
            attachments = {"5/chart.png": b"\x89PNG\r\n\x1a\n"}
            package_zip(xml, attachments, zip_path)

            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()
                self.assertIn("dradis-repository.xml", names)
                self.assertIn("5/chart.png", names)
                with zf.open("dradis-repository.xml") as fd:
                    self.assertIn(b"dradis-template", fd.read())
                with zf.open("5/chart.png") as fd:
                    self.assertEqual(fd.read(), b"\x89PNG\r\n\x1a\n")
        finally:
            os.unlink(zip_path)

    def test_archive_chart_path_matches_uploaded_files_node_id(self):
        # The chart bytes folder name in the zip MUST match the archive
        # node id of the "Uploaded files" node. We test the helper that
        # produces both pieces of info in lockstep.
        from libmagenta.dradis import build_repository_xml_with_attachments
        report = self._report_with_chart()
        xml_str, attachments = build_repository_xml_with_attachments(
            report, _minimal_mapping()
        )
        root = ET.fromstring(xml_str)
        uploaded_node_id = None
        for n in root.findall(".//nodes/node"):
            if n.findtext("label") == "Uploaded files":
                uploaded_node_id = n.findtext("id")
                break
        self.assertIsNotNone(uploaded_node_id)
        # Attachment key uses that ID as the folder name
        expected_key = "%s/chart.png" % uploaded_node_id
        self.assertIn(expected_key, attachments)


@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed")
class TestExportAsDradisEngineMethod(unittest.TestCase):
    def test_export_writes_valid_zip(self):
        from libmagenta.engine import MagentaReporter

        # Build a synthetic `report` dict shaped like process_files() output.
        report = {
            "metadata": {
                "project_info": {
                    "product_name": "X",
                    "client_name": "Acme",
                    "report_author": "tester@example.com",
                    "start_date": "2026-01-01",
                    "end_date": "2026-01-05",
                    "report_date": "2026-01-10",
                    "test_type": "MPT",
                },
                "report_sections_order": [],
                "issue_subsections_order": [],
            },
            "issues": [{
                "title": "Test Issue",
                "description": "A description.",
                "recommendations": "A fix.",
                "details": "Detected on host.",
                "severity": "medium",
                "affects": ["host-1"],
                "taxonomy": [], "references": [], "tools": [],
                "vulnid": "1.1",
            }],
            "sections": {"issues": {}},
        }

        magenta_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # MagentaReporter() reads MAGENTA_HOME from the environment.
        # In normal operation magenta.py sets this; for tests we set it ourselves.
        os.environ.setdefault("MAGENTA_HOME", magenta_root)

        with tempfile.TemporaryDirectory() as tmp:
            out_zip = os.path.join(tmp, "out.zip")
            dradis_templates = os.path.join(magenta_root, "formats", "dradis")

            magenta = MagentaReporter()
            magenta.set_language("en")
            magenta.export_as_dradis(report, out_zip, dradis_templates)

            self.assertTrue(os.path.isfile(out_zip))
            with zipfile.ZipFile(out_zip) as zf:
                self.assertIn("dradis-repository.xml", zf.namelist())
                with zf.open("dradis-repository.xml") as fd:
                    xml_content = fd.read().decode("utf-8")
                root = ET.fromstring(xml_content)
                self.assertEqual(root.tag, "dradis-template")
                self.assertEqual(root.attrib["version"], "4")
                # Has our issue
                issues = root.findall("issues/issue")
                self.assertEqual(len(issues), 1)
