"""Dradis-specific output logic: textile cleanup, mapping evaluation,
XML repository builder, and ZIP packager.

The plain `textile` format does NOT use anything from this module — see
libmagenta/pandoc.py for that. Everything here is Dradis-flavored, including
the textile cleanup, which exists because Dradis renders raw HTML tables and
HTML-encoded entities less reliably than native Textile constructs.
"""

import base64
import html
import json
import os
import re
import zipfile
from xml.etree import ElementTree as ET

import jinja2
import jinja2.sandbox
import json5

from libmagenta.pandoc import convert_from_markdown

_HERE = os.path.dirname(os.path.abspath(__file__))
_LUA_FILTER = os.path.join(_HERE, "table_linebreak_fix_gfm.lua")


# Characters pandoc tends to escape but Dradis renders fine unescaped.
# This list is empirical — verify against the test fixtures and adjust.
# Order matters: process double-backslash before single-character escapes.
_BACKSLASH_ESCAPES_TO_STRIP = (
    ("\\\\", "\\"),
    ("\\_", "_"),
    ("\\*", "*"),
    ("\\[", "["),
    ("\\]", "]"),
    ("\\#", "#"),
    ("\\<", "<"),
    ("\\>", ">"),
    ("\\|", "|"),
    ("\\~", "~"),
    ("\\..", ".."),
)


_HTML_TABLE_PATTERN = re.compile(r"<table[\s\S]*?</table>", re.IGNORECASE)
_BR_PATTERN = re.compile(r"<br\s*/?>", re.IGNORECASE)


def _re_convert_html_table(html_table):
    """Convert a raw HTML <table>...</table> block back into Textile.

    Two-step pass: HTML → GFM (using the lua filter to coerce multi-line
    cells into a single line via the {{linebreak}} placeholder) → Textile.
    """
    import pypandoc

    gfm = pypandoc.convert_text(
        html_table,
        "gfm",
        format="html",
        extra_args=["--lua-filter=" + _LUA_FILTER],
    )
    # {{linebreak}} → textile line break syntax (`\` then newline)
    gfm = gfm.replace("{{linebreak}}", "\\\n")
    # GFM → Textile (standard wrapper, no extra cleanup)
    return convert_from_markdown(gfm, "textile")


def markdown_to_dradis_textile(md_text):
    """Convert GFM Markdown to Dradis-flavored Textile.

    Calls pandoc once, then applies three cleanup passes:
      1. Re-convert any raw <table>...</table> HTML blocks back to Textile.
      2. html.unescape() to undo entity encoding (&amp; -> &, etc.).
      3. Strip backslash-escapes that Dradis renders better without.
    """
    text = convert_from_markdown(md_text, "textile")

    # Pass 1: HTML tables
    def _replace(match):
        return _re_convert_html_table(match.group(0))

    text = _HTML_TABLE_PATTERN.sub(_replace, text)

    # Pass 1b: Inline <br> tags that survive as-is inside Textile table cells.
    # Modern pandoc may emit a native Textile table but leave <br> inline in
    # cell content. A bare "\n" mid-cell terminates the table row in Textile —
    # we need the Textile linebreak escape "\\\n" (backslash-newline), matching
    # what _re_convert_html_table does for the {{linebreak}} placeholder above.
    text = _BR_PATTERN.sub("\\\\\n", text)

    # Pass 2: HTML entities
    text = html.unescape(text)

    # Pass 3: backslash escapes
    for old, new in _BACKSLASH_ESCAPES_TO_STRIP:
        text = text.replace(old, new)

    return text


class InvalidMappingError(Exception):
    """Raised when the mapping.json5 file is malformed or missing required keys."""


_REQUIRED_KEYS = (
    "evidence_nodes",
    "issue_sections",
    "evidence_sections",
    "project_properties",
)


def load_mapping(path):
    """Load and validate a dradis mapping.json5 file.

    Raises InvalidMappingError if required keys are missing or have wrong types.
    Returns the parsed dict.
    """
    try:
        with open(path, "r", encoding="utf-8") as fd:
            mapping = json5.load(fd, allow_duplicate_keys=False)
    except FileNotFoundError:
        raise InvalidMappingError("mapping file not found: %s" % path)
    except Exception as exc:
        raise InvalidMappingError("could not parse %s: %s" % (path, exc))

    for key in _REQUIRED_KEYS:
        if key not in mapping:
            raise InvalidMappingError("missing required key '%s' in %s" % (key, path))

    if not isinstance(mapping["evidence_nodes"], bool):
        raise InvalidMappingError("'evidence_nodes' must be a boolean")
    if not isinstance(mapping["issue_sections"], list):
        raise InvalidMappingError("'issue_sections' must be a list")
    if not isinstance(mapping["evidence_sections"], list):
        raise InvalidMappingError("'evidence_sections' must be a list")
    if not isinstance(mapping["project_properties"], dict):
        raise InvalidMappingError("'project_properties' must be an object")
    for i, entry in enumerate(mapping["issue_sections"]):
        if not (isinstance(entry, dict) and "name" in entry and "value" in entry):
            raise InvalidMappingError(
                "issue_sections[%d] must be an object with 'name' and 'value' keys" % i
            )
    for i, entry in enumerate(mapping["evidence_sections"]):
        if not (isinstance(entry, dict) and "name" in entry and "value" in entry):
            raise InvalidMappingError(
                "evidence_sections[%d] must be an object with 'name' and 'value' keys"
                % i
            )
    return mapping


# Sandboxed Jinja2 environment for user-supplied expressions. SandboxedEnvironment
# blocks attribute access to underscored names and disallows calling unsafe
# methods, which mitigates "I downloaded someone else's mapping.json5 and now
# it's running shutil.rmtree" scenarios.
_JINJA_ENV = jinja2.sandbox.SandboxedEnvironment(
    autoescape=False,
    undefined=jinja2.Undefined,  # Missing vars render as empty, not an error
    keep_trailing_newline=True,
)


def render_section_body(expression, context):
    """Render a single Jinja2 expression from the mapping against a context dict.

    Returns the rendered string. Missing context variables render as empty
    strings rather than raising (so one malformed issue doesn't kill the run).
    """
    try:
        tpl = _JINJA_ENV.from_string(expression)
        return tpl.render(**context)
    except jinja2.TemplateSyntaxError as exc:
        raise InvalidMappingError(
            "syntax error in mapping expression %r: %s" % (expression, exc)
        )


class _IdAllocator:
    """Assigns sequential archive-local IDs starting at 1.

    Archive IDs only need to be unique within the zip — Dradis maps them
    to fresh DB IDs on import via lookup_table.
    """

    def __init__(self):
        self._next = 1

    def next(self):
        nid = self._next
        self._next += 1
        return nid


def _set_cdata(element, text):
    """ElementTree has no CDATA support out of the box. We use a sentinel
    placeholder + post-process the serialized XML in build_repository_xml.
    Each `text` payload is wrapped here; the post-processor substitutes
    the actual CDATA syntax."""
    # Insert a unique marker pair that the post-processor will find and
    # rewrite into <![CDATA[ ... ]]>. We use control characters that won't
    # legitimately appear in textile / JSON content.
    element.text = "\x01CDATA_OPEN\x01" + text + "\x01CDATA_CLOSE\x01"


def _cdata_post_process(xml_str):
    return xml_str.replace("\x01CDATA_OPEN\x01", "<![CDATA[").replace(
        "\x01CDATA_CLOSE\x01", "]]>"
    )


def _make_node(parent_el, ids, label, type_id, parent_id=None, properties=None):
    """Emit a <node> with the standard set of children Dradis expects."""
    node = ET.SubElement(parent_el, "node")
    ET.SubElement(node, "id").text = str(ids.next())
    ET.SubElement(node, "label").text = label
    pid = ET.SubElement(node, "parent-id")
    if parent_id is not None:
        pid.text = str(parent_id)
    ET.SubElement(node, "position").text = "0"
    props_el = ET.SubElement(node, "properties")
    _set_cdata(props_el, properties if properties is not None else "{\n}")
    ET.SubElement(node, "type-id").text = str(type_id)
    ET.SubElement(node, "notes")
    ET.SubElement(node, "evidence")
    ET.SubElement(node, "activities")
    return node


def _build_project_properties_json(mapping, project_info):
    """Evaluate each project_properties expression and return a JSON string.

    Keys that evaluate to an empty string are omitted entirely (not emitted
    as empty-string values).
    """
    out = {}
    for key, expr in mapping["project_properties"].items():
        value = render_section_body(expr, project_info or {}).strip()
        if value:
            out[key] = value
    # Mimic the format we observed in tmp/dradis-export/dradis-repository.xml:
    # multi-line indented JSON inside the CDATA.
    return (
        "{\n"
        + ",\n".join('  "%s": %s' % (k, json.dumps(v)) for k, v in out.items())
        + "\n}"
    )


def _unique_hosts(issues):
    seen = set()
    out = []
    for issue in issues:
        for host in issue.get("affects", []):
            if host not in seen:
                seen.add(host)
                out.append(host)
    return out


def _render_issue_text(issue_data, mapping):
    """Build the #[Section]#-marker textile body for one issue.

    Each issue_sections entry is evaluated as a Jinja2 expression against the
    per-issue context, then Markdown->Textile-converted with Dradis cleanup.
    Sections that evaluate to empty still emit their marker (no body).
    """
    parts = []
    for entry in mapping["issue_sections"]:
        name = entry["name"]
        expr = entry["value"]
        body_md = render_section_body(expr, issue_data)
        if body_md.strip():
            body_textile = markdown_to_dradis_textile(body_md).strip()
            parts.append("#[%s]#\n%s\n" % (name, body_textile))
        else:
            parts.append("#[%s]#\n" % name)
    return "\n".join(parts)


def _render_evidence_content(issue_data, affected, mapping):
    """Build the #[Section]#-marker textile body for one evidence entry.

    Context = issue dict + `affected` = the host string for this evidence.
    """
    ctx = dict(issue_data)
    ctx["affected"] = affected
    parts = []
    for entry in mapping["evidence_sections"]:
        name = entry["name"]
        expr = entry["value"]
        body_md = render_section_body(expr, ctx)
        if body_md.strip():
            body_textile = markdown_to_dradis_textile(body_md).strip()
            parts.append("#[%s]#\n%s\n" % (name, body_textile))
        else:
            parts.append("#[%s]#\n" % name)
    return "\n".join(parts)


def _build_evidence_element(
    host_node, ids, issue_data, affected, mapping, issue_archive_id, author
):
    """Append an <evidence> item to host_node's <evidence> container.

    The dradis-projects v4 importer expects:
      - <author> (REQUIRED — items without it are silently dropped)
      - <content> (CDATA, the textile body)
      - <issue-id> (cross-reference to an <issue><id> elsewhere in the document)
    """
    evidence_parent = host_node.find("evidence")
    ev = ET.SubElement(evidence_parent, "evidence")
    ET.SubElement(ev, "id").text = str(ids.next())
    ET.SubElement(ev, "author").text = author
    content_el = ET.SubElement(ev, "content")
    _set_cdata(content_el, _render_evidence_content(issue_data, affected, mapping))
    ET.SubElement(ev, "issue-id").text = str(issue_archive_id)
    return ev


def _build_issue_element(parent_el, archive_id, issue_data, mapping, fallback_author):
    issue_el = ET.SubElement(parent_el, "issue")
    ET.SubElement(issue_el, "id").text = str(archive_id)
    ET.SubElement(issue_el, "author").text = fallback_author
    ET.SubElement(issue_el, "state").text = "published"
    text_el = ET.SubElement(issue_el, "text")
    _set_cdata(text_el, _render_issue_text(issue_data, mapping))
    return issue_el


def build_repository_xml(report, mapping):
    """XML-only entry point (chart attachment is silently dropped). Kept
    for tests; production code should use build_repository_xml_with_attachments."""
    xml_str, _ = build_repository_xml_with_attachments(report, mapping)
    return xml_str


def build_repository_xml_with_attachments(report, mapping):
    """Build the dradis-repository.xml AND collect attachment payloads.

    Returns (xml_str, attachments) where attachments is a dict mapping
    "<archive-node-id>/<filename>" to raw bytes. The caller writes both
    into the zip at the right paths.
    """
    ids = _IdAllocator()
    attachments = {}

    # Pre-allocate archive IDs for issues so evidence can cross-reference
    # them via <issue-id>. Evidence is emitted before issues in the XML
    # document, so the IDs must be known ahead of time.
    issue_archive_ids = {}
    for issue_data in report["issues"]:
        issue_archive_ids[id(issue_data)] = ids.next()

    root = ET.Element("dradis-template", attrib={"version": "4"})
    nodes_el = ET.SubElement(root, "nodes")

    # 1. "Report content" node (type-id=4)
    props_json = _build_project_properties_json(
        mapping, report["metadata"].get("project_info", {})
    )
    _make_node(nodes_el, ids, "Report content", type_id=4, properties=props_json)

    # 2. "Targets" node and one child per unique affected host
    targets_node = _make_node(nodes_el, ids, "Targets", type_id=0)
    targets_id = targets_node.findtext("id")
    host_nodes = {}
    for host in _unique_hosts(report["issues"]):
        host_nodes[host] = _make_node(
            nodes_el, ids, host, type_id=0, parent_id=int(targets_id)
        )

    project_info = report["metadata"].get("project_info", {})
    fallback_author = project_info.get("report_author") or "magenta"

    if mapping["evidence_nodes"]:
        for issue_data in report["issues"]:
            archive_id = issue_archive_ids[id(issue_data)]
            for host in issue_data.get("affects", []):
                host_node = host_nodes.get(host)
                if host_node is None:
                    continue
                _build_evidence_element(
                    host_node,
                    ids,
                    issue_data,
                    host,
                    mapping,
                    archive_id,
                    fallback_author,
                )

    # 3. Chart node (only when metadata.chart is present)
    chart_b64 = report["metadata"].get("chart")
    if chart_b64:
        chart_node = _make_node(nodes_el, ids, "Uploaded files", type_id=0)
        chart_node_id = chart_node.findtext("id")
        attachments["%s/chart.png" % chart_node_id] = base64.b64decode(chart_b64)

    # 4. Issues
    issues_el = ET.SubElement(root, "issues")
    for issue_data in report["issues"]:
        archive_id = issue_archive_ids[id(issue_data)]
        _build_issue_element(
            issues_el, archive_id, issue_data, mapping, fallback_author
        )

    # 5. Empty top-level elements
    ET.SubElement(root, "tags")
    ET.SubElement(root, "methodologies")
    ET.SubElement(root, "categories")

    raw = ET.tostring(root, encoding="utf-8").decode("utf-8")
    xml_str = '<?xml version="1.0" encoding="UTF-8"?>' + _cdata_post_process(raw)
    return xml_str, attachments


def package_zip(repository_xml, attachments, output_path):
    """Write the dradis project package zip to output_path.

    attachments is a dict of archive paths -> bytes (e.g. {"5/chart.png": b"..."}).
    """
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("dradis-repository.xml", repository_xml)
        for path, content in attachments.items():
            zf.writestr(path, content)
