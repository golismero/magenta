#!/usr/bin/python3

import base64
import copy
import fnmatch
import json
import jsonschema  # tried using fastjsonschema but saw literally no change in speed :(
import marshal
import os
import os.path
import re
import subprocess
import sys
import traceback
import urllib.parse
import uuid

import json5

import matplotlib.pyplot as plt
import numpy as np

from io import BytesIO

from .template import (
    DynAutoEscapeEnvironment,
    escapehtml,
    escapemd,
    http2md,
    CustomTemplateLoader,
)

######################################################################################################################


class FileCache:
    def __init__(self, pathname):
        self.pathname = pathname
        self.cache = {}
        self.dirty = False
        self.load()

    def __del__(self):
        self.save()

    def load(self):
        if self.pathname:
            try:
                with open(self.pathname, "rb") as fd:
                    self.cache = marshal.load(fd)
            except Exception:
                if os.path.exists(self.pathname):
                    os.unlink(self.pathname)

    def save(self):
        if self.dirty:
            try:
                with open(self.pathname, "wb") as fd:
                    marshal.dump(self.cache, fd)
            except Exception:
                pass

    def get(self, filename):
        if self.pathname and filename in self.cache:
            last_modified = os.path.getmtime(filename)
            timestamp, data = self.cache[filename]
            if timestamp >= last_modified:
                return copy.deepcopy(data)

    def put(self, filename, data):
        if self.pathname:
            timestamp = os.path.getmtime(filename)
            self.cache[filename] = (timestamp, copy.deepcopy(data))
            self.dirty = True


class MagentaReporter:
    RE_NAME = re.compile(r"^[a-zA-Z0-9_\\-]+$")

    SEVERITY_KEYS = ["none", "low", "medium", "high", "critical"]

    DEFAULT_CONFIG = {
        "python_executable": sys.executable,
        "parsers_directory": "parsers",
        "templates_directory": "templates",
        "internal_cache": ".magenta.cache",
    }

    DEFAULT_METADATA = {
        "min_severity": "none",
        "chart_type": "pie",
        "show_empty_summary": False,
        "show_empty_chart": False,
        "severity_colors": {  # https://htmlcolorcodes.com/colors/
            "none": "#87CEEB",  # Sky Blue
            "low": "#FFBF00",  # Amber
            "medium": "#EC5800",  # Persimon
            "high": "#D2042D",  # Cherry
            "critical": "#9F2B68",  # Amaranth
        },
        "report_sections_order": ["header", "summary", "tools", "issues", "notes"],
        "issue_subsections_order": [
            "severity",
            "affects",
            "description",
            "details",
            "recommendations",
            "tools",
            "taxonomy",
            "references",
        ],
    }

    SCHEMA_CONFIG = {
        "$schema": "https://json-schema.org/draft/2019-09/schema",
        "type": "object",
        "properties": {
            "default_language": {"type": "string"},
            "python_executable": {"type": "string"},
            "parsers_directory": {"type": "string"},
            "templates_directory": {"type": "string"},
        },
        "additionalProperties": False,
    }

    SCHEMA_METADATA = {
        "$schema": "https://json-schema.org/draft/2019-09/schema",
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "language": {"type": "string"},
            "min_severity": {"enum": list(SEVERITY_KEYS)},
            "chart_type": {"enum": ["none", "pie", "bars"]},
            "show_empty_summary": {"type": "boolean"},
            "show_empty_chart": {"type": "boolean"},
            "severity_colors": {
                "type": "object",
                "properties": {
                    key: {
                        "type": "string",
                        "pattern": "^#[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]$",
                    }
                    for key in SEVERITY_KEYS
                },
            },
            "report_sections_order": {
                "type": "array",
                "items": {"enum": ["header", "summary", "tools", "issues", "notes"]},
            },
            "issue_subsections_order": {
                "type": "array",
                "items": {
                    "enum": [
                        "severity",
                        "affects",
                        "taxonomy",
                        "description",
                        "details",
                        "recommendations",
                        "tools",
                        "references",
                    ]
                },
            },
            "project_info": {
                "type": "object",
                "properties": {
                    "report_team": {"type": "string"},  # Your company or team
                    "report_author": {"type": "string"},  # Your name
                    "client_name": {"type": "string"},  # The client company
                    "product_name": {"type": "string"},  # The product being pentested
                    "test_type": {"type": "string"},  # Kind of pentest
                    "start_date": {"type": "string"},  # Start of testing window
                    "end_date": {"type": "string"},  # End of testing window
                    "report_date": {"type": "string"},  # When the report is due
                },
                "required": [
                    "report_team",
                    "report_author",
                    "client_name",
                    "product_name",
                    "test_type",
                    "start_date",
                    "end_date",
                    "report_date",
                ],
            },
        },
        "additionalProperties": False,
    }

    SCHEMA_PARSER = {
        "$schema": "https://json-schema.org/draft/2019-09/schema",
        "type": "object",
        "properties": {
            "hidden": {"type": "boolean"},
            "status": {"enum": ["production", "testing", "development"]},
            "name": {"type": "string"},
            "url": {"type": "string", "pattern": "^https?://"},
            "description": {
                "type": "object",
                "additionalProperties": {"type": "string"},
            },
        },
        "if": {"properties": {"hidden": {"const": False}}},
        "then": {"required": ["url", "description"]},
        "additionalProperties": False,
    }

    SCHEMA_TEMPLATE = {
        "$schema": "https://json-schema.org/draft/2019-09/schema",
        "type": "object",
        "properties": {
            "summary": {"type": "string", "pattern": "^[^\\r\\n]*$"},
            "references": {
                "type": "array",
                "items": {"type": "string", "pattern": "^https?://"},
            },
            "taxonomy": {"type": "array", "items": {"type": "string", "minLength": 3}},
        },
        "additionalProperties": {"type": "string"},
        "required": ["title", "summary", "description", "recommendations", "details"],
    }

    SCHEMA_MAIN_TEMPLATE = {
        "$schema": "https://json-schema.org/draft/2019-09/schema",
        "type": "object",
        "additionalProperties": {"type": "string"},
    }

    def __init__(self, config=None):
        # Parse the configuration file.
        self.home = os.path.abspath(os.environ["MAGENTA_HOME"])
        assert os.path.isdir(self.home), (
            "Invalid 'MAGENTA_HOME' environment variable: '%s'" % self.home
        )
        if config is None:
            self.config = self.DEFAULT_CONFIG
        else:
            self.config = self._parse_config(config)

        # Initialize to an empty internal state.
        self.language = None
        self.parsers = None
        self.templates = None
        self.env = None

        # Load the file cache.
        self.cache = FileCache(self.config.get("internal_cache", None))

        # Find the mergers. These don't depend on language.
        self.mergers = self._find_mergers()

        # Find the schemas. These don't depend on language.
        self.schemas = self._find_schemas()

        # Auto initialize using the default language, if any was given.
        # Otherwise leave an empty internal state.
        # You can switch languages later using set_language().
        self.set_language(self.config.get("default_language", None))

    def set_language(self, language):
        # Switching to None will reset the internal state.
        if not language:
            self.language = None
            self.parsers = None
            self.templates = None
            self.env = None

        # Ignore attempts to switch to the currently loaded language.
        if self.language == language:
            return

        # Ensure we are left with a consistent internal state in case of errors.
        previous_state = (self.language, self.parsers, self.templates, self.env)
        try:
            # Switch to the new language.
            self.language = language

            # Find the parsers, getting the metadata for the requested language.
            self.parsers = self._find_parsers(language)

            # Find the templates for the requested language.
            self.templates = self._find_templates(language)

            # Prepare the Jinja environment.
            self.env = DynAutoEscapeEnvironment(
                autoescape=True,
                escape_func=escapemd,
                loader=CustomTemplateLoader(self),
                extensions=["jinja2.ext.loopcontrols"],
            )
            self.env.policies["urlize.extra_schemes"] = "data:"
            self.env.policies["urlize.rel"] = "nofollow noopener"
            self.env.filters["b64decode"] = lambda s: base64.b64decode(s).decode(
                "utf-8", "ignore"
            )
            self.env.filters["escapemd"] = escapemd
            self.env.filters["escapehtml"] = escapehtml
            self.env.filters["http2md"] = http2md

        # In case of errors, restore the previous state.
        except:
            (self.language, self.parsers, self.templates, self.env) = previous_state
            raise

    # Parse the configuration file.
    def _parse_config(self, filename="magenta.json5"):
        if not os.path.isabs(filename):
            filename = os.path.join(self.home, filename)
        with open(filename, "r") as fd:
            config = json5.load(fd, allow_duplicate_keys=False)
        jsonschema.validate(config, self.SCHEMA_CONFIG)
        for key, value in self.DEFAULT_CONFIG.items():
            if key not in config:
                config[key] = value
        return config

    # Parse all JSON5 files in the parsers directory and return a dictionary of parsers.
    def _find_parsers(self, language):
        # Get the parsers directory from the configuration.
        path = self.config["parsers_directory"]
        path = os.path.join(self.home, path)
        assert os.path.commonpath((self.home, path)) == self.home, (
            "Invalid parsers_directory ('%s') lies outside of MAGENTA_HOME ('%s')"
            % (path, self.home)
        )

        # Go through the parsers directory recursively looking for JSON5 files.
        parsers = dict()
        for root, dirs, files in os.walk(path):
            for name in fnmatch.filter(files, "*.json5"):
                filename = os.path.join(root, name)

                # Get the parsed JSON5 data from the cache, if available.
                # If not, parse the JSON5 file and validate the schema.
                data = self.cache.get(filename)
                if data is None:
                    with open(filename, "r") as fd:
                        data = json5.load(fd, allow_duplicate_keys=False)
                    jsonschema.validate(data, self.SCHEMA_PARSER)
                    self.cache.put(filename, data)

                # The tool name is derived from the filename.
                tool = os.path.splitext(name)[0]
                data["tool"] = tool

                # The parser script is derived from the filename.
                entrypoint = os.path.join(root, tool + ".py")
                assert os.path.exists(entrypoint), (
                    "Entrypoint for parser '%s' not found: '%s'" % (tool, entrypoint)
                )
                data["entrypoint"] = os.path.relpath(entrypoint, start=self.home)

                # The default human readable name is derived from the tool name.
                if "name" not in data:
                    data["name"] = tool.capitalize()

                # Make sure we don't have duplicated tools.
                assert tool not in parsers, "Duplicated parser '%s' in file %s" % (
                    tool,
                    filename,
                )

                # The default development status is "development".
                if "status" not in data or not data["status"]:
                    data["status"] = "development"

                # Default state is not hidden.
                if "hidden" not in data:
                    data["hidden"] = False

                # Validate the tool URL.
                try:
                    urllib.parse.urlparse(data["url"])
                except Exception:
                    raise AssertionError("Malformed reference URL: '%s'" % data["url"])

                # Remove the descriptions for other languages.
                assert language in data["description"], (
                    "Language '%s' not found in metadata for tool '%s'"
                    % (language, tool)
                )
                data["description"] = data["description"][language]

                # Collect the parser's data in a dictionary.
                parsers[tool] = data

                # Clean up the old values so they don't show up on tracebacks.
                data = None
                entrypoint = None

        # Return the parsers dictionary.
        return parsers

    # Parse all Python files in the templates directory and return a dictionary of mergers.
    def _find_mergers(self):
        # Get the templates directory from the configuration.
        path = self.config["templates_directory"]
        path = os.path.join(self.home, path)
        assert os.path.commonpath((self.home, path)) == self.home, (
            "Invalid templates_directory ('%s') lies outside of MAGENTA_HOME ('%s')"
            % (path, self.home)
        )

        # Go through the templates directory recursively looking for Python files.
        mergers = dict()
        for root, dirs, files in os.walk(path):
            for name in fnmatch.filter(files, "*.py"):
                filename = os.path.join(root, name)

                # The template name is derived from the filename.
                template_name = os.path.splitext(name)[0]
                assert self.RE_NAME.match(template_name), (
                    "Invalid name '%s' for template found in file '%s'"
                    % (template_name, filename)
                )

                # Add the merger script to the dictionary, unless it's the main script.
                if template_name != "main":
                    mergers[template_name] = os.path.relpath(filename, start=self.home)

        # Return the mergers.
        return mergers

    # Parse all JSON Schema files in the templates directory and return a dictionary of schemas.
    def _find_schemas(self):
        # Get the templates directory from the configuration.
        path = self.config["templates_directory"]
        path = os.path.join(self.home, path)
        assert os.path.commonpath((self.home, path)) == self.home, (
            "Invalid templates_directory ('%s') lies outside of MAGENTA_HOME ('%s')"
            % (path, self.home)
        )

        # Go through the templates directory recursively looking for JSON Schema files.
        schemas = dict()
        for root, dirs, files in os.walk(path):
            for name in fnmatch.filter(files, "*.schema.json"):
                filename = os.path.join(root, name)

                # The template name is derived from the filename.
                template_name = os.path.splitext(os.path.splitext(name)[0])[0]
                assert self.RE_NAME.match(template_name), (
                    "Invalid name '%s' for template found in file '%s'"
                    % (template_name, filename)
                )

                # Load the JSON schema.
                schema = self.cache.get(filename)
                if schema is None:
                    with open(filename, "r") as fd:
                        schema = json.load(fd)
                    self.cache.put(filename, schema)

                # Save the JSON schema in the dictionary.
                schemas[template_name] = schema

        # Return the schemas.
        return schemas

    # Parse all JSON5 files in the templates directory and return a dictionary of templates.
    def _find_templates(self, language):
        # Get the templates directory from the configuration.
        path = self.config["templates_directory"]
        path = os.path.join(self.home, path)
        assert os.path.commonpath((self.home, path)) == self.home, (
            "Invalid templates_directory ('%s') lies outside of MAGENTA_HOME ('%s')"
            % (path, self.home)
        )

        # Go through the templates directory recursively looking for JSON5 files.
        templates = dict()
        for root, dirs, files in os.walk(path):
            for name in fnmatch.filter(files, "*.json5"):
                filename = os.path.join(root, name)

                # The template name and language are derived from the filename.
                # The default language is English, so it can be ommitted.
                template_name = os.path.splitext(name)[0]
                if os.path.extsep in template_name:
                    template_name, template_language = os.path.splitext(template_name)
                    template_language = template_language[len(os.path.extsep) :]
                else:
                    template_language = "en"
                assert self.RE_NAME.match(template_name), (
                    "Invalid name '%s' for template found in file '%s'"
                    % (template_name, filename)
                )

                # Skip the languages we don't need.
                if template_language != language:
                    continue

                # Get the parsed JSON5 data from the cache, if available.
                # If not, parse the JSON5 file.
                filename = os.path.join(root, name)
                data = self.cache.get(filename)
                if data is None:
                    with open(filename, "r") as fd:
                        data = json5.load(fd, allow_duplicate_keys=False)
                    self.cache.put(filename, data)

                    # Some basic sanity checks.
                    # We need to treat the "main" template as a special case, though.
                    if template_name == "main":
                        jsonschema.validate(data, self.SCHEMA_MAIN_TEMPLATE)
                    else:
                        jsonschema.validate(data, self.SCHEMA_TEMPLATE)
                        if "references" in data:
                            for url in data["references"]:
                                try:
                                    urllib.parse.urlparse(url)
                                except Exception:
                                    raise AssertionError(
                                        "Malformed reference URL: '%s'" % url
                                    )
                    assert template_name not in templates, (
                        "Duplicated template '%s' in file '%s'"
                        % (template_name, filename)
                    )

                # Save the sanitized template data.
                templates[template_name] = data

        # Return the templates.
        return templates

    # ----------------------------------------------------------------------------------------------------------------#

    # Validate an issue object using the corresponding JSON schema.
    def validate_issue(self, issue):
        # print(issue)    # XXX DEBUG
        jsonschema.validate(issue, self.schemas["main"])
        assert issue["template"] != "main", "Cannot use 'main' template for an issue"
        assert issue["template"] in self.schemas, (
            "Unsupported issue template '%s'" % issue["template"]
        )
        jsonschema.validate(issue, self.schemas[issue["template"]])
        if "references" in issue:
            for url in issue["references"]:
                try:
                    urllib.parse.urlparse(url)
                except Exception:
                    raise AssertionError("Malformed reference URL: '%s'" % url)
        issue["affects"] = sorted(issue["affects"])
        if "tqxonomy" in issue:
            issue["taxonomy"] = sorted(issue["taxonomy"])
        if "references" in issue:
            issue["references"] = sorted(issue["references"])

    # Validate and sanitize the report metadata.
    def parse_metadata(self, metadata=None):
        # Shortcut for when the default metadata is used.
        if metadata is None:
            return self.DEFAULT_METADATA
        if metadata is self.DEFAULT_METADATA:
            return metadata

        # Validate the schema.
        jsonschema.validate(metadata, self.SCHEMA_METADATA)

        # Get missing properties from the default.
        # This also produces a copy of the object,
        # to avoid modifying the one from the caller.
        copy = dict()
        for propname in list(self.DEFAULT_METADATA.keys()):
            if propname in metadata:
                if propname == "severity_colors":
                    severity_colors = dict(metadata["severity_colors"])
                    for propname, propvalue in self.DEFAULT_METADATA[
                        "severity_colors"
                    ].items():
                        if propname not in severity_colors:
                            severity_colors[propname] = propvalue
                    copy["severity_colors"] = severity_colors
                else:
                    copy[propname] = metadata[propname]
            else:
                copy[propname] = self.DEFAULT_METADATA[propname]
        for propname in list(metadata.keys()):
            if propname not in self.DEFAULT_METADATA:
                copy[propname] = metadata[propname]
        metadata = copy

        # Return a copy of the sanitized metadata.
        return metadata

    # Try to generate a URL for a taxonomy tag. Returns None if not known.
    #
    # The following taxonomies are supported:
    #   - MITRE Common Vulnerabilities and Exposures (CVE)
    #   - MITRE Common Weakness Enumeration (CWE)
    #   - MITRE Common Attack Pattern Enumeration and Classification (CAPEC)
    #   - Chinese National Vulnerability Database (CNVD)
    #   - Japanese Vulnerability Database (JVNDB)
    #   - Russian Federation Data Bank of Information Security Threats (BDU)
    #   - Ubuntu Security Notices (USN)
    #   - Red Hat Security Announcements (RHSA)
    #   - Debian Security Announcements (DSA)
    #   - Microsoft Knowledge Base (KB)
    #   - Microsoft Security Bulletins (MS)
    #   - Mozilla Foundation Security Advisories (MFSA)
    #   - WPScan Wordpress Vulnerability Database (WPVDB)
    #   - Exploit DB
    #   - 1337 Day DB
    #   - Vulners Security Database
    #   - Open Bug Bounty Reports
    #   - IETF Request For Comments (RFC)
    #
    @staticmethod
    def url_from_tag(tag):
        assert tag == tag.upper()

        # Implementation note: one might be tempted to change this into anything
        # that's more elegant than this spaghetti of "if" statements.
        #
        # HOWEVER.
        #
        # Upon reflection you'll realize that anything more "elegant" than this
        # is also more complex and harder to maintain and debug. So this is the
        # correct solution.
        #
        # You may not like it but his is what peak code looks like. #dealwithit

        url = None
        if tag.startswith("CVE-"):
            url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + tag
        elif tag.startswith("CWE-"):
            url = "https://cwe.mitre.org/data/definitions/" + tag[4:] + ".html"
        elif tag.startswith("CAPEC-"):
            url = "https://capec.mitre.org/data/definitions/" + tag[6:] + ".html"
        elif tag.startswith("CNVD-"):
            url = "https://www.cnvd.org.cn/flaw/show/" + tag
        elif tag.startswith("JVNDB-"):
            url = "https://jvndb.jvn.jp/ja/contents/" + tag[6:10] + "/" + tag + ".html"
        elif tag.startswith("JVN"):
            url = "https://jvn.jp/jp/" + tag + "/index.html"
        elif tag.startswith("BDU:"):
            url = "https://bdu.fstec.ru/vul/" + tag[4:]
        elif tag.startswith("USN-"):
            url = "https://ubuntu.com/security/notices/" + tag[4:]
        elif tag.startswith("RHSA-"):
            url = "https://access.redhat.com/errata/" + tag
        elif tag.startswith("DSA-"):
            url = "https://www.debian.org/security/" + tag.lower()
        elif tag.startswith("KB"):
            url = "https://support.microsoft.com/kb/" + tag[2:]
        elif tag.startswith("MS"):
            url = (
                "https://docs.microsoft.com/en-us/security-updates/securitybulletins/20"
                + tag[2:4]
                + "/"
                + tag.lower()
            )
        elif tag.startswith("MFSA"):
            url = (
                "https://www.mozilla.org/en-US/security/advisories/" + tag.lower() + "/"
            )
        elif tag.startswith("WPVDB-ID:"):
            url = "https://wpscan.com/vulnerability/" + tag[9:].lower() + "/"
        elif tag.startswith("EDB-ID:"):
            url = "https://www.exploit-db.com/exploits/" + tag[7:]
        elif tag.startswith("1337DAY-ID-"):
            url = "https://0day.today/exploit/" + tag[11:]
        elif tag.startswith("GITHUBEXPLOIT:"):
            url = "https://vulners.com/githubexploit/" + tag[14:]
        elif tag.startswith("OSV:"):
            url = "https://vulners.com/osv/" + tag
        elif tag.startswith("PACKETSTORM:"):
            url = "https://vulners.com/packetstorm/" + tag
        elif tag.startswith("PATCHSTACK:"):
            url = "https://vulners.com/patchstack/" + tag
        elif tag.startswith("SECURITYVULNS:DOC:"):
            url = "https://vulners.com/securityvulns/" + tag
        elif tag.startswith("WPEX-ID:"):
            url = "https://vulners.com/wpexploit/" + tag
        elif tag.startswith("OBB-"):
            url = "https://www.openbugbounty.org/reports/" + tag[4:] + "/"
        elif tag.startswith("RFC "):
            url = "https://datatracker.ietf.org/doc/html/" + tag[:3].lower() + tag[4:]
        if url:
            try:
                urllib.parse.urlparse(url)
            except Exception:
                raise AssertionError("Malformed reference URL: '%s'" % url)
        return url

    # Issues are reported using subsections. These are the supported sections:
    #
    # Title:
    #  Single line with the title of the issue.
    #
    # Severity:
    #  Integer representing the severity level: LOW (0), MEDIUM (1), HIGH (2), CRITICAL (3)
    #
    # Summary:
    #  Single paragraph with a short summary of the issue.
    #
    # Taxonomy:
    #  List of taxonomy tags, such as CVE or CWE for example.
    #
    # Affects:
    #  List of affected resources.
    #
    # Description:
    #  Multiple paragraphs with a longer description of the issue type.
    #
    # Recommendations:
    #  Multiple paragraphs with a list of recommendations for this type of issue.
    #
    # References:
    #  List of links with external references.
    #
    # Details:
    #  Multiple paragraphs with a detailed description of this instance of the issue.
    #
    def render_issue(self, metadata, issue):
        template = issue["template"]
        src = self.templates[template]

        # We're producing a dictionary for each subsection within the issue.
        sections = {}

        # We need to make a copy of the issue object in order to make some changes.
        # We don't want to affect the original object passed by the caller.
        issue = copy.deepcopy(issue)

        # We need to know which sections need to be rendered.
        # Note that we render title always, minus the vulnerability ID.
        # The vulnerability ID is added by the caller, we can't know it here.
        issue_subsections = set(metadata["issue_subsections_order"])
        issue_subsections.add("title")

        # For the tools subsection, we need the parsers metadata instead of just the names.
        if "tools" in issue_subsections:
            parsers = self.parsers
            tools = sorted(
                (parsers[name]["name"], name, parsers[name])
                for name in set(issue["tools"])
            )
            tools = [t for _, _, t in tools]
            issue["tools"] = tools

        # For the references, we need to merge the issue and template default links.
        if "references" in issue_subsections:
            if "references" in src:
                refs = list(src["references"])
            else:
                refs = []
            if "references" in issue:
                refs.extend(issue["references"])
            issue["references"] = sorted(set(refs))

        # For the taxonomy, we try to get the link for every vulnerability tag.
        if "taxonomy" in issue_subsections:
            if "taxonomy" in src:
                taxonomy = list(src["taxonomy"])
            else:
                taxonomy = []
            if "taxonomy" in issue:
                taxonomy.extend(issue["taxonomy"])
            taxonomy = sorted(set(map(str.upper, taxonomy)))
            taglist = []
            for tag in taxonomy:
                tag = tag.strip()
                url = self.url_from_tag(tag)
                if url:
                    taglist.append({"tag": tag, "url": url})
                else:
                    taglist.append({"tag": tag})
            issue["taxonomy"] = taglist

        # Render the subsections.
        # For the severity we just translate the severity rating.
        for name in issue_subsections:
            if name == "severity":
                sections[name] = self.templates["main"][issue[name]].strip()
            else:
                if name in ("affects", "tools", "taxonomy", "references"):
                    tpl = "main/issue_" + name
                else:
                    tpl = template + "/" + name
                sections[name] = (
                    self.env.get_template(tpl).render(issue, metadata=metadata).strip()
                )

        # Return the contents of each subsection as a Python dictionary.
        # Note that we don't use the subsection headers here, that's the task of the caller.
        # We need this because we don't necessarily know the headers depth level here.
        return sections

    # Reports are rendered using sections. One of those sections contains the issues.
    #
    # The following are the supported sections:
    #
    # Header:
    #   Title of the report, followed by a paragraph with the count of the issues.
    #   If chart support is enabled, there will be a pie chart with the breakdown of the issues.
    #
    # Summary:
    #   Table with a list of all the issues and the summary of each one of them.
    #
    # Tools:
    #   Table with a list of all the tools used to find the issues.
    #
    # Issues:
    #   Issues with a severity rating of "low" or higher will be added here.
    #
    # Notes:
    #   Issues with a severity rating of "none" will be added here.
    #
    # In the future there will be more issues with arbitrary text (for example the methodology).
    # It should be possible at one point to have more than one Issues section too, with filters.
    # I want to add a final section with an Appendix, to put the actual input files there.
    #
    # All of these sections are optional, and the order can be configured as well.
    # This is defined in the "metadata" parameter.
    #
    def render_report(self, metadata, issuelist):
        # Make a copy of the metadata object, since we're going to modify it.
        metadata = copy.deepcopy(metadata)

        # Check the report does not contain duplicated isues.
        # If it does, this means the mergers were not executed.
        seen_templates = set()
        for issue in issuelist:
            template = issue["template"]
            if template == "manual":
                continue
            assert template not in seen_templates, (
                "Duplicated '%s' template in report" % template
            )
            seen_templates.add(template)

        # Collect various objects we will be using often in this method.
        tags = self.templates["main"]  # XXX FIXME
        min_severity = metadata["min_severity"]
        report_sections_order = metadata["report_sections_order"]
        issue_subsections_order = metadata["issue_subsections_order"]

        # We're producing a dictionary with the sections of the report.
        sections = {}

        # First, we need to filter and sort the issues.
        # This includes rendering the title of each one.
        # We will ignore informational issues (severity "none") here.
        severity_keys = ["low", "medium", "high", "critical"]
        if min_severity != "none":
            severity_keys = severity_keys[severity_keys.index(min_severity) :]
        severity_keys = tuple(severity_keys)
        issues_by_severity = {}
        for severity in severity_keys:
            issues_by_severity[severity] = sorted(
                (
                    self.env.get_template(issue["template"] + "/" + "title")
                    .render(issue)
                    .strip(),
                    issue["template"],
                    str(uuid.uuid4()),
                    issue,
                )
                for issue in issuelist
                if issue["severity"] == severity
            )
        metadata["issues_by_severity"] = issues_by_severity

        # Now, we do the same for informational issues.
        if min_severity == "none":
            sorted_notes = []
            for issue in issuelist:
                if issue["severity"] == "none":
                    title = (
                        self.env.get_template(issue["template"] + "/" + "title")
                        .render(issue)
                        .strip()
                    )
                    issue["title"] = title
                    sorted_notes.append((title, issue["template"], issue))
        else:
            sorted_notes = []

        # Next, we need to count how many issues we have of every type.
        severity_count = {}
        total = 0
        for severity in severity_keys:
            num = len(issues_by_severity[severity])
            severity_count[severity] = num
            total += num
        severity_count["issues"] = total
        severity_count["notes"] = len(sorted_notes)

        # Add the severity counts to the metadata so the templates can access them.
        metadata["severity_count"] = severity_count
        metadata["severity_keys"] = severity_keys

        # Now that everything is sorted and we have all the counts, we can calculate the IDs.
        tpl_vid = self.env.get_template("main/vulnid")
        index = 0
        section_index = 0
        for severity in severity_keys[::-1]:
            issue_index = 0
            subsection = issues_by_severity[severity]
            if len(subsection) > 0:
                while issue_index < len(subsection):
                    title, tplname, _, issue = subsection[issue_index]
                    vulnid = tpl_vid.render(
                        index=index + 1,
                        section=section_index + 1,
                        issue=issue_index + 1,
                    ).strip()
                    issue["title"] = title
                    issue["vulnid"] = vulnid
                    issue_index += 1
                    index += 1
                section_index += 1

        # Finally, put all of the issues into one big list, sorted by severity.
        sorted_issues = []
        for severity in severity_keys[::-1]:
            for title, tplname, _, issue in issues_by_severity[severity]:
                sorted_issues.append((severity, title, tplname, issue))

        # Add the list of issues to the metadata, so the templates can access them.
        metadata["issues"] = sorted_issues
        metadata["notes"] = sorted_notes

        # Collect all of the tools used in the engagement.
        parsers = self.parsers
        tool_names = []
        for _, _, _, issue in sorted_issues:
            tool_names.extend(issue["tools"])
        for _, _, issue in sorted_notes:
            tool_names.extend(issue["tools"])
        tools = sorted(
            (parsers[name]["name"], name)
            for name in set(tool_names)
            if not parsers[name]["hidden"]
        )
        tools = [parsers[name] for _, name in tools]
        metadata["tools"] = tools

        # If we have enabled the charts feature, generate one now.
        if (
            "chart_type" in metadata
            and metadata["chart_type"] != "none"
            and (total > 1 or metadata["show_empty_chart"] == "yes")
        ):
            if metadata["chart_type"] == "pie":
                labels = [
                    "%s (%d)" % (tags[severity], severity_count[severity])
                    for severity in severity_keys[::-1]
                    if severity_count[severity] > 0
                ]
            else:
                labels = [
                    tags[severity]
                    for severity in severity_keys[::-1]
                    if severity_count[severity] > 0
                ]
            colors = [
                metadata["severity_colors"][severity]
                for severity in severity_keys[::-1]
                if severity_count[severity] > 0
            ]
            data = [
                severity_count[severity]
                for severity in severity_keys[::-1]
                if severity_count[severity] > 0
            ]
            buf = BytesIO()
            if metadata["chart_type"] == "pie":
                plt.pie(np.array(data), labels=labels, colors=colors, shadow=True)
            elif metadata["chart_type"] == "bar":
                plt.bar(labels, np.array(data), color=colors)
            else:
                raise ValueError(
                    "Unsupported or incorrect chart type: '%s'" % metadata["chart_type"]
                )
            plt.savefig(buf, format="png")
            metadata["chart"] = base64.b64encode(buf.getvalue()).decode("utf-8")

        # Render the header section.
        if "header" in report_sections_order:
            sections["header"] = (
                self.env.get_template("main/header").render(metadata).strip()
            )

        # For the summary section, we have a series of tables per severity rating.
        # We don't include the informational issues here, they go in a separate section.
        # The whole section is skipped if we have no issues.
        if total > 0 and "summary" in report_sections_order:
            summaries_by_id = {}
            for severity in severity_keys:
                for _, template, _, issue in issues_by_severity[severity]:
                    summary = self.env.get_template(template + "/summary").render(issue)
                    summaries_by_id[issue["vulnid"]] = summary
            metadata["summaries_by_id"] = summaries_by_id
            sections["summary"] = (
                self.env.get_template("main/summary_table").render(metadata).strip()
            )

        # Render the tools section using the collected tools from the issues.
        # The whole section is skipped if we have no issues or notes.
        if "tools" in report_sections_order and metadata["tools"]:
            sections["tools"] = (
                self.env.get_template("main/tools_section").render(metadata).strip()
            )

        # Now we render the issues section.
        # We'll only include the requested sections in the requested order.
        # We'll also keep the rendered issues as a dictionary on the side.
        if sorted_issues and "issues" in report_sections_order:
            issues_dict = {}
            text = (
                self.env.get_template("main/issues_prologue").render(metadata).strip()
            )
            rendered_issues = [("header", text)]
            for severity, _, _, issue in sorted_issues:
                rendered = self.render_issue(metadata, issue)
                issues_dict[issue["vulnid"]] = rendered
                rendered_in_order = [
                    (name, rendered[name])
                    for name in issue_subsections_order
                    if name in rendered and rendered[name]
                ]
                text = (
                    self.env.get_template("main/issue_subsections")
                    .render(issue, rendered=rendered_in_order)
                    .strip()
                )
                rendered_issues.append((issue["template"], text))
            sections["issues"] = issues_dict
            sections["rendered_issues"] = rendered_issues

        # Finally, we do the same for the notes section.
        if sorted_notes and "notes" in report_sections_order:
            notes = []
            text = self.env.get_template("main/notes_prologue").render(metadata).strip()
            rendered_notes = [("header", text)]
            for _, _, issue in sorted_notes:
                rendered = self.render_issue(metadata, issue)
                rendered_in_order = [
                    (name, rendered[name])
                    for name in issue_subsections_order
                    if name in rendered and name != "severity" and rendered[name]
                ]
                text = (
                    self.env.get_template("main/issue_subsections")
                    .render(issue, rendered=rendered_in_order)
                    .strip()
                )
                notes.append(rendered)
                rendered_notes.append((issue["template"], text))
            sections["notes"] = notes
            sections["rendered_notes"] = rendered_notes

        # Now we generate a single Markdown text with all of this combined.
        report = ""
        for name in report_sections_order:
            if name not in sections or not sections[name]:
                continue
            if name == "header":
                text = sections[name] + "\n\n"
            elif name not in ("issues", "notes"):
                text = sections[name] + "\n\n"
            else:
                text = "\n\n".join(x[1] for x in sections["rendered_" + name]) + "\n\n"
            report += text.strip() + "\n\n"
        report = report.strip() + "\n"

        # We now return both the rendered Markdown file and the intermediate dictionaries.
        del metadata["issues"]
        del metadata["issues_by_severity"]
        del metadata["notes"]
        return metadata, sections, report

    # ----------------------------------------------------------------------------------------------------------------#

    # Run a tool parser against an input filename.
    def run_parser(self, tool, filename):
        parser = self.parsers[tool]["entrypoint"]
        parser = os.path.join(self.home, parser)
        assert os.path.exists(parser)
        # print(filename)     # XXX DEBUG
        with open(filename, "r") as stdin:
            p = subprocess.run(
                [self.config["python_executable"], parser],
                stdin=stdin,
                stdout=subprocess.PIPE,
                shell=False,
                check=True,
                encoding="utf-8",
                timeout=10,
            )
        issues = json.loads(p.stdout)
        validated = []
        for issue in issues:
            try:
                self.validate_issue(issue)
            except Exception:
                sys.stderr.write(
                    "Warning, discarded malformed issue object from '%s' parser when processing file '%s':\n"
                    % (tool, filename)
                )
                traceback.print_exc()
                sys.stderr.write("\n")
                continue
            validated.append(issue)
        return validated

    # Run a specific merger script against a list of issues.
    # All issues passed to this method must use the same template.
    # Returns a single merged issue.
    def run_merger(self, template, issues):
        assert template not in ("main", "manual"), (
            "Invalid template '%s' for merger" % template
        )
        assert template in self.mergers, "Missing or invalid template: '%s'" % template
        assert all(issue["template"] == template for issue in issues), (
            "Template name '%s' does not match for all input issues" % template
        )
        assert len(issues) > 0, "Cannot merge an empty list of issues"
        merger = self.mergers[template]
        merger = os.path.join(self.home, merger)
        assert os.path.exists(merger), "File not found: '%s'" % merger
        input_data = json.dumps(issues)
        try:
            p = subprocess.Popen(
                [self.config["python_executable"], merger],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                shell=False,
                encoding="utf-8",
            )
            output_data, _ = p.communicate(input_data, timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
            raise
        assert p.returncode == 0, "Parser script returned nonzero exit code"
        merged_issue = json.loads(output_data)
        assert isinstance(merged_issue, dict), "Wrong type '%s' for merger output" % (
            str(type(merged_issue))
        )
        self.validate_issue(merged_issue)
        assert merged_issue["template"] == template, (
            "Template name '%s' does not match for merged issue"
            % merged_issue["template"]
        )
        return merged_issue

    # Run all needed merger scripts until there are no duplicated issues.
    def merge_duplicated_issues(self, issues):
        templates = sorted(
            set(issue["template"] for issue in issues if issue["template"] != "manual")
        )
        merged = [
            self.run_merger(
                template, [issue for issue in issues if issue["template"] == template]
            )
            for template in templates
        ]
        merged.extend(issue for issue in issues if issue["template"] == "manual")
        return merged

    # Parse all files in a given directory and produce a report.
    # The files must be named after the tools (for example nmap.*).
    def process_files(self, pathname, metadata=DEFAULT_METADATA):
        # Ensure the metadata is valid.
        metadata = self.parse_metadata(metadata)

        # Switch to the requested language.
        if "language" in metadata and metadata["language"]:
            self.set_language(metadata["language"])
        assert self.language, "No language has been set, cannot render report"

        # Collect all of the filenames to parse.
        tasks = []
        for root, dirs, files in os.walk(pathname):
            for tool in self.parsers.keys():
                for filename in fnmatch.filter(files, tool + ".*"):
                    filename = os.path.join(root, filename)
                    tasks.append((tool, filename))

        # Parse the input files.
        issues = []
        for tool, filename in tasks:
            try:
                results = self.run_parser(tool, filename)
            except Exception:
                sys.stderr.write("Error processing file '%s':\n" % filename)
                traceback.print_exc()
                sys.stderr.write("\n")
                continue
            issues.extend(results)

        # Merge the results of parsing the files.
        issues = self.merge_duplicated_issues(issues)

        # Render the report in Markdown format.
        metadata, sections, report = self.render_report(metadata, issues)

        # Return the report and several intermediate stages.
        return {
            "metadata": metadata,
            "issues": issues,
            "sections": sections,
            "report": report,
        }

    # Export a generated report as an Obsidian vault.
    def export_as_obsidian(self, report, pathname, exist_ok=False):
        # Create the output directory structure.
        os.makedirs(pathname, exist_ok=exist_ok)

        # Create the Obsidian metadata.
        os.makedirs(os.path.join(pathname, ".obsidian"), exist_ok=exist_ok)
        with open(
            os.path.join(pathname, ".obsidian", "app.json"), "w", encoding="utf-8"
        ) as fd:
            fd.write('{\n"showInlineTitle": false\n}')

        # Save the Magenta metadata. This won't be used by Obsidian at all,
        # but it's good for debugging. I may remove it in future versions.
        os.makedirs(os.path.join(pathname, ".magenta"), exist_ok=exist_ok)
        with open(
            os.path.join(pathname, ".magenta", "metadata.json"), "w", encoding="utf-8"
        ) as fd:
            chart = report["metadata"]["chart"]
            try:
                del report["metadata"]["chart"]
                json.dump(report["metadata"], fd, sort_keys=True, indent=4)
            finally:
                report["metadata"]["chart"] = chart
        with open(
            os.path.join(pathname, ".magenta", "issues.json"), "w", encoding="utf-8"
        ) as fd:
            json.dump(report["issues"], fd, sort_keys=True, indent=4)
        with open(
            os.path.join(pathname, ".magenta", "sections.json"), "w", encoding="utf-8"
        ) as fd:
            json.dump(report["sections"], fd, sort_keys=True, indent=4)

        # Create a .gitignore file to ignore common useless files.
        with open(os.path.join(pathname, ".gitignore"), "w", encoding="utf-8") as fd:
            fd.write(".DS_Store\nThumbs.db\n")

        # Write all sections as individual Markdown files, except for Issues
        # and Notes. For those two, create a directory, and write each issue or
        # note as an file. The filenames will contain an index number to keep
        # the correct order as specified in the metadata.
        metadata = report["metadata"]
        sections = report["sections"]
        index = 0
        for name in metadata["report_sections_order"]:
            if name not in sections:
                continue
            if name in ("issues", "notes"):
                subdir = os.path.join(pathname, "%d-%s" % (index, name))
                os.makedirs(subdir, exist_ok=exist_ok)
                rendered = sections["rendered_" + name]
                subindex = 0
                for template, text in rendered:
                    with open(
                        os.path.join(subdir, "%d-%s.md" % (subindex, template)),
                        "w",
                        encoding="utf-8",
                    ) as fd:
                        fd.write(text)
                    subindex += 1
            else:
                with open(
                    os.path.join(pathname, "%d-%s.md" % (index, name)),
                    "w",
                    encoding="utf-8",
                ) as fd:
                    fd.write(sections[name])
            index += 1
