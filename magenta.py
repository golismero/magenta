#!/usr/bin/python3

import fnmatch
import json
import os
import os.path
import sys

import babel
import click
import json5
import jsonschema
from click_default_group import DefaultGroup
from pygments import highlight
from pygments.formatters.terminal256 import Terminal256Formatter
from pygments.lexers.web import JsonLexer
from rich import box
from rich.console import Console
from rich.table import Table

try:
    MAGENTA_HOME = os.environ["MAGENTA_HOME"]
except KeyError:
    MAGENTA_HOME = os.path.dirname(os.path.abspath(__file__))
MAGENTA_HOME = os.path.abspath(MAGENTA_HOME)
assert os.path.isdir(MAGENTA_HOME), (
    "Invalid 'MAGENTA_HOME' environment variable: '%s'" % MAGENTA_HOME
)
os.environ["MAGENTA_HOME"] = MAGENTA_HOME

try:
    from libmagenta import VERSION
    from libmagenta.engine import MagentaReporter, ParseHaltError
except ImportError:
    import sys

    sys.path.insert(1, os.environ["MAGENTA_HOME"])
    from libmagenta import VERSION
    from libmagenta.engine import MagentaReporter, ParseHaltError


# Helper function to format JSON with syntax highlighting.
def color_json(obj):
    text = json.dumps(obj, sort_keys=True, indent=4)
    text = highlight(text, lexer=JsonLexer(), formatter=Terminal256Formatter())
    return text


@click.group(cls=DefaultGroup, default="report", default_if_no_args=True)
@click.version_option("v%s.%s" % VERSION)
@click.option(
    "-c",
    "--config",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    default=None,
    help="Configuration file (JSON5). Defaults to built-in configuration.",
)
@click.pass_context
def main(ctx, config):
    ctx.ensure_object(dict)
    ctx.obj["config"] = config


@main.command()
@click.argument(
    "pathname",
    required=True,
    type=click.Path(
        exists=True, file_okay=False, dir_okay=True, readable=True, resolve_path=True
    ),
)
@click.option(
    "-o",
    "--output",
    default="-",
    help="Output file for the report. Defaults to standard output.",
)
@click.option(
    "-f",
    "--format",
    default="auto",
    type=click.Choice(
        choices=("auto", "markdown", "json", "obsidian", "textile", "dradis"),
        case_sensitive=False,
    ),
    help="Output file format. Defaults to 'auto'.",
)
@click.option(
    "-l",
    "--language",
    default="en",
    help="Language for the report. Defaults to English ('en').",
)
@click.option(
    "-m",
    "--metadata",
    type=click.File("r"),
    default=None,
    help="Report metadata (project information, rendering settings, etc.)",
)
@click.option(
    "--dradis-templates",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, resolve_path=True),
    default=None,
    help="Directory containing the Dradis mapping.json5. "
    "Defaults to <MAGENTA_HOME>/formats/dradis. Only used with -f dradis.",
)
@click.option(
    "--on-error",
    type=click.Choice(("ignore", "skip", "halt"), case_sensitive=False),
    default="ignore",
    show_default=True,
    help="How to react to a file-level parser error: 'ignore' logs and "
    "continues (exit 0); 'skip' logs and continues but exits 2 if any file "
    "failed; 'halt' logs and stops without writing a report (exit 3).",
)
@click.pass_context
def report(ctx, pathname, output, format, language, metadata, dradis_templates, on_error):
    """Read all tool output files in the PATHNAME directory
    and generate a report from them.

    Files MUST be named after the tool they were generated with.
    For example, nmap files should be named: 'nmap.*'.
    Multiple extensions are allowed ('nmap.whatever.xml').
    """

    # Determine the output format and location.
    # We do this first as a convenience for the user; if the output pathname
    # is wrong, it's a lot better to detect this before the lengthy process
    # of generating a report.
    if not format:
        format = "auto"
    if format == "obsidian":
        if output == "-":
            output = "obsidian"
    elif format == "auto":
        if output == "-":
            format = "markdown"
        else:
            base = os.path.basename(output).lower()
            ext = os.path.splitext(output)[1].lower()
            if base == "dradis-export.zip":
                format = "dradis"
            elif ext == ".zip":
                click.echo(
                    "error: ambiguous .zip extension; pass -f explicitly "
                    "(use exact filename 'dradis-export.zip' to autodetect)"
                )
                return
            elif not ext:
                format = "obsidian"
                click.echo(
                    "warning: autodetecting 'obsidian' format from a "
                    "directory-style output path is deprecated and will be "
                    "removed in a future release. Pass '-f obsidian' explicitly.",
                    err=True,
                )
            elif ext in (".md", ".txt"):
                format = "markdown"
            elif ext in (".json", ".js"):
                format = "json"
            elif ext == ".textile":
                format = "textile"
            else:
                click.echo("error: cannot guess file format for extension: '%s'" % ext)
                return
    if output != "-":
        output = os.path.abspath(output)
        if os.path.exists(output):
            click.echo("error: output pathname already exists: '%s'" % output)
            return

    # If the metadata file was provided, read it.
    if metadata is not None:
        metadata = json5.load(metadata, allow_duplicate_keys=False)

    # Parse the files and generate the report.
    magenta = MagentaReporter(ctx.obj["config"])
    if (
        metadata is None
        or "language" not in metadata
        or metadata["language"] != language
    ):
        if metadata is not None:
            metadata["language"] = language
        magenta.set_language(language)
    try:
        result = magenta.process_files(pathname, metadata, on_error)
    except ParseHaltError:
        sys.exit(3)
    if format == "dradis":
        if dradis_templates is None:
            dradis_templates = os.path.join(MAGENTA_HOME, "formats", "dradis")
        magenta.export_as_dradis(result, output, dradis_templates)
    elif format == "obsidian":
        magenta.export_as_obsidian(result, output)
    else:
        if output == "-":
            fd = sys.stdout
        else:
            fd = open(output, "w", encoding="utf-8")
        with fd:
            if format == "markdown":
                fd.write(result["report"])
            elif format == "json":
                click.echo(color_json(result), file=fd)
            elif format == "textile":
                from libmagenta.pandoc import convert_from_markdown

                fd.write(convert_from_markdown(result["report"], "textile"))
            else:
                assert False
    if on_error == "skip" and result.get("skipped", 0):
        sys.stderr.write(
            "%d file(s) skipped due to parse errors.\n" % result["skipped"]
        )
        sys.exit(2)


@main.command()
@click.option(
    "-l",
    "--language",
    default="en",
    help="Language for the tool descriptions. Defaults to English ('en').",
)
@click.option(
    "-s",
    "--status",
    type=click.Choice(
        ["all", "production", "testing", "development"], case_sensitive=False
    ),
    default="all",
    help="Only include tools with the given development status.",
)
@click.pass_context
def tools(ctx, language, status):
    "Show the list of supported tools and exit."
    magenta = MagentaReporter(ctx.obj["config"])
    magenta.set_language(language)
    if not magenta.parsers:
        print("No parsers found! Something is wrong with this installation of Magenta.")
        return
    if status == "all":
        title = "Supported tools"
    else:
        title = "Supported tools (%s)" % status
    table = Table(title=title, box=box.HORIZONTALS, show_lines=True)
    table.add_column("Prefix", justify="left", no_wrap=True)
    table.add_column("Tool", justify="left", no_wrap=True)
    if status == "all":
        table.add_column("Status", justify="left", no_wrap=True)
    table.add_column("Description", justify="full")
    for tool in sorted(magenta.parsers.keys()):
        metadata = magenta.parsers[tool]
        if status == "all":
            table.add_row(
                tool + ".*",
                metadata["name"],
                metadata["status"].title(),
                metadata["description"],
            )
        elif status == metadata["status"]:
            table.add_row(tool + ".*", metadata["name"], metadata["description"])
    console = Console()
    print()
    console.print(table)
    print()


@main.command()
@click.pass_context
def languages(ctx):
    "Show the list of supported languages and exit."
    magenta = MagentaReporter(ctx.obj["config"])

    # Count how many templates we have per language.
    template_count = {}
    path = magenta.config["templates_directory"]
    for root, dirs, files in os.walk(path):
        for name in fnmatch.filter(files, "*.json5"):
            filename = os.path.join(root, name)
            template_name = os.path.splitext(name)[0]
            if os.path.extsep in template_name:
                template_name, template_language = os.path.splitext(template_name)
                template_language = template_language[len(os.path.extsep) :]
            else:
                template_language = "en"
            if template_language in template_count:
                template_count[template_language] += 1
            else:
                template_count[template_language] = 1

    # Count how many parsers we have per language.
    parser_count = {}
    path = magenta.config["parsers_directory"]
    for root, dirs, files in os.walk(path):
        for name in fnmatch.filter(files, "*.json5"):
            filename = os.path.join(root, name)
            data = magenta.cache.get(filename)
            if data is None:
                with open(filename, "r") as fd:
                    data = json5.load(fd, allow_duplicate_keys=False)
                jsonschema.validate(data, magenta.SCHEMA_PARSER)
                magenta.cache.put(filename, data)
            for description_language in data["description"].keys():
                if description_language in parser_count:
                    parser_count[description_language] += 1
                else:
                    parser_count[description_language] = 1

    # Make sure both counters have the same languages.
    languages = sorted(set(list(template_count.keys()) + list(parser_count.keys())))
    for lang in languages:
        if lang not in template_count:
            template_count[lang] = 0
        if lang not in parser_count:
            parser_count[lang] = 0
    if not languages:
        print(
            "No templates found! Something is wrong with this installation of Magenta."
        )
        return

    # Print out a table with the results.
    table = Table(title="Supported languages", box=box.SIMPLE_HEAVY)
    table.add_column("Code", justify="center", no_wrap=True)
    table.add_column("Language", justify="center", no_wrap=True)
    table.add_column("# Tools", justify="center", no_wrap=True)
    table.add_column("# Templates", justify="center", no_wrap=True)
    for lang in languages:
        name = babel.Locale(lang).display_name.capitalize()
        table.add_row(lang, name, str(parser_count[lang]), str(template_count[lang]))
    console = Console()
    print()
    console.print(table)


if __name__ == "__main__":
    try:
        main(max_content_width=120)
    except Exception:
        Console().print_exception(show_locals=True)
        sys.exit(1)
