#!/usr/bin/python3

# Some code adapted from jinja-vanish pull request 1, not accepted at the time of writing.
# The official version of jinja-vanish from pip does not work.
# https://github.com/mbr/jinja-vanish/pull/1/commits

import html
import html.entities
import jinja2
import posixpath
import weakref

from functools import wraps

from markupsafe import Markup
from jinja2.sandbox import ImmutableSandboxedEnvironment
from jinja2.compiler import CodeGenerator
from jinja2.utils import pass_context  # jinja2 3.x


class LocalOverridingCodeGenerator(CodeGenerator):
    def visit_Template(self, *args, **kwargs):
        super(LocalOverridingCodeGenerator, self).visit_Template(*args, **kwargs)
        overrides = getattr(self.environment, "_codegen_overrides", {})

        if overrides:
            self.writeline("")

        for name, override in overrides.items():
            self.writeline("{} = {}".format(name, override))


class DynAutoEscapeEnvironment(ImmutableSandboxedEnvironment):
    code_generator_class = LocalOverridingCodeGenerator

    def __init__(self, *args, **kwargs):
        escape_func = kwargs.pop("escape_func", None)
        markup_class = kwargs.pop("markup_class", None)

        super(DynAutoEscapeEnvironment, self).__init__(*args, **kwargs)

        # we need to disable constant-evaluation at compile time, because it
        # calls jinja's own escape function.
        #
        # this is done by jinja itself if a finalize function is set and it
        # is marked as a contextfunction. this is accomplished by either
        # suppling a no-op contextfunction itself or wrapping an existing
        # finalize in a contextfunction
        if self.finalize:
            if not (
                getattr(self.finalize, "contextfunction", False)  # jinja2 2.x
                or getattr(self.finalize, "jinja_pass_arg", False)  # jinja2 3.x
            ):
                _finalize = getattr(self, "finalize")
                self.finalize = lambda _, v: _finalize(v)
        else:
            self.finalize = lambda _, v: v
        pass_context(self.finalize)

        self._codegen_overrides = {}

        if escape_func:
            self._codegen_overrides["escape"] = "environment.escape_func"
            self.escape_func = escape_func
            self.filters["e"] = escape_func
            self.filters["escape"] = escape_func

        if markup_class:
            self._codegen_overrides["markup"] = "environment.markup_class"
            self.markup_class = markup_class

    # Jinja2 hack to make relative imports possible.
    # https://stackoverflow.com/a/8530761/426293
    """Override join_path() to enable relative template paths."""

    def join_path(self, template, parent):
        return posixpath.join(posixpath.dirname(parent), template)


def markup_escape_func(f):
    @wraps(f)
    def _(v, **kw):
        if isinstance(v, Markup):
            return v
        return Markup(f(v, **kw))

    return _


# Helper function to convert non-ASCII characters to HTML entities.
@markup_escape_func
def escapehtml(v):
    v = str(v)
    v = html.escape(v, quote=True)
    a = []
    for c in v:
        o = ord(c)
        if o >= 127 or (o < 32 and c not in "\t\r\n"):
            if c in html.entities.html5:
                a.append("&" + html.entities.html5[c])
            else:
                a.append("&#x" + hex(o) + ";")
        else:
            a.append(c)
    return "".join(a)


# Helper function to escape Markdown characters from strings.
@markup_escape_func
def escapemd(v):
    v = str(v)
    v = escapehtml(v)
    v = v.replace("\\", "\\\\")  # must be first
    for char in (
        r"_*[]()~`>#+-=|{}.!"
    ):  # https://github.com/go-telegram/bot/blob/main/common.go#L12C23-L12C43
        v = v.replace(char, "\\" + char)
    v = v.replace("\r", "")
    v = v.replace("\n", "")
    v = v.replace("\t", "    ")  # not sure about this one
    """
    p = -1
    while True:
        p = v.find("#", p+1)
        if p < 0: break
        #sys.stderr.write("p = %d\n" % p)
        if p > 1 and v[p-1:p+1] == "&#x": continue
        v = v[:p] + "\\" + v[p:]
        p += 1
        #sys.stderr.write("v = %r\n" % v)
    """
    return v


# Helper function to render HTTP requests and responses in Markdown.
# Automatically truncates the body leaving only the relevant parts.
#
# XXX TODO: add highlighting in addition to truncation, using <pre> and <b> tags instead of triple backtick.
#   https://meta.stackexchange.com/questions/183610/how-to-combine-bold-and-code-sample-in-markdown
#
@markup_escape_func
def http2md(v, hfind=[], find=[], full=False, headersonly=False):
    # Accepts both strings and list of strings.
    if hfind and isinstance(hfind, str):
        hfind = [hfind]
    if find and isinstance(find, str):
        find = [find]
    hfind = set(map(str.lower, hfind))
    find = list(map(str.lower, find))

    # Split the HTTP headers from the body.
    if "\r\n\r\n" in v:
        headers, body = v.split("\r\n\r\n", 1)
    elif "\n\n" in v:
        headers, body = v.split("\n\n", 1)
    elif "\r\r" in v:  # possible according to the RFC, but haven't seen it in real life
        headers, body = v.split("\r\r", 1)
    else:
        # assert False, v     # XXX DEBUG
        headers = v
        body = ""

    # The "hfind" parameter does an HTTP headers search.
    # If no headers are searched for, all are shown.
    # The status line and the "Host" header are always shown.
    if not hfind:
        output = headers.split("\r\n")
    else:
        output = []
        lines = headers.split("\r\n")
        output.append(lines.pop(0))
        skip = False
        for line in lines:
            h, v = line.split(":", 1)
            h = h.lower()
            if h == "host" or h in hfind:
                if skip:
                    output.append("[...]")
                    skip = False
                output.append(line)
            else:
                skip = True

    # The "find" parameter does a case insensitive search on the body.
    # If no body strings are searched for, it's truncated at the beginning.
    # If a line is too long, it too is truncated.
    # If "headersonly" was used, skip the body entirely.
    if body and not headersonly:
        if full:
            output.extend(body)
        else:
            output.append("")
            body = body.replace("\r\n", "\n")
            lines = body.split("\n")
            if find:
                backlog = []
                skip = False
                for line in lines:
                    line = line.strip()
                    found = []
                    for f in find:
                        if f in line:
                            found.append(f)
                    if found:
                        if len(line) > 160:
                            for f in found:
                                p = line.find(f)
                                p = max(0, p - 64)
                                q = min(p + len(f) + 64, len(line))
                                new_line = line[p:q]
                                if p > 0 and not new_line.strip().startswith("[...]"):
                                    new_line = "[...]" + new_line
                                if q < len(line) and not new_line.strip().endswith(
                                    "[...]"
                                ):
                                    new_line = new_line + "[...]"
                                line = new_line
                        if skip:
                            if output[-1] != "":
                                output.append("")
                            output.append("[...]")
                            output.append("")
                            output.extend(backlog)
                            skip = False
                            backlog = []
                        output.append(line)
                    else:
                        skip = True
                        if len(line) > 160:
                            line = line[:160] + "[...]"
                        backlog.append(line)
                        if len(backlog) > 3:
                            backlog.pop(0)
            else:
                for line in lines[:10]:
                    line = line.strip()
                    if len(line) > 160:
                        line = line[:160] + "[...]"
                    output.append(line)
                if len(lines) > 10:
                    if output[-1] != "":
                        output.append("")
                    output.append("[...]")
            if output[-1] == "":
                output.pop(-1)

    # Return the HTTP headers and body in a code block.
    text = "\n".join(output)
    if len(text) > 65536:
        text = "[... output truncated due to length ...]"
    text = escapehtml(text)
    text = text.replace("`", "\\`")
    text = "```\n" + text + "\n```\n"
    return text


# Custom Jinja2 loader to fetch our templates.
class CustomTemplateLoader(jinja2.BaseLoader):
    def __init__(self, magenta):
        self.magenta = weakref.ref(magenta)

    def get_source(self, environment, template):
        try:
            template = posixpath.normpath(template)
            tplname, propname = template.split("/")
            magenta = self.magenta()
            if magenta is None:
                raise jinja2.TemplateNotFound(template)
            try:
                source = magenta.templates[tplname][propname]
            except KeyError:
                try:
                    source = magenta.templates["main"][propname]
                except KeyError:
                    raise jinja2.TemplateNotFound(template)
            return source, template, lambda x=None: True
        except jinja2.TemplateNotFound:
            raise
        except Exception as e:
            raise jinja2.TemplateNotFound(template) from e
