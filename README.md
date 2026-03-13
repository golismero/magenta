# Magenta Reporter
*Well secluded, I see all...*

## What is it?

Magenta Reporter takes the output files from commonly used penetration testing tools and generates a ready to use report in Markdown format. You can either use the report as-is or edit it to your liking. Its powerful templating system allows for easy expansion, modification and customization of the reports it generates.

## How to install it?

You will need Python 3.x, which can be downloaded [here](https://www.python.org/).

Then, download the source code from Github or clone it using Git:

`git clone https://github.com/MarioVilas/magenta.git``

Finally, install the dependencies:

```
cd magenta
python3 -m pip install -r requirements.txt
```

## How do I use it?

Place all your files to be parsed by Magenta into a directory. Use as many subdirectories as you need. The names of the files need to follow a simple pattern:

```
<name of the tool>.<swhatever>.<any extension>
```

The only requirement is the name of the tool **MUST** be the first thing before the dot character. It doesn't matter if it's `nmap.xml` or `nmap.thisismysecondscan.xml`. The extension doesn't even matter because Magenta looks at the file *contents* to determine the type.

Now call Magenta and pass it the directory with all your files. By default the report will be generated on standard output (i.e. you'll get a lot of Markdown on the screen) but you can specify an output file too, which is much more neat.

```sh
python3 magenta.py my_pentest_files/ -o report.md
```

Magenta supports internationalization, and some of the templates have been translated to other languages. You can try this out to generate a report in Spanish like this:

```sh
python3 magenta.py mis_ficheros_de_pentest/ -o informe.md -l es
```

Magenta es mostly meant to be used as a starting point for a pentesting report, so being able to manually edit the text is always handy. That's why it also supports generating reports as Obsidian vaults, for easy editing:

```sh
python3 magenta.py my_pentest_files/ -o obsidian_report/ -f obsidian
```

You can also generate a JSON output, which is not terribly useful if you're a pentester, but may come in handy if you're a developer looking to integrate Magenta with other tools.

```sh
python3 magenta.py my_pentest_files/ -o data.json
```

There's more info for developers below, but as a final user you don't need to worry about any of this.

## How do I install it?

Magenta works on any operating system, in principle, but has been tested mostly on Debian Linux and Mac OS X. The following instructions assume such an environment.

The first step is to install Python. You can download it from here: https://www.python.org/downloads/

The next step is to download Magenta. It's best to use Git for this, so you can easily get updates. You can download Git from here: https://git-scm.com/downloads

Here's how you download Magenta using Git:

```sh
git clone git@github.com:MarioVilas/magenta.git
```

The next step is to install Pip, the Python package manager. This is needed to install the dependencies. You can download Pip here: https://pip.pypa.io/en/stable/installation/

Run this in your shell to look for all of the dependencies and install them:

```sh
cd magenta
for r in $(find . -name requirements.txt); do python3 -m pip install -r requirements.txt; done
```

## How does it work?

***TL;DR:** *This is the stuff developers love. If you're a user you don't need to know any of this. ;)*

Magenta is divided into three major components: the engine, the parsers and the templates.

The `magenta.py` script contains only the command line interface, the actual implementation of the engine is available as a library called `libmagenta`. This makes it easier to integrate Magenta into other tools, by simply importing it as just another Python module.

The parsers are located in the [parsers/](parsers/) directory and contains Python scripts that take input files via stdin and generate JSON output via stdout. The JSON schemas used by the parsers are defined by the templates. Each parser corresponds to a supported tool, and is defined with two files: a JSON5 metadata file, and a Python script source code. By storing each parser in its own subdirectory, it is possible to add a `requirements.txt` file to specify any dependencies, and other miscellaneous data files; but this is not strictly required by the engine. The metadata file looks like this:

```json5
{
    // Tool name for humans.
    name: "Nmap",

    // URL to the tool.
    url: "https://nmap.org/",

    // Tool description for humans, translate to each supported language.
    description: {
        en: "Nmap is a free and open source utility for network discovery and security auditing.",
        es: "Nmap es una utilidad gratuita y de código abierto para el descubrimiento de redes y la auditoría de seguridad.",
    },

    // Development status. Supported values are:
    //   production: Parser is production ready.
    //   testing: Parser is finished, but still under testing. Results may be unreliable.
    //   development: Parser is still under development, results will almost certainly be unreliable.
    status: "production",

    // Set to true to avoid listing this tool as one of the tools used in the pentest.
    // Useful for tools that are not pentesting tools per se, such as reporting or management tools.
    hidden: false
}
```

The templates are powered by Jinja2, with some monkey patching to ensure the autoescaping feature supports Markdown instead of HTML. They are located in the [templates/](templates/) subdirectory. While there tends to be a subdirectory per tool, this is not at all required by Magenta. It was simply easier to organize them that way, and may change in the future. Rather, each individual template corresponds to a vulnerability, which can be reported by any tool. This is useful, since different tools may report different instances of the same vulnerability, but Magenta does not care and integrates them all.

Each template is defined by at least three files: a JSON5 file for each supported language, containing the actual Jinja2 template code; a Python script that handles the integration of duplicated vulnerabilities into one, so the same vulnerability is not added multiple times to the report; and a JSON schema file that defines the JSON input it expects. These schemas are applied to the output of the parsers, to ensure no corrupted data reaches the templates in case of a bug in the parsers. Templates can be edited in order to either change the wording of certain vulnerabilities to better suit your needs, or to add more translations.

There is a special template called `main`, where the main structure of the report is defined. There is also a `main.schema.json` schema file that all of the parsers must adhere to. The main template follows its own format, completely different from a regular vulnerability template. Usually you never need to edit this.

A vulnerability template JSON5 file may look like this:

```json5
{
    title: "Cleartext Open Ports",

    taxonomy: ["CWE-319"],

    references: [
        "https://blog.netwrix.com/2022/08/04/open-port-vulnerabilities-list",
        "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml"
        ],

    summary: "Open ports were discovered during {% if affects|length == 1 %}a port scan{% else %}multiple port scans{% endif %} that did not use encryption to protect data in transit.",

    description: "During the security scan, {% if affects|length == 1 %}an open port was{% else %}open ports were{% endif %} discovered that did not use encryption to protect data in transit. This can result in sensitive information being disclosed to threat actors.\n\nIt should be noted that the exact impact of this issue is highly dependent on context, such as the relevance of the services being exposed by {% if affects|length == 1 %}this open port{% else %}these open ports{% endif %} and whether or not sensitive information is being transmitted using {% if affects|length == 1 %}it{% else %}them{% endif %}. The severity rating presented in this report is merely an estimate and should be reviewed with this context in mind.",

    recommendations: "When possible, protect all services with TLS to encrypt data in transit.\n\nSome protocols implement mechanisms to upgrade plaintext connections to encrypted connections after being established - care must be taken on these instances to ensure it is not possible to opt out of this upgrade, to prevent data from being accidentally exposed due to configuration errors on the client side. Some examples of such services include SMTP, IMAP and FTP.\n\nOther services such as TELNET do not allow encryption to be used at all - in these cases, the recommendation is to replace them entirely with a more secure protocol, such as SSH.",

    details: "The following plaintext services were identified during the security test:\n\n| Address | Port | Service |\n| --- | --- | --- |\n{% for row in plaintext_ports %}| {{ row.address }} | {{ row.port }} | {{ row.service }} |\n{% endfor %}",
}
```

Note that it is possible to include text from other templates and even the main template, making it easy to re-use text across templates. It is also possible to include generic vulnerability descriptiones that will be reused by many, more specific vulnerability templates, akin to an inheritance system, but without any of its drawbacks.

Adding new parsers and templates is as easy as just dropping the new files in the corresponding subdirectory - Magenta will pick them up automatically when loading.

More details can be found by reading the source code, which is heavily commented.

As mentioned above, the data model that allows the communication between the parsers and the templates is defined by a series of JSON schema files. The main schema can be found in [templates/main.schema.json](templates/main.schema.json), and defines the common format all files produced by parsers and consumed by templates must follow. The engine itself will also rely on this common schema, since it needs to be able to parse the JSON data well enough to know how to route the data from parsers to templates. Each template will define a custom JSON schema, but it includes **only the new properties defined by the template**, which makes it a lot easier to add new templates without duplicating schema information. For example, the [templates/nmap/cleartext_open_ports.schema.json](templates/nmap/cleartext_open_ports.schema.json)

When templates have the exact same schema, or even the exact same Python scripts, we just add a symlink to it, to avoid code duplication in the cheapest way. Be mindful of this when working on Windows hosts, since Git on Windows can be a bit particular with symlinks in that platform.
