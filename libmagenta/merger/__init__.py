#!/usr/bin/python3

import inspect
import json
import os.path
import sys
import traceback

SEVERITY_LABELS = ("none", "low", "medium", "high", "critical")

# Helper class to perform an issue merge.
# Takes care of most of the work, and uses callbacks to allow each merger to customize the process.
# Callbacks are defined as methods in the class, named after the properties they handle.
class Merger:

    def __init__(self, template_name=None):

        # This trick will only work if you call the constructor directly
        # from the merger script for a template. Otherwise you'll have
        # to supply the correct template name as an argument. Note:
        # it's important to use abspath() rather than realpath() so
        # we can use symbolic links for scripts that are identical.
        if template_name is None:
            lib_dir = os.path.dirname(os.path.abspath(__file__))
            for stack in inspect.stack():
                filename = os.path.abspath(inspect.getmodule(stack[0]).__file__)
                if os.path.commonprefix([lib_dir, filename]) != lib_dir:
                    template_name = os.path.splitext(os.path.basename(filename))[0]

        self.template_name = template_name
        self.mandatory_properties = [
            name[3:-10]
            for name in list(self.__dict__.keys())
            if name.startswith("is_") and name.endswith("_mandatory") and getattr(self, name)
        ]
        self.properties_with_defaults = [
            name[7:-6]
            for name in list(self.__dict__.keys())
            if name.startswith("default") and name.endswith("_value") and getattr(self, name)
        ]

    def __get_callback(self, propname, callbacktype):
        if callbacktype == "mandatory":
            propname = "is_" + propname + "_mandatory"
        else:
            propname = "do_" + propname + "_" + callbacktype
        return getattr(self, propname, None)

    def run(self):

        # XXX FIXME maybe skip "none" risk issues if another risk is present, instead of merging them

        # We will collect all of the properties from the issues into this one.
        merged = {
            "template": self.template_name,
            "tools": [],
            "severity": "none",
            "affects": [],
            "taxonomy": [],
            "references": [],
        }
        for propname in self.properties_with_defaults:
            merged[propname] = self.__get_callback(propname, "init")()

        # We must have an object array in stdin. Parse it.
        input_array = json.load(sys.stdin)

        # Go through the list of issues and merge their properties.
        assert isinstance(input_array, list), "Malformed data passed to merger script"
        assert input_array, "Merger script received an empty list of issues"
        index = 0
        while index < len(input_array):
            issue = input_array[index]
            try:

                # First, start with some basic sanity checks.
                assert isinstance(issue, dict), "Malformed data passed to merger script"
                assert issue.get("template", self.template_name) == self.template_name, \
                        "Wrong issue '%s' sent to merger for '%s'" % (issue["template"], self.template_name)

                # Add default values for missing properties.
                for propname in self.properties_with_defaults:
                    if not issue.get(propname, None):
                        issue[propname] = self.__get_callback(propname, "default")()

                # Merge the property. If there is no collector method, assume it's a list.
                for propname, propvalue in issue.items():
                    callback = self.__get_callback(propname, "collect")
                    if callback is None:
                        if propname in merged:
                            merged[propname].extend(propvalue)
                        else:
                            merged[propname] = list(propvalue)
                    else:
                        if propname not in merged:
                            init = self.__get_callback(propname, "init")
                            if init is not None:
                                merged[propname] = init()
                            else:
                                merged[propname] = []
                        merged[propname] = callback(merged[propname], propvalue)

                # On success, move to the next issue.
                index += 1

            # If an error occurs while processing the issue, it will be discarded.
            # This may result in slightly malformed merged objects, but I don't care for that right now.
            except Exception:
                sys.stderr.write("Error processing issue:\n%s\n\n" % json.dumps(issue))
                traceback.print_exc()
                sys.stderr.write("\n")
                del input_array[index]
                continue

        # Do the cleanup of the merged properties, since there may be duplicates and such.
        # If no cleanup method is defined assume it's a sorted list of unique strings.
        # Note that an error here will botch the entire merge.
        for propname in list(merged.keys()):
            callback = self.__get_callback(propname, "cleanup")
            if callback is None:
                merged[propname] = sorted(set(merged[propname]))
            else:
                merged[propname] = callback(merged[propname])
            if not merged[propname] and propname not in self.mandatory_properties:
                del merged[propname]

        # Write the merged issue to stdout in JSON format.
        json.dump(merged, sys.stdout)

    # The following are the callbacks for the built-in properties in all vulnerabilities.
    # Don't override them in template scripts unless you REALLY know what you're doing!
    def do_template_init(self): return self.template_name
    def do_tools_init(self): return []
    def do_severity_init(self): return "none"
    def do_affects_init(self): return []
    def do_taxonomy_init(self): return []
    def do_references_init(self): return []
    def do_template_collect(self, merged, issue): return self.template_name
    def do_severity_collect(self, merged, issue):
        return issue if SEVERITY_LABELS.index(issue) > SEVERITY_LABELS.index(merged) else merged
    def do_template_cleanup(self, value): return value
    def do_severity_cleanup(self, value): return value
