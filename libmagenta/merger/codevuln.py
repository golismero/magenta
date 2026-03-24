#!/usr/bin/python3

from . import Merger


# Generic issue merger for all source code auditing vulnerabilities.
class CodeVulnMerger(Merger):
    def do_code_cleanup(self, code):
        # This was my original implementation, I'm only leaving it here
        # as testament to my hubris. Was I really so naive to think I could
        # solve this with three measly lines of code? Let it be a lesson.
        #
        # unique = {(x["filename"], x["lines"][0]): x for x in code}
        # unique_keys = sorted(unique.keys())
        # return [unique[k] for k in unique_keys]

        # We define a basic "key" to try to sort the instances of the issue.
        # We can't just put them in a dictionary because it's possible for
        # the same issue to be reported twice on the same sink, but using
        # different sources or a different path to get to the sink, and we
        # (in principle) don't want to miss anything. Maybe later we can just
        # check the sources and sinks and ignore anything in between, if it
        # turns out this approach generates too much noise.
        unique_keys = sorted((item["file"], item["line"]) for item in code)

        # Now we process each "key" in order, to ensure our results array is sorted.
        results = []
        for key in unique_keys:
            # We need to go through every instance of the issue, since they're
            # not sorted and we can't just put them in a dictionary.
            for item in code:
                # Ignore all instances where our "key" doesn't match.
                if key != (item["file"], item["line"]):
                    continue

                # Ignore literally duplicated objects. This saves us some time.
                if item in results:
                    continue

                # Now comes the hairy part, we need to compare the traces.
                found = False
                for old_item in results:
                    # As before, skip objects not matching our "key".
                    if key != (old_item["file"], old_item["line"]):
                        continue

                    # When the new object does't have a trace, just drop it.
                    # If conversely the old object doesn't have a trace, add it.
                    # This is likely the result of having parsed the same issue
                    # twice from different input files, and some file formats
                    # may have incomplete information depending on the tool.
                    if "trace" not in item:
                        found = True
                        break
                    if "trace" not in old_item:
                        old_item["trace"] = item["trace"]
                        found = True
                        break

                    # At this point we should not have an identical trace.
                    # The differences should be more subtle.
                    assert item["trace"] != old_item["trace"], "Internal error"

                    # Let's check if we have different steps in the trace.
                    # That is, if we're going through different files.
                    # If we are, these are genuinely different instances.
                    st_old = [x["source"] for x in old_item["trace"]]
                    st_new = [x["source"] for x in item["trace"]]
                    if st_old != st_new:
                        continue

                    # So we go through the same files, the only possible difference
                    # are the highlighted bits. Let's see if we can merge the highlights.
                    st_merged = []
                    cannot_merge = False
                    for index in range(len(item["trace"])):
                        t_old = old_item["trace"][index]
                        t_new = item["trace"][index]

                        # The old one does not have highlights.
                        if "highlight" not in t_old:
                            # The new one has highlights, let's use it.
                            if "highlight" in t_new:
                                st_merged.append(t_new)

                            # Neither has highlights, keep the old one.
                            else:
                                st_merged.append(t_old)

                        # The old one has highlights, let's see what happens to the new one.
                        else:
                            # The new one also has highlights but they don't match.
                            # This makes it a new path, so we cannot merge them.
                            if (
                                "highlight" in t_new
                                and t_old["highlight"] != t_new["highlight"]
                            ):
                                cannot_merge = True
                                break

                            # Either the old one has highlights but the new one does not,
                            # or they both do and are identical. Keep the old one.
                            st_merged.append(t_old)

                    # If the merge was successful, add the merged trace to the old object.
                    if not cannot_merge:
                        old_item["trace"] = st_merged
                        found = True

                # We geniunely encountered a new instance of the same vuln,
                # add it to the results array.
                if not found:
                    results.append(item)

        # Return the results array, now sorted and without duplicates.
        return results
