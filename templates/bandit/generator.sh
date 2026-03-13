#!/bin/bash
set -e
for filename in *.py
do
    filename="${filename%.*}"
    ln -f -s "../generic_source_code_issue.schema.json" "${filename%.*}.schema.json"
    ln -f -s "../generic_source_code_issue.py" "${filename%.*}.py"
done
