## Setup

`npm ci`

## Building

`npm run build`

## Parsing (generate report)

`SCAN_RESULT="./xx.json" npm run parse`

Where `SCAN_RESULT` is the output from the vuln scanner. Optionally set `SARIF_OUTPUT` to specify the name/location the
report file is written to.  Otherwise the output is written to `./report.sarif.json`

Other env vars:

* `CUSTOM_DOCKERFILE_NAME`: When globbing the project for docker files, if using a non-standard name supply with this
    var
* `PROJECT_ROOT`: What is the base location that should be searched, relative to your source code, for docker file.

>Note: Currently only the first dockefile found results are processed.  TODO: Process all.
