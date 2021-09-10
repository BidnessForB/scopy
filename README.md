## Setup

`npm ci`

## Building

`npm run build`

## Parsing (generate report)

1. Set `SCAN_RESULT` environment variable to point to the lw-scanner output file to parse:

`SCAN_RESULT="<path-to-lw-scanner-output.json"

2. Run

`npm run parse`

Optionally set `SARIF_OUTPUT` to specify the name/location the report file is written to.  Otherwise the output is written to `./report.sarif.json`

Other env vars:

* `CUSTOM_DOCKERFILE_NAME`: When globbing the project for docker files, if using a non-standard name supply with this
    var
* `PROJECT_ROOT`: What is the base location that should be searched, relative to your source code, for docker file.

>Note: Currently only the first dockerfile found is processed.  TODO: Process all.
