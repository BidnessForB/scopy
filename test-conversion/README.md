## Setup

`npm ci`

## Building

`npm run build`

## Parsing (generate report)

`SCAN_RESULT="./xx.json" npm run parse`

Where `SCAN_RESULT` is the output from the vuln scanner. Optionally set `SARIF_OUTPUT` to specify the name/location the
report file is written to.  Otherwise the output is written to `./report.sarif.json`

