import yargs from "yargs";
import scanner from "../src";

const defaultOutput = './report.sarif.json'
const options = yargs
  .usage("Usage: -s <path to scan result>")
  .option('p', {alias: "projectroot", describe: "Source code location, relative to the project root.", default: '.'})
  .option('d', {alias: "dockerfilename", describe: "Name of the Dockerfile.", default: 'Dockerfile'})
  .option('o', {alias: "outputlocation", describe: "Path to write the resulting SARIF report", default: defaultOutput})
  .option('s', {alias: "scanresult", describe: "Path to the Lacework scan output JSON file", default: process.env.SCAN_OUTPUT, demandOption: true})
  .help()
  .argv

try {
  scanner(
    (options as any).scanresult,
    (options as any).dockerfilename,
    (options as any).projectroot,
    (options as any).outputlocation)
  console.log(`Report written to ${(options as any).outputlocation}`)
} catch (e) {
  console.log(`Failed to run conversion! \n\n${(e as any).message}`)
  process.exit(1)
}

