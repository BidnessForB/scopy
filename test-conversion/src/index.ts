// import { compileFromFile } from 'json-schema-to-typescript'
import * as fs from 'fs';
import { Run, ReportingDescriptor, Result } from "../typings/sarif-schema"
import { ImagePackageVulnerability, ScanResult } from "./interfaces"


const result: ScanResult = JSON.parse(fs.readFileSync('outputs/example.json').toString())
const vulns: ImagePackageVulnerability[] = []
result.image.image_layers.forEach(l => {
  l.packages.forEach(p => {
    p.vulnerabilities.forEach(v => {
      vulns.push(v)
    })
  })
})

const rules: ReportingDescriptor[] = []
vulns.forEach(v => {
  rules.push({
    id: v.name,
    name: v.name,
    shortDescription: {
      text: v.name,
    },
    fullDescription: {
      text: v.description,
    },
    properties: v.metadata.NVD,
  })
})

const results: Result[] = [] 
result.image.image_layers.forEach(l => {
  l.packages.forEach(p => {
    p.vulnerabilities.forEach(v => {
      results.push({
        ruleId: v.name,
        message: {
          text: `${v.name} (${v.link})`,
        },
        fingerprints: {
          layer_hash: l.hash,
        }
      })
    })
  })
})

let report: Run = {
  tool: {
    driver: {
      organization: "Lacework",
      name: "Vulnerability Scanner",
      rules,
    },
  },
  results,
};

const output = {
  $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [
    report,
  ],
}

console.log(JSON.stringify(output, undefined, 2))
// compile from file
// compileFromFile('schemas/sarif-schema-2.1.0.json')
  // .then(ts => fs.writeFileSync('sarif-schema.d.ts', ts))
