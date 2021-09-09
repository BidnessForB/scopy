// import { compileFromFile } from 'json-schema-to-typescript'
import * as fs from 'fs';
import { Run, ReportingDescriptor, Result } from "../typings/sarif-schema"
import { ImageInfo, ImageLayer, ImagePackage, ImagePackageVulnerability, ScanResult } from "./interfaces"

const buildRuleDescriptionMarkdown = (
  image: ImageInfo,
  layer: ImageLayer,
  imgpackage: ImagePackage,
  v: ImagePackageVulnerability): string => {
  return `
${v.name} found in package ${imgpackage.name}

**Severity**: ${v.severity}
**CVSSv3 Score**: ${v.metadata.NVD.CVSSv3.Score}
**Image**: ${image.repository}:${image.tags[0]}
**Image layer hash**: ${layer.hash}
**Image creation command**: ${layer.created_by}
**Package Name**: ${imgpackage.name}@${imgpackage.version}

#### Description
${v.description}

More details [here](${v.link}).
`
}

const result: ScanResult = JSON.parse(fs.readFileSync('outputs/example.json').toString())
const rules: ReportingDescriptor[] = []
result.image.image_layers.forEach(l => {
  l.packages.forEach(p => {
    p.vulnerabilities.forEach(v => {
      rules.push({
        id: v.name,
        helpUri: v.link,
        help: {
          text: v.description,
          markdown: buildRuleDescriptionMarkdown(result.image.image_info, l, p, v),
        },
        properties: {
          "security-severity": `${v.metadata.NVD.CVSSv3.Score}`,
          ...v.metadata.NVD,
        },
      })
    })
  })
})

const results: Result[] = [] 
result.image.image_layers.forEach(l => {
  l.packages.forEach(p => {
    p.vulnerabilities.forEach(v => {
      results.push({
        ruleId: v.name,
        message: {
          text: `${v.name}`,
        },
        fingerprints: {
          layer_hash: l.hash,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: "Dockerfile"
              },
              region: {
                startLine: 1,
                startColumn: 1,
                endColumn: 2
              }
            }
          }
        ]
      })
    })
  })
})

let report: Run = {
  tool: {
    driver: {
      version: "1.0", // Needs populated properly
      organization: "Lacework",
      name: "lacework-vuln-scanner",
      informationUri: "https://support.lacework.com/hc/en-us/articles/360035472393-Container-Vulnerability-Assessment-Overview",
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
