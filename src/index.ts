import * as fs from 'fs';
import {Run, ReportingDescriptor, Result} from "../typings/sarif-schema"
import {ImageInfo, ImageLayer, ImagePackage, ImagePackageVulnerability, ScanResult} from "./interfaces"
import {gatherLayerData, searchLayerInstructions} from './parse';


const buildRuleDescriptionMarkdown = (
  image: ImageInfo,
  layer: ImageLayer,
  imgpackage: ImagePackage,
  v: ImagePackageVulnerability): string => {
  return `
${v.name} found in package ${imgpackage.name}

**Severity**: ${v.severity}
**CVSSv3 Score**: ${v.metadata?.NVD.CVSSv3.Score}
**Image**: ${image.repository}:${image.tags[0]}
**Image layer hash**: ${layer.hash}
**Image creation command**: ${layer.created_by}
**Package Name**: ${imgpackage.name}@${imgpackage.version}

#### Description
${v.description}

More details [here](${v.link}).
`
}

export default (scanResult?: string, customDockerfileName?: string, projectRoot?: string, outputLocation?: string) => {
  // Test if input file var is set
  const msg = 'No scan result specified!  Must set scan result location!'
  if (!scanResult && !process.env.SCAN_RESULT) {
    throw new Error(msg)
  }

  const scanPath = scanResult || process.env.SCAN_RESULT

  if (!scanPath) {
    throw new Error(msg)
  }

  const result: ScanResult = JSON.parse(fs.readFileSync(scanPath).toString())
  const rules: ReportingDescriptor[] = []
  const results: Result[] = []
  const layerData = gatherLayerData(
    customDockerfileName || process.env.CUSTOM_DOCKERFILE_NAME,
    projectRoot || process.env.PROJECT_ROOT,
  )

  result.image.image_layers.forEach(l => {
    l.packages.forEach(p => {
      p.vulnerabilities.forEach(v => {
        const locationDetails = searchLayerInstructions(l.created_by, layerData[0])
        rules.push({
          id: v.name,
          helpUri: v.link,
          help: {
            text: v.description,
            markdown: buildRuleDescriptionMarkdown(result.image.image_info, l, p, v),
          },
          properties: {
            "security-severity": `${v.metadata?.NVD?.CVSSv3?.Score}`,
            ...v.metadata?.NVD,
          },
        })

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
                  uri: layerData[0] ? layerData[0].location.replace('\./', '') : 'Dockerfile'
                },
                region: {
                  startLine: locationDetails ? locationDetails.startLine : 1,
                  endLine: locationDetails ? locationDetails.endLine : 1,
                  startColumn: locationDetails ? locationDetails.startColumn : 1,
                  endColumn: locationDetails ? locationDetails.endColumn : 2
                }
              }
            }
          ]
        })
      })
    })
  })

  // Build SARIF report object to be written
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


  // Write results
  const output = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      report,
    ],
  }
  fs.writeFileSync(outputLocation || process.env.SARIF_REPORT || './report.sarif.json', JSON.stringify(output, undefined, 2))
}
