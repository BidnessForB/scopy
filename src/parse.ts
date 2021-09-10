import {DockerfileParser, Instruction} from 'dockerfile-ast';
import {readFileSync} from 'fs';
import glob from 'glob';
import {LayerDetails} from './interfaces';

function parseDockerfileInstructions(_location: string, handle: Buffer): Instruction[] {
  return DockerfileParser.parse(handle.toString()).getInstructions()
}

interface LayerData {
  location: string,
  details: Instruction[],
}

export function gatherLayerData(
  dockerfileName: string = 'Dockerfile',
  projectRoot: string = ".",
): LayerData[] {
  const retdata: LayerData[] = []
  const results = glob.sync(`**/${dockerfileName}`, {cwd: projectRoot})

  for (var i = 0; i < results.length; i++) {
    const fileLocation = `${projectRoot.replace(/\/$/, '')}/${results[i]}`
    const handle = readFileSync(fileLocation)
    const data = parseDockerfileInstructions(results[i], handle)

    if (data) {
      retdata.push({location: fileLocation, details: data})
    }
  }

  return retdata
}

export function searchLayerInstructions(
  cmd: string,
  data: LayerData,
): LayerDetails | void {
  if (data) {
    const command = cmd.substring(0, cmd.indexOf('#')).trim()
    for (var i = 0; i < data.details.length; i++) {
      const d = data.details[i]
      if (d.getTextContent().includes(command)) {
        const details = d.getInstructionRange()

        // Note:When GH consumes this they count the offsets from 1, not 0 like this parser
        return {
          uri: data.location,
          startLine: details.start.line+1,
          startColumn: details.start.character+1,
          endColumn: details.end.character+1,
          endLine: details.end.line+1,
        }
      }
    }

  }

}
