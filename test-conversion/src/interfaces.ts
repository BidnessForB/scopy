// Image Metadata
export interface ImageInfo {
  image_digest: string
  image_id: string
  registry: string
  repository: string
  created_time: string
  size: number
  tags: string[]
}

export interface ImagePackageNVDVulnerabilityCVSSv3Metadata {
  ExploitabilityScore: number
  ImpactScore: number
  Score: number
  Vectors: string
}

export interface ImagePackageNVDVulnerabilityCVSSv2Metadata {
  PublishedDateTime: string
  Score: number
  Vectors: string
}

export interface ImagePackageNVDVulnerabilityMetadata {
  NVD: {
    CVSSv2: ImagePackageNVDVulnerabilityCVSSv2Metadata
    CVSSv3: ImagePackageNVDVulnerabilityCVSSv3Metadata
  }
}

export interface ImagePackageVulnerability {
  name: string
  description: string
  severity: string
  link: string
  fix_version: string | undefined
  metadata: ImagePackageNVDVulnerabilityMetadata
}

export interface ImagePackage {
  name: string
  namespace: string
  version: string
  vulnerabilities: ImagePackageVulnerability[]
}

export interface ImageLayer {
  hash: string
  created_by: string
  packages: ImagePackage[]
}

export interface Image {
  image_info: ImageInfo
  image_layers: ImageLayer[]
}

// Top-level ScanResult
export interface ScanResult {
  total_vulnerabilities: number
  critical_vulnerabilities: number
  high_vulnerabilities: number
  medium_vulnerabilities: number
  low_vulnerabilities: number
  info_vulnerabilities: number
  fixable_vulnerabilities: number
  last_evaluation_time: string
  image: Image
  scan_status: string
}

export interface LayerDetails {
  uri: string
  startLine: number
  startColumn: number
  endColumn: number
  endLine: number
}

