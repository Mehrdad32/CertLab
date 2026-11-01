import 'reflect-metadata'
import {
  X509Certificate, Pkcs10CertificateRequest,
  SubjectAlternativeNameExtension, BasicConstraintsExtension,
  ExtendedKeyUsageExtension, KeyUsagesExtension,
  type Extension,
} from '@peculiar/x509'

export const MAX_SOURCE_BYTES = 2 * 1024 * 1024
export const MAX_ENTRIES = 20
export type ItemKind = 'certificate' | 'csr'
export type TimeStatus = 'active' | 'soon' | 'expired' | 'future' | 'request'

export interface InspectResult {
  id: string
  kind: ItemKind
  label: string
  source: string
  subject: string
  issuer: string | null
  serial: string | null
  notBefore: string | null
  notAfter: string | null
  daysRemaining: number | null
  timeStatus: TimeStatus
  signatureAlgorithm: string
  publicKeyAlgorithm: string
  sha256: string
  sans: { kind: string; value: string }[]
  ca: boolean | null
  keyUsages: string[]
  extendedKeyUsages: string[]
  extensions: { oid: string; critical: boolean; name: string }[]
  csrSignatureVerified: boolean | null
  selfIssued: boolean | null
}
export interface PemBlock { kind: ItemKind; content: string }

export function extractPemBlocks(text: string): PemBlock[] {
  if (/-----BEGIN [^-]*PRIVATE KEY-----/i.test(text)) {
    throw new Error('کلید خصوصی شناسایی شد. فقط Certificate یا CSR را وارد کنید؛ نه Private Key.')
  }
  const blocks: PemBlock[] = []
  const pattern = /-----BEGIN (CERTIFICATE|CERTIFICATE REQUEST|NEW CERTIFICATE REQUEST)-----([\s\S]*?)-----END \1-----/g
  let match: RegExpExecArray | null
  while ((match = pattern.exec(text)) !== null) {
    const base64 = match[2].replace(/\s/g, '')
    if (!base64 || !/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) {
      throw new Error('محتوای Base64 فایل PEM معتبر نیست.')
    }
    blocks.push({ kind: match[1] === 'CERTIFICATE' ? 'certificate' : 'csr', content: match[0] })
    if (blocks.length > MAX_ENTRIES) throw new Error('حداکثر ۲۰ گواهی یا CSR در هر ورودی پشتیبانی می‌شود.')
  }
  if (!blocks.length) throw new Error('بلوک CERTIFICATE یا CERTIFICATE REQUEST پیدا نشد.')
  return blocks
}

function hex(data: ArrayBuffer): string {
  return Array.from(new Uint8Array(data), v => v.toString(16).padStart(2, '0').toUpperCase()).join('')
}
export async function fingerprint(data: ArrayBuffer): Promise<string> {
  return hex(await crypto.subtle.digest('SHA-256', data)).match(/../g)!.join(':')
}
export function validityStatus(from: Date, until: Date, now = new Date()):
  { state: TimeStatus; days: number } {
  const days = Math.ceil((until.getTime() - now.getTime()) / 86400000)
  if (now < from) return { state: 'future', days }
  if (now > until) return { state: 'expired', days }
  return { state: days <= 30 ? 'soon' : 'active', days }
}

const extensionNames: Record<string,string> = {
  '2.5.29.17':'Subject Alternative Name',
  '2.5.29.19':'Basic Constraints',
  '2.5.29.15':'Key Usage',
  '2.5.29.37':'Extended Key Usage',
  '2.5.29.14':'Subject Key Identifier',
  '2.5.29.35':'Authority Key Identifier',
  '2.5.29.31':'CRL Distribution Points',
  '1.3.6.1.5.5.7.1.1':'Authority Information Access',
  '2.5.29.32':'Certificate Policies',
}
const ekuNames: Record<string,string> = {
  '1.3.6.1.5.5.7.3.1':'Server authentication',
  '1.3.6.1.5.5.7.3.2':'Client authentication',
  '1.3.6.1.5.5.7.3.3':'Code signing',
  '1.3.6.1.5.5.7.3.4':'Email protection',
  '1.3.6.1.5.5.7.3.8':'Time stamping',
  '1.3.6.1.5.5.7.3.9':'OCSP signing',
}
function extensionSummary(items: Extension[]) {
  return items.map(e => ({ oid: e.type, name: extensionNames[e.type] ?? 'Other extension', critical: e.critical }))
}
function alternativeNames(items: Extension[]): {kind:string;value:string}[] {
  const ext = items.find(e => e.type === '2.5.29.17')
  if (!ext) return []
  try {
    return new SubjectAlternativeNameExtension(ext.rawData).names.items.map(item => ({
      kind: String(item.type), value: item.value,
    }))
  } catch { return [] }
}
function inspectExtensions(items: Extension[]) {
  let ca: boolean | null = null
  let keyUsages: string[] = []
  let extendedKeyUsages: string[] = []

  const constraints = items.find(e => e.type === '2.5.29.19')
  try { if (constraints) ca = new BasicConstraintsExtension(constraints.rawData).ca }
  catch { /* unknown encoding */ }
  const keyUsage = items.find(e => e.type === '2.5.29.15')
  try {
    if (keyUsage) {
      const flags = new KeyUsagesExtension(keyUsage.rawData).usages
      const names: [number,string][] = [
        [1,'Digital signature'], [2,'Content commitment'], [4,'Key encipherment'],
        [8,'Data encipherment'], [16,'Key agreement'], [32,'Certificate signing'],
        [64,'CRL signing'], [128,'Encipher only'], [256,'Decipher only'],
      ]
      keyUsages = names.filter(([flag]) => (flags & flag) !== 0).map(([, name]) => name)
    }
  } catch { /* unknown encoding */ }
  const eku = items.find(e => e.type === '2.5.29.37')
  try {
    if (eku) extendedKeyUsages = new ExtendedKeyUsageExtension(eku.rawData).usages
      .map(oid => ekuNames[String(oid)] ?? String(oid))
  } catch { /* unknown encoding */ }
  return { ca, keyUsages, extendedKeyUsages }
}
function signatureLabel(alg: {name:string;hash?:{name:string}}) {
  return [alg.name, alg.hash?.name].filter(Boolean).join(' / ')
}
function keyLabel(alg: {name:string;namedCurve?:string;modulusLength?:number}) {
  return [alg.name, alg.namedCurve, alg.modulusLength ? alg.modulusLength + ' bit' : null]
    .filter(Boolean).join(' / ')
}

async function parseBlock(block: PemBlock, index: number): Promise<InspectResult> {
  if (block.kind === 'certificate') {
    const cert = new X509Certificate(block.content)
    const dates = validityStatus(cert.notBefore, cert.notAfter)
    return {
      id: String(index), kind:'certificate', source:block.content,
      label: cert.subject.split(',')[0] || 'Certificate ' + (index + 1),
      subject:cert.subject, issuer:cert.issuer, serial:cert.serialNumber,
      notBefore:cert.notBefore.toISOString(), notAfter:cert.notAfter.toISOString(),
      daysRemaining:dates.days, timeStatus:dates.state,
      signatureAlgorithm:signatureLabel(cert.signatureAlgorithm),
      publicKeyAlgorithm:keyLabel(cert.publicKey.algorithm),
      sha256:await fingerprint(cert.rawData), sans:alternativeNames(cert.extensions),
      ...inspectExtensions(cert.extensions), extensions:extensionSummary(cert.extensions),
      csrSignatureVerified:null, selfIssued:cert.subject === cert.issuer,
    }
  }

  const csr = new Pkcs10CertificateRequest(block.content)
  let verified: boolean | null = null
  try { verified = await csr.verify() } catch { /* unsupported algorithm in this browser */ }
  return {
    id:String(index), kind:'csr', source:block.content,
    label:csr.subject.split(',')[0] || 'CSR ' + (index + 1),
    subject:csr.subject, issuer:null, serial:null, notBefore:null, notAfter:null,
    daysRemaining:null, timeStatus:'request',
    signatureAlgorithm:signatureLabel(csr.signatureAlgorithm),
    publicKeyAlgorithm:keyLabel(csr.publicKey.algorithm),
    sha256:await fingerprint(csr.rawData), sans:alternativeNames(csr.extensions),
    ...inspectExtensions(csr.extensions), extensions:extensionSummary(csr.extensions),
    csrSignatureVerified:verified, selfIssued:null,
  }
}

export async function inspectPem(text: string): Promise<InspectResult[]> {
  if (new TextEncoder().encode(text).byteLength > MAX_SOURCE_BYTES) {
    throw new Error('حجم ورودی بیشتر از ۲ مگابایت است.')
  }
  const blocks = extractPemBlocks(text)
  const reports: InspectResult[] = []
  for (const [index, block] of blocks.entries()) {
    try { reports.push(await parseBlock(block,index)) }
    catch { throw new Error('بلوک شماره ' + (index + 1) + ' معتبر یا قابل تحلیل نیست.') }
  }
  return reports
}

export async function inspectFile(file: File): Promise<InspectResult[]> {
  if (file.size > MAX_SOURCE_BYTES) throw new Error('حداکثر حجم فایل ۲ مگابایت است.')
  if (/\.(p12|pfx|key)$/i.test(file.name)) {
    throw new Error('فایل‌های PFX/P12 و کلید خصوصی پشتیبانی نمی‌شوند.')
  }
  const data = await file.arrayBuffer()
  if (!data.byteLength) throw new Error('فایل خالی است.')
  const prefix = new TextDecoder().decode(data.slice(0,96))
  if (/^\uFEFF?\s*-----BEGIN/.test(prefix)) {
    return inspectPem(new TextDecoder().decode(data))
  }
  if (/\.(pem|txt)$/i.test(file.name)) {
    throw new Error('در فایل متنی بلوک PEM پیدا نشد.')
  }
  // DER is binary. Attempt X.509, then PKCS#10; never interpret private keys.
  const encoded = Array.from(new Uint8Array(data), v => String.fromCharCode(v)).join('')
  const b64 = btoa(encoded)
  const certLabel = 'CERTIFICATE'
  const csrLabel = 'CERTIFICATE REQUEST'
  const makePem = (label:string):string =>
    '-----BEGIN ' + label + '-----\n' + b64 + '\n-----END ' + label + '-----'
  const preferred: ItemKind = /\.csr$/i.test(file.name) ? 'csr' : 'certificate'
  const orders: ItemKind[] = [preferred, preferred === 'csr' ? 'certificate' : 'csr']
  for (const kind of orders) {
    try {
      return [await parseBlock({kind,content:makePem(kind === 'csr' ? csrLabel : certLabel)},0)]
    } catch { /* Try the other ASN.1 structure */ }
  }
  throw new Error('فرمت DER معتبر گواهی یا CSR شناسایی نشد.')
}
