import { describe, expect, it } from 'vitest'
import cert from '../test-fixtures/cert.pem?raw'
import csr from '../test-fixtures/request.csr?raw'
import { extractPemBlocks, inspectPem, validityStatus, fingerprint } from './certificates'

describe('PEM parsing and safety', () => {
  it('recognizes X.509 and PKCS#10 (including bundles)', () => {
    expect(extractPemBlocks(cert)).toHaveLength(1)
    expect(extractPemBlocks(csr)[0].kind).toBe('csr')
    expect(extractPemBlocks(cert + '\n' + csr).map(x => x.kind)).toEqual(['certificate','csr'])
  })
  it('rejects private keys', () => {
    expect(() => extractPemBlocks('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----')).toThrow()
    expect(() => extractPemBlocks('-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----')).toThrow()
  })
  it('rejects invalid PEM', () => {
    expect(() => extractPemBlocks('not a certificate')).toThrow()
    expect(() => extractPemBlocks('-----BEGIN CERTIFICATE-----\n*&^\n-----END CERTIFICATE-----')).toThrow()
  })
})

describe('certificate inspector with real OpenSSL-generated fixtures', () => {
  it('parses a certificate with subject, issuer, SAN, validity and SHA-256', async () => {
    const [result] = await inspectPem(cert)
    expect(result.kind).toBe('certificate')
    expect(result.subject).toContain('certlab.example')
    expect(result.issuer).toContain('certlab.example')
    expect(result.notBefore).toBeTruthy()
    expect(result.notAfter).toBeTruthy()
    expect(result.sans.map(x=>x.value)).toContain('www.certlab.example')
    expect(result.sha256.split(':')).toHaveLength(32)
    expect(result.ca).toBe(false)
    expect(result.keyUsages).toContain('Digital signature')
    expect(result.keyUsages).toContain('Key encipherment')
    expect(result.extendedKeyUsages).toContain('Server authentication')
  })
  it('parses CSR and verifies its signature', async () => {
    const [result] = await inspectPem(csr)
    expect(result.kind).toBe('csr')
    expect(result.subject).toContain('certlab.example')
    expect(result.issuer).toBe(null)
    expect(result.notAfter).toBe(null)
    expect(result.sans.map(x=>x.value)).toContain('certlab.example')
    expect(result.csrSignatureVerified).toBe(true)
  })
  it('parses certificate and CSR together', async () => {
    const results = await inspectPem(cert+'\n'+csr)
    expect(results.map(x=>x.kind)).toEqual(['certificate','csr'])
  })
  it('computes the canonical uppercase SHA-256 fingerprint', async () => {
    const hash = await fingerprint(new TextEncoder().encode('test').buffer)
    expect(hash).toBe('9F:86:D0:81:88:4C:7D:65:9A:2F:EA:A0:C5:5A:D0:15:A3:BF:4F:1B:2B:0B:82:2C:D1:5D:6C:15:B0:F0:0A:08')
  })
})

describe('time validity is NOT chain trust',()=>{
  it('reports expired, future, and soon by local time',()=>{
    const now=new Date('2026-11-01T00:00:00Z')
    expect(validityStatus(new Date('2025-01-01'),new Date('2026-01-01'),now).state).toBe('expired')
    expect(validityStatus(new Date('2027-01-01'),new Date('2028-01-01'),now).state).toBe('future')
    expect(validityStatus(new Date('2026-01-01'),new Date('2026-11-10'),now).state).toBe('soon')
    expect(validityStatus(new Date('2026-01-01'),new Date('2027-01-01'),now).state).toBe('active')
  })
})
