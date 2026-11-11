import { describe, expect, it } from 'vitest'
import { hashFor, isBare, portFromHash } from './route'
import { portId } from './view'

describe('the address of a lane', () => {
  it('is the protocol and the port, plainly', () => {
    expect(portId({ proto: 'tcp', port: 5432 })).toBe('tcp-5432')
    expect(portId({ proto: 'UDP', port: 53 })).toBe('udp-53')
    expect(hashFor('tcp-5432')).toBe('#tcp-5432')
    expect(hashFor(null)).toBe('')
  })

  it('reads back to the same lane', () => {
    expect(portFromHash('#tcp-5432')).toBe('tcp-5432')
    expect(portFromHash('tcp-22')).toBe('tcp-22')
    expect(portFromHash('#UDP-53')).toBe('udp-53')
    expect(portFromHash(hashFor(portId({ proto: 'sctp', port: 9899 })))).toBe('sctp-9899')
    // a number has one spelling
    expect(portFromHash('#tcp-0080')).toBe('tcp-80')
  })

  it('names no lane when the hash is something else', () => {
    for (const hash of ['', '#', '#chart', '#own', '#fine-print', '#tcp-', '#tcp-0', '#tcp-65536', '#tcp-123456', '#-22', '#tcp-22-passage', '#tcp-22/x', '#tcp-22"><i>']) {
      expect(portFromHash(hash), hash).toBeNull()
    }
  })

  it('tells the bare page from a part of it', () => {
    expect(isBare('')).toBe(true)
    expect(isBare('#')).toBe(true)
    expect(isBare('#chart')).toBe(false)
    expect(isBare('#tcp-22')).toBe(false)
  })
})
