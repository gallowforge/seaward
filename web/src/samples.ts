// The sample servers: samples/index.json at the root of the repository lists them, and the
// build copies it and the snapshot files beside the page.
import type { Sample } from './types'

const beside = (file: string) => new URL(file, document.baseURI).href

/** Keeps the entries that are whole: an id, a file name, a title and a description. */
export function readIndex(data: unknown): Sample[] {
  const list = Array.isArray(data) ? data : Array.isArray((data as { samples?: unknown })?.samples) ? (data as { samples: unknown[] }).samples : []
  const out: Sample[] = []
  for (const x of list as Partial<Sample>[]) {
    if (!x || typeof x.id !== 'string' || typeof x.file !== 'string') continue
    if (!/^[a-z0-9][a-z0-9-]*$/.test(x.id) || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(x.file)) continue
    if (out.some((s) => s.id === x.id)) continue
    out.push({ id: x.id, file: x.file, title: typeof x.title === 'string' && x.title ? x.title : x.id, description: typeof x.description === 'string' ? x.description : '' })
  }
  return out
}

export async function loadIndex(): Promise<Sample[]> {
  const r = await fetch(beside('samples/index.json'))
  if (!r.ok) throw new Error(`The list of samples did not load (HTTP ${r.status}).`)
  const list = readIndex(await r.json())
  if (list.length === 0) throw new Error('The list of samples is empty.')
  return list
}

export async function loadSnapshot(sample: Sample): Promise<string> {
  const r = await fetch(beside(`samples/${sample.file}`))
  if (!r.ok) throw new Error(`The sample ${sample.file} did not load (HTTP ${r.status}).`)
  return r.text()
}
