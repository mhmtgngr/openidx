/// <reference types="node" />
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { API_SPECS } from './api-specs'

// The API-docs page shows exactly the specs api/openapi/ holds. Both
// directions matter: a listed file that does not exist is a 404 on the page,
// and an unlisted file is an API nobody can read on the page. For two months
// public/api-specs/ held ten hand-written files, three of them listed nowhere,
// and nothing compared them to anything.
const here = path.dirname(fileURLToPath(import.meta.url))
const SPEC_DIR = path.resolve(here, '../../../../api/openapi')

describe('API_SPECS', () => {
  const onDisk = fs
    .readdirSync(SPEC_DIR)
    .filter((f) => f.endsWith('.yaml'))
    .sort()
  const listed = API_SPECS.map((s) => s.file).sort()

  it('lists every canonical spec, and only canonical specs', () => {
    expect(listed).toEqual(onDisk)
  })

  it('names each spec once', () => {
    expect(new Set(API_SPECS.map((s) => s.id)).size).toBe(API_SPECS.length)
  })
})
