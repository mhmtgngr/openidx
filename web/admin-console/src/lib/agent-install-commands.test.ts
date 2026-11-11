import { describe, expect, it } from 'vitest'
import { INSTALL_TARGETS, installCommands } from './agent-install-commands'

const input = { serverUrl: 'https://idp.example.com/', token: '11111111-2222-3333-4444-555555555555' }

describe('installCommands', () => {
  it.each(INSTALL_TARGETS)('renders the %s commands', (target) => {
    expect(installCommands(target, input)).toMatchSnapshot()
  })

  it('carries the token and server into every command that enrolls', () => {
    for (const target of INSTALL_TARGETS) {
      const all = installCommands(target, input).map((c) => c.value).join('\n')
      expect(all).toContain('https://idp.example.com')
      expect(all).not.toContain('https://idp.example.com//')
      if (target !== 'intune') expect(all).toContain(input.token)
    }
    const intune = installCommands('intune', input).find((c) => c.label === 'installCommand')!.value
    expect(intune).toContain(`-EnrollToken '${input.token}'`)
    const gpo = installCommands('gpo', input)[1].value
    expect(gpo).toContain('KEEP_ENROLL_TOKEN=1')
    expect(gpo).toContain(`ENROLL_TOKEN="${input.token}"`)
  })

  it('quotes a single quote in a PowerShell literal', () => {
    const cmds = installCommands('manual', { serverUrl: "https://x'y", token: 't' })
    expect(cmds[0].value).toContain("'https://x''y'")
  })
})
