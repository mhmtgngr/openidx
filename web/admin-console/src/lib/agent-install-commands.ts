// Copy-paste deployment commands for a freshly minted fleet enrollment token.
//
// The token is shown exactly once (the server stores only its hash), so the
// Deploy panel renders these right after the mint and never again. Every
// command embeds the token and the server URL; nothing here is a secret the
// operator did not just receive.
//
// Windows paths use agent/scripts/Install-OpenIDXAgent.ps1 (manifest + SHA-256
// + Authenticode checked before msiexec) or the MSI directly with its public
// properties: SERVER_URL, ENROLL_TOKEN and KEEP_ENROLL_TOKEN=1, which seals
// the token so a machine installed before its network is up finishes
// enrolling on its own. Linux uses /downloads/install.sh, whose --code
// accepts an enrollment token as well as a session code.

export type InstallTarget = 'intune' | 'gpo' | 'manual' | 'linux'

export const INSTALL_TARGETS: InstallTarget[] = ['intune', 'gpo', 'manual', 'linux']

export interface InstallCommand {
  /** i18n key suffix under pages.agentFleet.deploy.steps */
  label: string
  value: string
}

export interface InstallCommandInput {
  serverUrl: string
  token: string
  /** MSI file name as served under /downloads (defaults to openidx-agent.msi). */
  msiName?: string
}

const SCRIPT = 'Install-OpenIDXAgent.ps1'

// psQuote single-quotes a PowerShell string literal.
function psQuote(s: string): string {
  return `'${s.replace(/'/g, "''")}'`
}

// shQuote single-quotes a POSIX shell word.
function shQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`
}

function trimServer(url: string): string {
  return url.trim().replace(/\/+$/, '')
}

export function installCommands(target: InstallTarget, input: InstallCommandInput): InstallCommand[] {
  const server = trimServer(input.serverUrl)
  const token = input.token
  const msi = input.msiName || 'openidx-agent.msi'
  const scriptArgs = `-ServerUrl ${psQuote(server)} -EnrollToken ${psQuote(token)}`
  const msiProps = `SERVER_URL="${server}" ENROLL_TOKEN="${token}" KEEP_ENROLL_TOKEN=1`

  switch (target) {
    case 'intune':
      return [
        { label: 'download', value: `${server}/downloads/${SCRIPT}` },
        {
          label: 'installCommand',
          value: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\${SCRIPT} ${scriptArgs}`,
        },
        {
          label: 'uninstallCommand',
          value: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\${SCRIPT} -Uninstall`,
        },
        {
          label: 'detectionScript',
          value: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\${SCRIPT} -Detect`,
        },
      ]
    case 'gpo':
      return [
        { label: 'download', value: `${server}/downloads/${msi}` },
        {
          label: 'startupScript',
          value: `msiexec.exe /i "\\\\<fileserver>\\<share>\\${msi}" /qn /norestart ${msiProps}`,
        },
      ]
    case 'manual':
      return [
        {
          label: 'elevatedPowerShell',
          value:
            `Invoke-WebRequest -UseBasicParsing ${psQuote(`${server}/downloads/${SCRIPT}`)} -OutFile "$env:TEMP\\${SCRIPT}"; ` +
            `& "$env:TEMP\\${SCRIPT}" ${scriptArgs}`,
        },
        {
          label: 'msiDirect',
          value: `msiexec.exe /i ${msi} /qn /norestart ${msiProps}`,
        },
      ]
    case 'linux':
      return [
        {
          label: 'shell',
          value: `curl -fsSL ${shQuote(`${server}/downloads/install.sh`)} | sudo sh -s -- --server ${shQuote(server)} --code ${shQuote(token)}`,
        },
      ]
  }
}
