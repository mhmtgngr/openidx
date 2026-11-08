import Guacamole from 'guacamole-common-js'

// blobTunnel turns a downloaded recording into the Guacamole.Tunnel that
// SessionRecording reads from.
//
// SessionRecording accepts a Blob in its documentation, but in
// guacamole-common-js 1.5.0 the Blob branch reads an internal variable that is
// never assigned, and throws "Cannot read properties of undefined (reading
// 'size')" on construction. The Tunnel branch works and keeps its own Blob
// for seeking, so the recording is parsed here and replayed into a tunnel
// that is closed once the last instruction is delivered. The bytes never
// leave the page: they arrived through the authenticated API client.
export function blobTunnel(blob: Blob): Guacamole.Tunnel {
  const tunnel = new Guacamole.Tunnel()
  tunnel.connect = () => {
    tunnel.setState(Guacamole.Tunnel.State.OPEN)
    const parser = new Guacamole.Parser()
    parser.oninstruction = (opcode: string, args: string[]) => {
      tunnel.oninstruction?.(opcode, args)
    }
    readBlobText(blob)
      .then((text) => {
        parser.receive(text)
        tunnel.setState(Guacamole.Tunnel.State.CLOSED)
      })
      .catch((e: unknown) => {
        tunnel.onerror?.(new Guacamole.Status(Guacamole.Status.Code.SERVER_ERROR, String(e)))
        tunnel.setState(Guacamole.Tunnel.State.CLOSED)
      })
  }
  tunnel.disconnect = () => tunnel.setState(Guacamole.Tunnel.State.CLOSED)
  tunnel.sendMessage = () => {}
  return tunnel
}

// readBlobText reads a Blob as UTF-8 text with FileReader, which every browser
// and jsdom have (jsdom's Blob has no text()).
function readBlobText(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result ?? ''))
    reader.onerror = () => reject(reader.error)
    reader.readAsText(blob)
  })
}
