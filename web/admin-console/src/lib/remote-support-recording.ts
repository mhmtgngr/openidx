// A remote-support session's recording, as the console fetches it. The server
// serves every recording as WebM: a staff session's as the viewer's browser
// stored it, a vendor session's remuxed from the broker's IVF (no re-encode).
// The endpoint wants the Authorization header, which neither a link nor a
// <video src> can send, so the recording is fetched as a blob.

export function recordingURL(sessionId: string): string {
  return `/api/v1/access/remote-support/sessions/${sessionId}/recording`
}

export async function fetchRecording(sessionId: string): Promise<Blob> {
  const token = localStorage.getItem('token')
  const resp = await fetch(recordingURL(sessionId), {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!resp.ok) throw new Error(`recording fetch failed: ${resp.status}`)
  return resp.blob()
}

// saveRecording hands the blob to the browser as a download.
export function saveRecording(sessionId: string, blob: Blob) {
  const objectUrl = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = objectUrl
  a.download = `openidx-recording-${sessionId}.webm`
  a.click()
  URL.revokeObjectURL(objectUrl)
}
