// parseFingerprints turns the pinned-fingerprints text area of a PAM entry
// into the list the API takes: one per line or comma-separated, blanks
// dropped. The server normalises and validates each one.
export function parseFingerprints(text: string): string[] {
  return text.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
}
