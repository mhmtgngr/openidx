import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { RecordingPlayer } from './recording-player'

// The console's player for a remote-support recording: fetched with the
// bearer (a <video src> cannot send it), played from an object URL, and
// released when the dialog closes.

describe('RecordingPlayer', () => {
  const fetchMock = vi.fn()
  beforeEach(() => {
    localStorage.setItem('token', 'tok-1')
    vi.stubGlobal('fetch', fetchMock)
    URL.createObjectURL = vi.fn(() => 'blob:recording-1')
    URL.revokeObjectURL = vi.fn()
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    fetchMock.mockReset()
    localStorage.removeItem('token')
  })

  it('fetches the recording with the bearer and plays it from an object URL', async () => {
    fetchMock.mockResolvedValue({ ok: true, blob: async () => new Blob(['webm'], { type: 'video/webm' }) })
    const { unmount } = render(<RecordingPlayer sessionId="0123456789abcdef" onClose={() => {}} />)
    const video = await screen.findByTestId('recording-video')
    expect(video).toHaveAttribute('src', 'blob:recording-1')
    expect(video).toHaveAttribute('controls')
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/access/remote-support/sessions/0123456789abcdef/recording',
      { headers: { Authorization: 'Bearer tok-1' } })
    expect(screen.getByRole('button', { name: /Download/ })).toBeInTheDocument()
    unmount()
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:recording-1')
  })

  it('says so when the recording cannot be loaded', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 404 })
    render(<RecordingPlayer sessionId="0123456789abcdef" onClose={() => {}} />)
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/could not be loaded/i))
    expect(screen.queryByTestId('recording-video')).not.toBeInTheDocument()
  })
})
