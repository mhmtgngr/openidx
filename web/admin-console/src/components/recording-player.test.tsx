import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'

vi.mock('../lib/api', () => ({ api: { get: vi.fn() } }))

import { api } from '../lib/api'
import { RecordingPlayer } from './recording-player'
import { formatRecordingTime } from '../lib/recording-time'

const get = api.get as unknown as ReturnType<typeof vi.fn>

// A tiny but real guacd recording: a 64x48 screen, a filled rectangle, and
// two frames 1.5 s apart, in the Guacamole protocol guacd writes to disk.
function ins(...args: string[]): string {
  return args.map((a) => `${a.length}.${a}`).join(',') + ';'
}
const recording = [
  ins('size', '0', '64', '48'),
  ins('rect', '0', '0', '0', '64', '48'),
  ins('cfill', '14', '0', '255', '0', '0', '255'),
  ins('sync', '1000'),
  ins('rect', '0', '0', '0', '32', '24'),
  ins('cfill', '14', '0', '0', '0', '255', '255'),
  ins('sync', '2500'),
].join('')

describe('formatRecordingTime', () => {
  it('formats minutes and hours', () => {
    expect(formatRecordingTime(0)).toBe('0:00')
    expect(formatRecordingTime(65_000)).toBe('1:05')
    expect(formatRecordingTime(3_725_000)).toBe('1:02:05')
    expect(formatRecordingTime(-5)).toBe('0:00')
  })
})

describe('RecordingPlayer', () => {
  beforeEach(() => vi.clearAllMocks())

  it('fetches the recording through the API client as a blob and plays it', async () => {
    get.mockResolvedValue(new Blob([recording]))
    render(<RecordingPlayer url="/api/v1/access/pam/sessions/s1/recording" title="DC01" onClose={() => {}} />)
    expect(get).toHaveBeenCalledWith('/api/v1/access/pam/sessions/s1/recording', { responseType: 'blob' })
    const play = await screen.findByRole('button', { name: 'Play' })
    // The recording's frames span 1.5 s.
    expect(screen.getByText('0:00 / 0:01')).toBeInTheDocument()
    expect(screen.getByLabelText('Position in the recording')).toHaveAttribute('max', '1500')
    // The display was mounted.
    expect(screen.getByTestId('recording-display').children.length).toBe(1)
    fireEvent.click(play)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Pause' })).toBeInTheDocument())
  })

  it('says a purged recording is gone', async () => {
    get.mockRejectedValue({ response: { status: 410 } })
    render(<RecordingPlayer url="/x" title="DC01" onClose={() => {}} />)
    expect(await screen.findByRole('alert')).toHaveTextContent(/removed by the retention policy/i)
  })

  it('says a recording that cannot be loaded failed', async () => {
    get.mockRejectedValue({ response: { status: 500 } })
    render(<RecordingPlayer url="/x" title="DC01" onClose={() => {}} />)
    expect(await screen.findByRole('alert')).toHaveTextContent(/could not be loaded/i)
  })
})
