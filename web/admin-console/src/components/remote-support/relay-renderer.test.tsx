import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import { RelayRenderer } from './relay-renderer'

// The reconnect path when every socket needs its own URL: the sponsor's watch
// opens with a one-use ticket, so a reconnect on the same URL could only be
// refused. resolveWsUrl is asked for a fresh one before each reconnect, and
// when it is refused the viewer stops and says so instead of retrying.

class FakeSocket {
  static opened: string[] = []
  static last: FakeSocket | null = null
  binaryType = ''
  readyState = 0
  onopen: (() => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((ev: MessageEvent) => void) | null = null
  constructor(public url: string) {
    FakeSocket.opened.push(url)
    FakeSocket.last = this
  }
  send() {}
  close() {}
}

class FakeDecoder {
  configure() {}
  decode() {}
  close() {}
}

describe('RelayRenderer reconnects', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    FakeSocket.opened = []
    FakeSocket.last = null
    vi.stubGlobal('WebSocket', FakeSocket)
    vi.stubGlobal('VideoDecoder', FakeDecoder)
  })
  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('asks resolveWsUrl for a fresh URL before reconnecting', async () => {
    const resolve = vi.fn().mockResolvedValue('wss://idp.test/watch?ticket=t-2')
    render(<RelayRenderer wsUrl="wss://idp.test/watch?ticket=t-1" resolveWsUrl={resolve} mode="view" onEnd={() => {}} />)
    expect(FakeSocket.opened).toEqual(['wss://idp.test/watch?ticket=t-1'])
    expect(resolve).not.toHaveBeenCalled()

    await act(async () => {
      FakeSocket.last!.onclose!()
      await vi.advanceTimersByTimeAsync(1000)
    })
    expect(resolve).toHaveBeenCalledTimes(1)
    expect(FakeSocket.opened).toEqual(['wss://idp.test/watch?ticket=t-1', 'wss://idp.test/watch?ticket=t-2'])
  })

  it('stops and says so when a fresh URL is refused', async () => {
    const resolve = vi.fn().mockRejectedValue(new Error('step_up_required'))
    render(<RelayRenderer wsUrl="wss://idp.test/watch?ticket=t-1" resolveWsUrl={resolve} mode="view" onEnd={() => {}} />)
    await act(async () => {
      FakeSocket.last!.onclose!()
      await vi.advanceTimersByTimeAsync(1000)
    })
    expect(FakeSocket.opened).toHaveLength(1)
    expect(screen.getAllByText(/could not be reopened/i).length).toBeGreaterThan(0)
  })

  it('reconnects on the same URL when no resolver is given', async () => {
    render(<RelayRenderer wsUrl="wss://idp.test/ws" mode="view" onEnd={() => {}} />)
    await act(async () => {
      FakeSocket.last!.onclose!()
      await vi.advanceTimersByTimeAsync(1000)
    })
    expect(FakeSocket.opened).toEqual(['wss://idp.test/ws', 'wss://idp.test/ws'])
  })
})
