// Minimal types for the part of guacamole-common-js (Apache-2.0) the console
// uses: playing a session recording. The package ships no declarations.
declare module 'guacamole-common-js' {
  namespace Guacamole {
    class Status {
      constructor(code: number, message?: string)
      code: number
      message?: string
      static Code: { SERVER_ERROR: number; [name: string]: number }
    }
    class Parser {
      receive(packet: string): void
      oninstruction: ((opcode: string, args: string[]) => void) | null
    }
    class Tunnel {
      connect(data?: string): void
      disconnect(): void
      sendMessage(...elements: unknown[]): void
      setState(state: number): void
      state: number
      oninstruction: ((opcode: string, args: string[]) => void) | null
      onerror: ((status: Status) => void) | null
      onstatechange: ((state: number) => void) | null
      static State: { CONNECTING: number; OPEN: number; CLOSED: number; UNSTABLE: number }
    }
    class Display {
      getElement(): HTMLElement
      getWidth(): number
      getHeight(): number
      scale(scale: number): void
      onresize: ((width: number, height: number) => void) | null
    }
    class SessionRecording {
      constructor(source: Blob | Tunnel)
      connect(data?: string): void
      disconnect(): void
      abort(): void
      getDisplay(): Display
      getPosition(): number
      getDuration(): number
      isPlaying(): boolean
      play(): void
      pause(): void
      seek(position: number, callback?: () => void): void
      onload: (() => void) | null
      onerror: ((message: string) => void) | null
      onabort: (() => void) | null
      onprogress: ((duration: number, parsedSize: number) => void) | null
      onplay: (() => void) | null
      onpause: (() => void) | null
      onseek: ((position: number, current: number, total: number) => void) | null
    }
  }
  export default Guacamole
}
