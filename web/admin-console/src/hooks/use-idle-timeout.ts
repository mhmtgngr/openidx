import { useState, useEffect, useCallback, useRef } from 'react'

interface UseIdleTimeoutOptions {
  idleTimeout: number // seconds, 0 = disabled
  warningTime?: number // seconds before timeout to show warning (default 300 = 5 min)
  onIdle?: () => void
  onWarning?: () => void
  enabled?: boolean
}

interface UseIdleTimeoutReturn {
  isIdle: boolean
  isWarning: boolean
  remainingTime: number // seconds
  resetTimer: () => void
}

export function useIdleTimeout({
  idleTimeout,
  warningTime = 300,
  onIdle,
  onWarning,
  enabled = true,
}: UseIdleTimeoutOptions): UseIdleTimeoutReturn {
  const [isIdle, setIsIdle] = useState(false)
  const [isWarning, setIsWarning] = useState(false)
  const [remainingTime, setRemainingTime] = useState(idleTimeout)
  const lastActivityRef = useRef(Date.now())
  const warningFiredRef = useRef(false)
  const onIdleRef = useRef(onIdle)
  const onWarningRef = useRef(onWarning)

  // Keep callback refs up to date without triggering effect re-runs
  useEffect(() => {
    onIdleRef.current = onIdle
  }, [onIdle])

  useEffect(() => {
    onWarningRef.current = onWarning
  }, [onWarning])

  const resetTimer = useCallback(() => {
    lastActivityRef.current = Date.now()
    setIsIdle(false)
    setIsWarning(false)
    setRemainingTime(idleTimeout)
    warningFiredRef.current = false
  }, [idleTimeout])

  useEffect(() => {
    if (!enabled || idleTimeout <= 0) return

    // Reset state when timeout value changes
    lastActivityRef.current = Date.now()
    setRemainingTime(idleTimeout)
    setIsIdle(false)
    setIsWarning(false)
    warningFiredRef.current = false

    const handleActivity = () => {
      // Only reset on activity if we are not yet in the warning phase
      if (!warningFiredRef.current) {
        lastActivityRef.current = Date.now()
      }
    }

    const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click']
    events.forEach((event) => window.addEventListener(event, handleActivity, { passive: true }))

    const interval = setInterval(() => {
      const elapsed = Math.floor((Date.now() - lastActivityRef.current) / 1000)
      const remaining = Math.max(0, idleTimeout - elapsed)
      setRemainingTime(remaining)

      if (remaining <= 0) {
        setIsIdle(true)
        setIsWarning(false)
        onIdleRef.current?.()
      } else if (remaining <= warningTime && !warningFiredRef.current) {
        setIsWarning(true)
        warningFiredRef.current = true
        onWarningRef.current?.()
      }
    }, 1000)

    return () => {
      events.forEach((event) => window.removeEventListener(event, handleActivity))
      clearInterval(interval)
    }
  }, [enabled, idleTimeout, warningTime])

  return { isIdle, isWarning, remainingTime, resetTimer }
}
