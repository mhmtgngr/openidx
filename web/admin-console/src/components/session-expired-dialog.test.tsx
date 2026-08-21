import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { SessionExpiredDialog } from './session-expired-dialog'

describe('SessionExpiredDialog', () => {
  it('shows when open and calls onSignIn', () => {
    const onSignIn = vi.fn()
    render(<SessionExpiredDialog open onSignIn={onSignIn} />)
    expect(screen.getByText(/session ended/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    expect(onSignIn).toHaveBeenCalled()
  })
  it('renders nothing when closed', () => {
    const { container } = render(<SessionExpiredDialog open={false} onSignIn={() => {}} />)
    expect(container.textContent).toBe('')
  })
})
