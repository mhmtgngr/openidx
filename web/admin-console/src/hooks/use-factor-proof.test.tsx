import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { useFactorProof } from './use-factor-proof'
import { ProofCancelled, type FactorProof } from '../lib/factor-proof'

// The refusal the identity service answers a factor change with when its
// proof is missing or wrong (internal/identity/factor_proof.go).
function refusal(error: string, accepts: string[]) {
  return { response: { status: 403, data: { error, error_description: 'x', accepts } } }
}

function Harness({ action }: { action: (proof: FactorProof) => Promise<string> }) {
  const { withProof, dialog } = useFactorProof()
  const [outcome, setOutcome] = useState('')
  return (
    <div>
      {dialog}
      <button
        onClick={() =>
          withProof(action).then(
            (v) => setOutcome('done:' + v),
            (e) => setOutcome(e instanceof ProofCancelled ? 'cancelled' : 'failed:' + (e?.response?.data?.error ?? 'other')),
          )
        }
      >
        change
      </button>
      <p data-testid="outcome">{outcome}</p>
    </div>
  )
}

describe('useFactorProof', () => {
  it('runs a change that needs no proof without asking', async () => {
    const action = vi.fn().mockResolvedValue('ok')
    render(<Harness action={action} />)
    await userEvent.click(screen.getByRole('button', { name: 'change' }))
    await waitFor(() => expect(screen.getByTestId('outcome')).toHaveTextContent('done:ok'))
    expect(action).toHaveBeenCalledTimes(1)
    expect(action).toHaveBeenCalledWith({})
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('asks for the password when the server wants it, and sends it with the change', async () => {
    const action = vi
      .fn()
      .mockRejectedValueOnce(refusal('reauthentication_required', ['current_password']))
      .mockResolvedValueOnce('ok')
    render(<Harness action={action} />)
    await userEvent.click(screen.getByRole('button', { name: 'change' }))

    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('Enter your current password to make this change.')
    expect(screen.queryByLabelText('Authenticator code')).not.toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('Current password'), 'hunter2-hunter2')
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))

    await waitFor(() => expect(screen.getByTestId('outcome')).toHaveTextContent('done:ok'))
    expect(action).toHaveBeenLastCalledWith({ current_password: 'hunter2-hunter2' })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('offers the authenticator code where the change accepts one', async () => {
    const action = vi
      .fn()
      .mockRejectedValueOnce(refusal('reauthentication_required', ['current_password', 'totp_code']))
      .mockResolvedValueOnce('ok')
    render(<Harness action={action} />)
    await userEvent.click(screen.getByRole('button', { name: 'change' }))

    await screen.findByRole('dialog')
    await userEvent.type(screen.getByLabelText('Authenticator code'), '123456')
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))

    await waitFor(() => expect(screen.getByTestId('outcome')).toHaveTextContent('done:ok'))
    expect(action).toHaveBeenLastCalledWith({ totp_code: '123456' })
  })

  it('says so when the proof is wrong, and asks again', async () => {
    const action = vi
      .fn()
      .mockRejectedValueOnce(refusal('reauthentication_required', ['current_password']))
      .mockRejectedValueOnce(refusal('reauthentication_failed', ['current_password']))
      .mockResolvedValueOnce('ok')
    render(<Harness action={action} />)
    await userEvent.click(screen.getByRole('button', { name: 'change' }))

    await screen.findByRole('dialog')
    await userEvent.type(screen.getByLabelText('Current password'), 'wrong-password')
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('That password is not correct.')
    expect(screen.getByLabelText('Current password')).toHaveValue('')

    await userEvent.type(screen.getByLabelText('Current password'), 'right-password')
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(screen.getByTestId('outcome')).toHaveTextContent('done:ok'))
    expect(action).toHaveBeenCalledTimes(3)
    expect(action).toHaveBeenLastCalledWith({ current_password: 'right-password' })
  })

  it('fails the change with ProofCancelled when the prompt is closed', async () => {
    const action = vi.fn().mockRejectedValue(refusal('reauthentication_required', ['current_password']))
    render(<Harness action={action} />)
    await userEvent.click(screen.getByRole('button', { name: 'change' }))

    await screen.findByRole('dialog')
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.getByTestId('outcome')).toHaveTextContent('cancelled'))
    expect(action).toHaveBeenCalledTimes(1)
  })

  it('does not ask when the proof cannot be given here, and passes the refusal on', async () => {
    for (const code of ['reauthentication_locked', 'reauthentication_unavailable']) {
      const action = vi.fn().mockRejectedValue(refusal(code, code === 'reauthentication_locked' ? ['current_password'] : []))
      const { unmount } = render(<Harness action={action} />)
      await userEvent.click(screen.getByRole('button', { name: 'change' }))
      await waitFor(() => expect(screen.getByTestId('outcome')).toHaveTextContent('failed:' + code))
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      unmount()
    }
  })
})
