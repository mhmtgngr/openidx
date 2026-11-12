import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

vi.mock('../lib/api', () => ({ baseURL: '' }))

import { MfaInlineEnroll } from './mfa-inline-enroll'

const ok = (body: unknown) => Promise.resolve(new Response(JSON.stringify(body), { status: 200 }))

describe('MfaInlineEnroll SMS', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('offers no SMS option when the session does not allow sms', () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => ok({ qr_code_url: 'otpauth://x', manual_key: 'K' }))
    render(<MfaInlineEnroll enrollSession="es" methods={['totp', 'webauthn']} onDone={vi.fn()} />)
    expect(screen.queryByRole('button', { name: /text message/i })).toBeNull()
  })

  it('sends the code to the phone, then completes with the code', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((url) =>
      String(url).endsWith('/sms/begin') ? ok({ sent: true }) : ok({ redirect_url: 'https://app/cb?code=c' }),
    )
    const onDone = vi.fn()
    const user = userEvent.setup()
    render(<MfaInlineEnroll enrollSession="es" methods={['sms']} onDone={onDone} />)

    await user.type(screen.getByLabelText(/country code/i), '90')
    await user.type(screen.getByLabelText(/mobile number/i), '5321234567')
    await user.click(screen.getByRole('button', { name: /send code/i }))

    const [beginURL, beginInit] = fetchMock.mock.calls[0]
    expect(String(beginURL)).toContain('/oauth/mfa/enroll/sms/begin')
    expect(JSON.parse(String(beginInit?.body))).toEqual({ enroll_session: 'es', phone_number: '5321234567', country_code: '+90' })

    await user.type(await screen.findByLabelText(/code/i), '123456')
    await user.click(screen.getByRole('button', { name: /verify/i }))

    const [finishURL, finishInit] = fetchMock.mock.calls[1]
    expect(String(finishURL)).toContain('/oauth/mfa/enroll/sms/finish')
    expect(JSON.parse(String(finishInit?.body))).toEqual({ enroll_session: 'es', code: '123456' })
    expect(onDone).toHaveBeenCalledWith({ redirect_url: 'https://app/cb?code=c' })
  })

  it('shows the server error for a wrong code', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((url) =>
      String(url).endsWith('/sms/begin')
        ? ok({ sent: true })
        : Promise.resolve(new Response(JSON.stringify({ error_description: 'The code does not match.' }), { status: 401 })),
    )
    const onDone = vi.fn()
    const user = userEvent.setup()
    render(<MfaInlineEnroll enrollSession="es" methods={['totp', 'sms']} onDone={onDone} />)
    await user.click(screen.getByRole('button', { name: /text message/i }))
    await user.type(screen.getByLabelText(/mobile number/i), '5551234567')
    await user.type(screen.getByLabelText(/country code/i), '1')
    await user.click(screen.getByRole('button', { name: /send code/i }))
    await user.type(await screen.findByLabelText(/code/i), '000000')
    await user.click(screen.getByRole('button', { name: /verify/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent('The code does not match.')
    expect(onDone).not.toHaveBeenCalled()
  })
})
