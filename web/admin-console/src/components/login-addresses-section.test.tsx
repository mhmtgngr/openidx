import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({ api: { get: vi.fn(), post: vi.fn(), delete: vi.fn() } }))
const toast = vi.fn()
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast }) }))

import { LoginAddressesSection } from './login-addresses-section'
import { api } from '../lib/api'

const get = vi.mocked(api.get)
const post = vi.mocked(api.post)
const del = vi.mocked(api.delete)

const data = {
  email: 'hana@corp.example',
  mail: '',
  addresses: [{ id: 'a1', address: 'hana.real@company.example', created_at: '2026-11-23T10:00:00Z' }],
}

function mount() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
      <LoginAddressesSection userId="u1" />
    </QueryClientProvider>,
  )
}

describe('LoginAddressesSection', () => {
  beforeEach(() => {
    get.mockReset().mockResolvedValue(data as never)
    post.mockReset()
    del.mockReset()
    toast.mockReset()
  })

  it('shows what already works and the addresses an administrator gave', async () => {
    mount()
    expect(await screen.findByText('hana.real@company.example')).toBeInTheDocument()
    expect(screen.getByText('hana@corp.example')).toBeInTheDocument()
    expect(screen.getByText('from the account')).toBeInTheDocument()
    expect(get).toHaveBeenCalledWith('/api/v1/identity/users/u1/login-addresses')
  })

  it('adds an address, trimmed, and reloads the list', async () => {
    post.mockResolvedValue({} as never)
    mount()
    await userEvent.type(await screen.findByLabelText('Add a sign-in address'), '  New.Mail@Company.Example ')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith('/api/v1/identity/users/u1/login-addresses', { address: 'New.Mail@Company.Example' }),
    )
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
  })

  it('says plainly when the address belongs to someone else', async () => {
    post.mockRejectedValue({ response: { status: 409, data: { error: 'address_in_use' } } })
    mount()
    await userEvent.type(await screen.findByLabelText('Add a sign-in address'), 'x@company.example')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: 'This address already belongs to another account.' })),
    )
  })

  it('removes an address only after a confirmation', async () => {
    del.mockResolvedValue({} as never)
    mount()
    await userEvent.click(await screen.findByRole('button', { name: 'Remove hana.real@company.example' }))
    expect(del).not.toHaveBeenCalled()
    await userEvent.click(await screen.findByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/api/v1/identity/users/u1/login-addresses/a1'))
  })

  it('does not offer Add for an empty field', async () => {
    mount()
    expect(await screen.findByRole('button', { name: 'Add' })).toBeDisabled()
  })
})
