import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

vi.mock('../lib/api', () => ({
  api: {
    getPushDevices: vi.fn(),
    registerPushDevice: vi.fn(() => Promise.resolve({})),
    deletePushDevice: vi.fn(() => Promise.resolve()),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { PushDevicesPage } from './push-devices'
import { api } from '../lib/api'

const iphone = {
  id: 'd-1',
  device_name: 'Alice iPhone',
  device_model: 'iPhone 15',
  platform: 'ios',
  created_at: '2026-05-01T00:00:00Z',
  last_used_at: '2026-06-09T00:00:00Z',
}

const androidPhone = {
  id: 'd-2',
  device_name: 'Pixel Work',
  device_model: 'Pixel 8',
  platform: 'android',
  created_at: '2026-04-01T00:00:00Z',
  last_used_at: null,
}

describe('PushDevicesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.getPushDevices).mockResolvedValue([iphone, androidPhone])
  })

  it('renders the heading + subtitle + Enroll Device button', async () => {
    render(
      <MemoryRouter>
        <PushDevicesPage />
      </MemoryRouter>,
    )

    expect(
      await screen.findByText('Push Notification Devices'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/manage devices for push notification mfa verification/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /enroll device/i }),
    ).toBeInTheDocument()
  })

  it('lists each enrolled device with its name', async () => {
    render(
      <MemoryRouter>
        <PushDevicesPage />
      </MemoryRouter>,
    )

    expect(await screen.findByText('Alice iPhone')).toBeInTheDocument()
    expect(screen.getByText('Pixel Work')).toBeInTheDocument()

    // Devices count line in the card description.
    expect(screen.getByText(/2 devices enrolled/i)).toBeInTheDocument()
  })

  it('opens the enrollment form when the Enroll Device button is clicked', async () => {
    const user = userEvent.setup()
    render(
      <MemoryRouter>
        <PushDevicesPage />
      </MemoryRouter>,
    )
    await screen.findByText('Alice iPhone')

    await user.click(screen.getByRole('button', { name: /enroll device/i }))

    expect(
      await screen.findByText(/enroll push notification device/i),
    ).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/my iphone, work phone/i),
    ).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/iphone 15, pixel 8/i),
    ).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/push notification token/i),
    ).toBeInTheDocument()
  })

  it('renders the empty state when no devices are enrolled', async () => {
    vi.mocked(api.getPushDevices).mockResolvedValue([])

    render(
      <MemoryRouter>
        <PushDevicesPage />
      </MemoryRouter>,
    )

    expect(
      await screen.findByText(/no push notification devices enrolled yet/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/enroll a device to use push notifications for mfa verification/i),
    ).toBeInTheDocument()
  })
})
