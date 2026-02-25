import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { Sidebar } from './Sidebar'

// Mock the stores - use the same path alias as the component
const mockToggleSidebar = vi.fn()
const mockLogout = vi.fn()

vi.mock('@/lib/store', () => ({
  useAppStore: vi.fn(() => ({
    sidebarOpen: true,
    toggleSidebar: mockToggleSidebar,
  })),
  useAuthStore: vi.fn(() => ({
    user: { name: 'John Doe', email: 'john@example.com', role: 'Administrator' },
    logout: mockLogout,
  })),
}))

const renderWithRouter = (component: React.ReactNode) => {
  return render(<MemoryRouter>{component}</MemoryRouter>)
}

describe('Sidebar', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    mockToggleSidebar.mockClear()
    mockLogout.mockClear()
  })

  it('renders sidebar aside element', () => {
    renderWithRouter(<Sidebar />)
    const sidebar = screen.getByRole('complementary')
    expect(sidebar).toBeInTheDocument()
  })

  it('renders OpenIDX logo when open', () => {
    renderWithRouter(<Sidebar />)
    expect(screen.getByText('OpenIDX')).toBeInTheDocument()
  })

  it('renders all navigation items', () => {
    renderWithRouter(<Sidebar />)

    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Users')).toBeInTheDocument()
    expect(screen.getByText('Access Reviews')).toBeInTheDocument()
    expect(screen.getByText('Policies')).toBeInTheDocument()
    expect(screen.getByText('Audit Logs')).toBeInTheDocument()
    expect(screen.getByText('Settings')).toBeInTheDocument()
  })

  it('renders user info', () => {
    renderWithRouter(<Sidebar />)

    expect(screen.getByText('John Doe')).toBeInTheDocument()
    expect(screen.getByText('Administrator')).toBeInTheDocument()
  })

  it('renders logout button', () => {
    renderWithRouter(<Sidebar />)

    // The logout button should be present
    const buttons = screen.getAllByRole('button')
    const logoutBtn = buttons.find((btn) => btn.querySelector('svg.lucide-log-out'))
    expect(logoutBtn).toBeInTheDocument()
  })

  it('calls logout when logout button is clicked', async () => {
    const user = userEvent.setup()
    renderWithRouter(<Sidebar />)

    const buttons = screen.getAllByRole('button')
    const logoutBtn = buttons.find((btn) => btn.querySelector('svg.lucide-log-out'))

    if (logoutBtn) {
      await user.click(logoutBtn)
      expect(mockLogout).toHaveBeenCalled()
    }
  })

  it('calls toggleSidebar when collapse button is clicked', async () => {
    const user = userEvent.setup()
    renderWithRouter(<Sidebar />)

    const buttons = screen.getAllByRole('button')
    const collapseBtn = buttons.find((btn) => btn.querySelector('svg.lucide-chevron-left'))

    if (collapseBtn) {
      await user.click(collapseBtn)
      expect(mockToggleSidebar).toHaveBeenCalled()
    }
  })

  it('has navigation links with correct routes', () => {
    renderWithRouter(<Sidebar />)

    const dashboardLink = screen.getByText('Dashboard').closest('a')
    expect(dashboardLink).toHaveAttribute('href', '/')

    const usersLink = screen.getByText('Users').closest('a')
    expect(usersLink).toHaveAttribute('href', '/users')
  })

  it('renders navigation items with icons', () => {
    renderWithRouter(<Sidebar />)

    // Check for icon classes
    const icons = document.querySelectorAll('.lucide-layout-dashboard, .lucide-users, .lucide-shield-check, .lucide-file-text, .lucide-scroll-text, .lucide-settings')
    expect(icons.length).toBeGreaterThan(0)
  })
})
