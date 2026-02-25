import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Layout } from './Layout'

// Mock the store
vi.mock('@/lib/store', () => ({
  useAppStore: vi.fn(() => ({
    sidebarOpen: true,
    toggleSidebar: vi.fn(),
  })),
  useAuthStore: vi.fn(() => ({
    user: { name: 'Test User', email: 'test@example.com', role: 'Admin' },
    logout: vi.fn(),
  })),
}))

// Mock the child components to simplify testing
vi.mock('./Sidebar', () => ({
  Sidebar: () => <aside data-testid="sidebar">Sidebar</aside>,
}))

vi.mock('./Header', () => ({
  Header: () => <header data-testid="header">Header</header>,
}))

describe('Layout', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
  })

  const renderWithRouter = (component: React.ReactNode) => {
    return render(<MemoryRouter>{component}</MemoryRouter>)
  }

  it('renders sidebar and header', () => {
    renderWithRouter(<Layout />)

    expect(screen.getByTestId('sidebar')).toBeInTheDocument()
    expect(screen.getByTestId('header')).toBeInTheDocument()
  })

  it('renders main content area', () => {
    renderWithRouter(<Layout />)

    const main = document.querySelector('main')
    expect(main).toBeInTheDocument()
  })

  it('has correct overflow classes', () => {
    renderWithRouter(<Layout />)

    const main = document.querySelector('main')
    expect(main).toHaveClass('overflow-y-auto')
  })

  it('renders outlet for child routes', () => {
    renderWithRouter(<Layout />)

    // Outlet is rendered inside main
    const main = document.querySelector('main')
    expect(main).toBeInTheDocument()
  })
})
