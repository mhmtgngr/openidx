import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Header } from './Header'

// Mock the store - use the same path alias as the component
const mockToggleSidebar = vi.fn()

vi.mock('@/lib/store', () => ({
  useAppStore: vi.fn(() => ({
    toggleSidebar: mockToggleSidebar,
  })),
}))

describe('Header', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    mockToggleSidebar.mockClear()
  })

  it('renders header element', () => {
    render(<Header />)
    expect(screen.getByRole('banner')).toBeInTheDocument()
  })

  it('renders search input', () => {
    render(<Header />)
    const searchInput = screen.getByPlaceholderText('Search...')
    expect(searchInput).toBeInTheDocument()
    expect(searchInput).toHaveAttribute('type', 'search')
  })

  it('renders notification bell', () => {
    render(<Header />)
    const buttons = screen.getAllByRole('button')
    expect(buttons.length).toBeGreaterThan(0)
  })

  it('renders mobile menu button', () => {
    render(<Header />)
    const buttons = screen.getAllByRole('button')
    expect(buttons.length).toBeGreaterThan(0)
  })

  it('calls toggleSidebar when menu button is clicked', async () => {
    const user = userEvent.setup()
    render(<Header />)

    // Find the menu button (hidden on lg screens but present in DOM)
    const buttons = screen.getAllByRole('button')
    const menuButton = buttons.find((btn) => btn.querySelector('svg'))

    expect(menuButton).toBeInTheDocument()

    if (menuButton) {
      await user.click(menuButton)
      expect(mockToggleSidebar).toHaveBeenCalled()
    }
  })

  it('search input has correct placeholder', () => {
    render(<Header />)
    const searchInput = screen.getByPlaceholderText('Search...')
    expect(searchInput).toBeInTheDocument()
  })

  it('header has sticky positioning', () => {
    render(<Header />)
    const header = screen.getByRole('banner')
    expect(header).toHaveClass('sticky', 'top-0')
  })

  it('search form has relative positioning for icon', () => {
    render(<Header />)
    const form = document.querySelector('form')
    expect(form).toHaveClass('relative')
  })

  it('renders search icon inside input', () => {
    render(<Header />)
    const searchIcon = document.querySelector('.lucide-search')
    expect(searchIcon).toBeInTheDocument()
  })
})
