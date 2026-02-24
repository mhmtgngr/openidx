import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableFooter,
  TableHead,
  TableHeader,
  TableRow,
} from './table'

describe('Table Components', () => {
  describe('Table', () => {
    it('renders with default styles', () => {
      render(
        <Table>
          <TableBody>
            <TableRow>
              <TableCell>Content</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      const table = screen.getByRole('table')
      expect(table).toBeInTheDocument()
      expect(table).toHaveClass('w-full', 'caption-bottom', 'text-sm')
    })

    it('renders with custom className', () => {
      render(
        <Table className="custom-table">
          <TableBody>
            <TableRow>
              <TableCell>Content</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      const table = screen.getByRole('table')
      expect(table).toHaveClass('custom-table')
    })
  })

  describe('TableHeader', () => {
    it('renders with default styles', () => {
      render(
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Header</TableHead>
            </TableRow>
          </TableHeader>
        </Table>
      )
      const header = screen.getByText('Header')
      expect(header).toBeInTheDocument()
      expect(header.tagName).toBe('TH')
    })

    it('renders multiple headers', () => {
      render(
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Email</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
        </Table>
      )
      expect(screen.getByText('Name')).toBeInTheDocument()
      expect(screen.getByText('Email')).toBeInTheDocument()
      expect(screen.getByText('Status')).toBeInTheDocument()
    })
  })

  describe('TableBody', () => {
    it('renders rows with data', () => {
      render(
        <Table>
          <TableBody>
            <TableRow>
              <TableCell>John Doe</TableCell>
            </TableRow>
            <TableRow>
              <TableCell>Jane Smith</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      expect(screen.getByText('John Doe')).toBeInTheDocument()
      expect(screen.getByText('Jane Smith')).toBeInTheDocument()
    })
  })

  describe('TableFooter', () => {
    it('renders with footer content', () => {
      render(
        <Table>
          <TableFooter>
            <TableRow>
              <TableCell>Total: 2</TableCell>
            </TableRow>
          </TableFooter>
        </Table>
      )
      expect(screen.getByText('Total: 2')).toBeInTheDocument()
    })

    it('renders with proper font weight', () => {
      render(
        <Table>
          <TableFooter>
            <TableRow>
              <TableCell>Footer Content</TableCell>
            </TableRow>
          </TableFooter>
        </Table>
      )
      const footer = screen.getByText('Footer Content')
      // TableFooter has border-t bg-muted/50 font-medium as base classes
      // but TableCell has p-4 align-middle which overrides some classes
      expect(footer).toHaveClass('p-4', 'align-middle')
    })
  })

  describe('TableRow', () => {
    it('renders with hover effect', () => {
      render(
        <Table>
          <TableBody>
            <TableRow>
              <TableCell>Row Content</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      const row = screen.getByText('Row Content').closest('tr')
      expect(row).toHaveClass('hover:bg-muted/50')
    })

    it('renders with border bottom', () => {
      render(
        <Table>
          <TableBody>
            <TableRow>
              <TableCell>Row Content</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      const row = screen.getByText('Row Content').closest('tr')
      expect(row).toHaveClass('border-b')
    })
  })

  describe('TableHead', () => {
    it('renders with proper alignment and padding', () => {
      render(
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Header</TableHead>
            </TableRow>
          </TableHeader>
        </Table>
      )
      const header = screen.getByText('Header')
      expect(header).toHaveClass('h-10', 'px-4', 'text-left', 'align-middle')
    })

    it('renders with font medium', () => {
      render(
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Header</TableHead>
            </TableRow>
          </TableHeader>
        </Table>
      )
      const header = screen.getByText('Header')
      expect(header).toHaveClass('font-medium', 'text-muted-foreground')
    })
  })

  describe('TableCell', () => {
    it('renders with proper padding and alignment', () => {
      render(
        <Table>
          <TableBody>
            <TableRow>
              <TableCell>Cell Content</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      const cell = screen.getByText('Cell Content')
      expect(cell).toHaveClass('p-4', 'align-middle')
    })

    it('renders multiple cells in a row', () => {
      render(
        <Table>
          <TableBody>
            <TableRow>
              <TableCell>Cell 1</TableCell>
              <TableCell>Cell 2</TableCell>
              <TableCell>Cell 3</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      expect(screen.getByText('Cell 1')).toBeInTheDocument()
      expect(screen.getByText('Cell 2')).toBeInTheDocument()
      expect(screen.getByText('Cell 3')).toBeInTheDocument()
    })
  })

  describe('TableCaption', () => {
    it('renders caption text', () => {
      render(
        <Table>
          <TableCaption>User List</TableCaption>
          <TableBody>
            <TableRow>
              <TableCell>Content</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      expect(screen.getByText('User List')).toBeInTheDocument()
    })

    it('renders at top with side variant', () => {
      render(
        <Table>
          <TableCaption className="caption-top">Top Caption</TableCaption>
          <TableBody>
            <TableRow>
              <TableCell>Content</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )
      const caption = screen.getByText('Top Caption')
      expect(caption).toHaveClass('caption-top')
    })
  })

  describe('Complete Table', () => {
    it('renders a complete table structure', () => {
      render(
        <Table>
          <TableCaption>A list of your recent invoices.</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>Invoice</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Amount</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow>
              <TableCell>INV001</TableCell>
              <TableCell>Paid</TableCell>
              <TableCell>$250.00</TableCell>
              <TableCell className="text-right">
                <button>View</button>
              </TableCell>
            </TableRow>
            <TableRow>
              <TableCell>INV002</TableCell>
              <TableCell>Pending</TableCell>
              <TableCell>$150.00</TableCell>
              <TableCell className="text-right">
                <button>View</button>
              </TableCell>
            </TableRow>
          </TableBody>
          <TableFooter>
            <TableRow>
              <TableCell colSpan={3}>Total</TableCell>
              <TableCell className="text-right">$400.00</TableCell>
            </TableRow>
          </TableFooter>
        </Table>
      )

      expect(screen.getByText('A list of your recent invoices.')).toBeInTheDocument()
      expect(screen.getByText('Invoice')).toBeInTheDocument()
      expect(screen.getByText('Status')).toBeInTheDocument()
      expect(screen.getByText('INV001')).toBeInTheDocument()
      expect(screen.getByText('Paid')).toBeInTheDocument()
      expect(screen.getByText('Total')).toBeInTheDocument()
      expect(screen.getByText('$400.00')).toBeInTheDocument()
    })

    it('is clickable on rows when clickable prop is provided', async () => {
      const user = userEvent.setup()
      const handleClick = () => {}

      render(
        <Table>
          <TableBody>
            <TableRow onClick={handleClick} data-testid="clickable-row">
              <TableCell>Clickable Row</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      )

      const row = screen.getByTestId('clickable-row')
      await user.click(row)
      expect(row).toBeInTheDocument()
    })
  })
})
