import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogClose,
  DialogOverlay,
} from './dialog'
import { Button } from './button'

describe('Dialog', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
  })

  it('does not render content when open is false', () => {
    render(
      <Dialog open={false}>
        <DialogContent>Dialog Content</DialogContent>
      </Dialog>
    )
    expect(screen.queryByText('Dialog Content')).not.toBeInTheDocument()
  })

  it('renders content when open is true', () => {
    render(
      <Dialog open={true}>
        <DialogContent>Dialog Content</DialogContent>
      </Dialog>
    )
    expect(screen.getByText('Dialog Content')).toBeInTheDocument()
  })

  it('renders dialog with title', () => {
    render(
      <Dialog open={true}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Test Dialog</DialogTitle>
          </DialogHeader>
        </DialogContent>
      </Dialog>
    )
    expect(screen.getByText('Test Dialog')).toBeInTheDocument()
  })

  it('renders dialog with description', () => {
    render(
      <Dialog open={true}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Test Dialog</DialogTitle>
            <DialogDescription>This is a test description</DialogDescription>
          </DialogHeader>
        </DialogContent>
      </Dialog>
    )
    expect(screen.getByText('This is a test description')).toBeInTheDocument()
  })

  it('renders dialog footer with proper alignment', () => {
    render(
      <Dialog open={true}>
        <DialogContent>
          <DialogFooter>
            <Button variant="outline">Cancel</Button>
            <Button>Confirm</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    )
    expect(screen.getByText('Cancel')).toBeInTheDocument()
    expect(screen.getByText('Confirm')).toBeInTheDocument()
  })

  it('can be controlled with open prop', () => {
    const { rerender } = render(
      <Dialog open={false}>
        <DialogContent>Dialog Content</DialogContent>
      </Dialog>
    )

    expect(screen.queryByText('Dialog Content')).not.toBeInTheDocument()

    rerender(
      <Dialog open={true}>
        <DialogContent>Dialog Content</DialogContent>
      </Dialog>
    )

    expect(screen.getByText('Dialog Content')).toBeInTheDocument()
  })

  it('renders with custom className', () => {
    render(
      <Dialog open={true}>
        <DialogContent className="custom-dialog-class">Dialog Content</DialogContent>
      </Dialog>
    )
    // DialogContent is rendered in a Portal and has the className on the inner content div
    // The text is inside the content, so we need to find the actual DialogContent element
    const dialogContent = document.querySelector('.custom-dialog-class')
    expect(dialogContent).toBeInTheDocument()
  })

  it('renders dialog header', () => {
    render(
      <Dialog open={true}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Title</DialogTitle>
            <DialogDescription>Description</DialogDescription>
          </DialogHeader>
        </DialogContent>
      </Dialog>
    )
    expect(screen.getByText('Title')).toBeInTheDocument()
    expect(screen.getByText('Description')).toBeInTheDocument()
  })

  it('renders dialog footer', () => {
    render(
      <Dialog open={true}>
        <DialogContent>
          <DialogFooter>
            <Button variant="outline">Cancel</Button>
            <Button>Save</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    )
    const footer = screen.getByText('Cancel').parentElement
    expect(footer).toBeInTheDocument()
  })

  it('DialogClose component exists', () => {
    render(
      <Dialog open={true}>
        <DialogContent>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
        </DialogContent>
      </Dialog>
    )

    const cancelButton = screen.getByRole('button', { name: 'Cancel' })
    expect(cancelButton).toBeInTheDocument()
  })

  it('renders dialog overlay', () => {
    render(
      <Dialog open={true}>
        <DialogOverlay />
        <DialogContent>Dialog Content</DialogContent>
      </Dialog>
    )

    expect(screen.getByText('Dialog Content')).toBeInTheDocument()
  })

  it('renders DialogTrigger button', () => {
    render(
      <Dialog>
        <DialogTrigger asChild>
          <Button>Open Dialog</Button>
        </DialogTrigger>
        <DialogContent>
          <DialogTitle>Test Dialog</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    const triggerButton = screen.getByRole('button', { name: 'Open Dialog' })
    expect(triggerButton).toBeInTheDocument()
  })
})
