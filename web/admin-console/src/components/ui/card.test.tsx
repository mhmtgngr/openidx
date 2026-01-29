import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './card'

describe('Card', () => {
  it('renders a card with all sections', () => {
    render(
      <Card>
        <CardHeader>
          <CardTitle>Title</CardTitle>
          <CardDescription>Description</CardDescription>
        </CardHeader>
        <CardContent>
          <p>Content</p>
        </CardContent>
      </Card>
    )

    expect(screen.getByText('Title')).toBeInTheDocument()
    expect(screen.getByText('Description')).toBeInTheDocument()
    expect(screen.getByText('Content')).toBeInTheDocument()
  })

  it('renders card with custom className', () => {
    const { container } = render(<Card className="custom-class">Test</Card>)
    expect(container.firstChild).toHaveClass('custom-class')
  })

  it('renders card title as heading', () => {
    render(
      <CardHeader>
        <CardTitle>My Title</CardTitle>
      </CardHeader>
    )
    expect(screen.getByText('My Title')).toBeInTheDocument()
  })
})
