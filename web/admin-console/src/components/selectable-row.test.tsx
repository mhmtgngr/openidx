import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SelectableRow } from './selectable-row'

describe('SelectableRow', () => {
  it('is reachable by Tab', async () => {
    render(
      <SelectableRow onSelect={vi.fn()}>
        <p>Agent one</p>
      </SelectableRow>,
    )

    await userEvent.tab()
    expect(screen.getByRole('button')).toHaveFocus()
  })

  it('activates on Enter', async () => {
    const onSelect = vi.fn()
    render(
      <SelectableRow onSelect={onSelect}>
        <p>Agent one</p>
      </SelectableRow>,
    )

    await userEvent.tab()
    await userEvent.keyboard('{Enter}')
    expect(onSelect).toHaveBeenCalledTimes(1)
  })

  it('activates on Space', async () => {
    // Space is the half that gets forgotten when this is hand-rolled: a
    // `role="button"` that only answers Enter still fails the pattern, and
    // without preventDefault Space scrolls the page instead of selecting.
    const onSelect = vi.fn()
    render(
      <SelectableRow onSelect={onSelect}>
        <p>Agent one</p>
      </SelectableRow>,
    )

    await userEvent.tab()
    await userEvent.keyboard(' ')
    expect(onSelect).toHaveBeenCalledTimes(1)
  })

  it('prevents the default Space action so the page does not scroll', () => {
    const onSelect = vi.fn()
    render(
      <SelectableRow onSelect={onSelect}>
        <p>Agent one</p>
      </SelectableRow>,
    )

    const row = screen.getByRole('button')
    const event = new KeyboardEvent('keydown', {
      key: ' ',
      bubbles: true,
      cancelable: true,
    })
    row.dispatchEvent(event)
    expect(event.defaultPrevented).toBe(true)
  })

  it('ignores keys that are not Enter or Space', async () => {
    const onSelect = vi.fn()
    render(
      <SelectableRow onSelect={onSelect}>
        <p>Agent one</p>
      </SelectableRow>,
    )

    await userEvent.tab()
    await userEvent.keyboard('{ArrowDown}a')
    expect(onSelect).not.toHaveBeenCalled()
  })

  it('still works with a mouse', async () => {
    const onSelect = vi.fn()
    render(
      <SelectableRow onSelect={onSelect}>
        <p>Agent one</p>
      </SelectableRow>,
    )

    await userEvent.click(screen.getByRole('button'))
    expect(onSelect).toHaveBeenCalledTimes(1)
  })

  it('passes the caller its state attribute and merges class names', () => {
    render(
      <SelectableRow onSelect={vi.fn()} aria-pressed className="bg-blue-50">
        <p>Agent one</p>
      </SelectableRow>,
    )

    const row = screen.getByRole('button')
    expect(row).toHaveAttribute('aria-pressed', 'true')
    expect(row.className).toContain('bg-blue-50')
    // The focus ring is the component's own, and must survive the merge --
    // a row that takes focus without showing it fails WCAG 2.4.7.
    expect(row.className).toContain('focus-visible:ring-2')
  })
})
