import * as React from 'react'
import { cn } from '@/lib/utils/cn'

interface SelectableRowProps
  extends Omit<React.HTMLAttributes<HTMLDivElement>, 'onSelect'> {
  /** Run when the row is chosen, by mouse or by keyboard. */
  onSelect: () => void
}

/**
 * A list row you pick to reveal its detail panel.
 *
 * Five pages had written this as a bare `<div onClick>`, which a mouse can use
 * and a keyboard cannot: no tab stop, no key handler, no focus ring. On those
 * pages selecting an item was the only way to see any of its detail, so a
 * keyboard-only operator could not reach it at all.
 *
 * It stays a `<div role="button">` rather than becoming a real `<button>`
 * because these rows contain `<p>` elements, and flow content inside a
 * `<button>` is invalid HTML — the ARIA pattern is the honest way to get the
 * same semantics here. That does mean the keyboard contract is ours to
 * implement, which is the other reason this is one component and not five
 * copies: Space must be preventDefault'd or it scrolls the page instead of
 * activating the row, and that is precisely the detail that goes missing when
 * the pattern is hand-rolled.
 *
 * The caller supplies the state attribute, because it differs by page:
 * `aria-pressed` where a row is selected, `aria-expanded` where selecting it
 * toggles a region open and shut.
 */
export function SelectableRow({
  onSelect,
  className,
  children,
  ...rest
}: SelectableRowProps) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onSelect()
        }
      }}
      className={cn(
        'cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
        className,
      )}
      {...rest}
    >
      {children}
    </div>
  )
}
