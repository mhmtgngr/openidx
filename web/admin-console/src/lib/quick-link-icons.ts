import {
  Globe,
  Headphones,
  LifeBuoy,
  Link2,
  Mail,
  MessageSquare,
  Monitor,
  Phone,
  Server,
  Terminal,
  Ticket,
  Video,
  type LucideIcon,
} from 'lucide-react'

/**
 * The icons an admin can give a quick link, keyed by the lucide identifier
 * stored on the link. The admin picker offers exactly these keys, and the end
 * user's quick-links section resolves through the same map.
 *
 * This used to be `import * as Icons from 'lucide-react'` indexed by name,
 * which pulled every lucide icon (several hundred kB) into the My Apps &
 * Network chunk to render one of twelve. A stored name outside this map
 * renders as Link2, as an unknown name always did.
 */
export const QUICK_LINK_ICONS: Record<string, LucideIcon> = {
  Link2,
  Video,
  MessageSquare,
  Headphones,
  LifeBuoy,
  Monitor,
  Server,
  Ticket,
  Globe,
  Mail,
  Phone,
  Terminal,
}

/** lucide icon identifiers, not prose. */
export const QUICK_LINK_ICON_NAMES = Object.keys(QUICK_LINK_ICONS)

export function quickLinkIcon(name: string): LucideIcon {
  return Object.prototype.hasOwnProperty.call(QUICK_LINK_ICONS, name) ? QUICK_LINK_ICONS[name] : Link2
}
