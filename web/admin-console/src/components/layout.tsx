import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  Users,
  Users2,
  AppWindow,
  ClipboardCheck,
  FileText,
  Settings,
  LogOut,
  Shield,
  Menu,
  Scale,
  ShieldCheck,
  ClipboardList,
  Key as KeyIcon,
  User,
  Workflow
} from 'lucide-react'
import { useState } from 'react'
import { useAuth } from '../lib/auth'
import { Button } from './ui/button'
import { Avatar, AvatarFallback } from './ui/avatar'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './ui/dropdown-menu'

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard, adminOnly: false },
  { name: 'My Profile', href: '/profile', icon: User, adminOnly: false },
  { name: 'Users', href: '/users', icon: Users, adminOnly: true },
  { name: 'Groups', href: '/groups', icon: Users2, adminOnly: true },
  { name: 'Roles', href: '/roles', icon: ShieldCheck, adminOnly: true },
  { name: 'Applications', href: '/applications', icon: AppWindow, adminOnly: true },
  { name: 'Identity Providers', href: '/identity-providers', icon: KeyIcon, adminOnly: true },
  { name: 'Provisioning Rules', href: '/provisioning-rules', icon: Workflow, adminOnly: true },
  { name: 'Access Reviews', href: '/access-reviews', icon: ClipboardCheck, adminOnly: true },
  { name: 'Policies', href: '/policies', icon: Scale, adminOnly: true },
  { name: 'Audit Logs', href: '/audit-logs', icon: FileText, adminOnly: true },
  { name: 'Compliance', href: '/compliance-reports', icon: ClipboardList, adminOnly: true },
  { name: 'Settings', href: '/settings', icon: Settings, adminOnly: true },
]

export function Layout() {
  const { user, logout, hasRole } = useAuth()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const navigate = useNavigate()

  const initials = user?.name
    ?.split(' ')
    .map((n) => n[0])
    .join('')
    .toUpperCase() || 'U'

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <aside
        className={`${
          sidebarOpen ? 'w-64' : 'w-16'
        } flex flex-col bg-white border-r transition-all duration-300`}
      >
        {/* Logo */}
        <div className="flex h-16 items-center justify-between px-4 border-b">
          {sidebarOpen && (
            <div className="flex items-center gap-2">
              <Shield className="h-8 w-8 text-blue-600" />
              <span className="text-xl font-bold">OpenIDX</span>
            </div>
          )}
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setSidebarOpen(!sidebarOpen)}
          >
            <Menu className="h-5 w-5" />
          </Button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-1">
          {navigation
            .filter((item) => !item.adminOnly || hasRole('admin'))
            .map((item) => (
              <NavLink
                key={item.name}
                to={item.href}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${
                    isActive
                      ? 'bg-blue-50 text-blue-700'
                      : 'text-gray-600 hover:bg-gray-100'
                  }`
                }
              >
                <item.icon className="h-5 w-5 flex-shrink-0" />
                {sidebarOpen && <span>{item.name}</span>}
              </NavLink>
            ))}
        </nav>

        {/* User menu */}
        <div className="p-4 border-t">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className={`w-full ${sidebarOpen ? 'justify-start' : 'justify-center'}`}
              >
                <Avatar className="h-8 w-8">
                  <AvatarFallback>{initials}</AvatarFallback>
                </Avatar>
                {sidebarOpen && (
                  <div className="ml-3 text-left">
                    <p className="text-sm font-medium">{user?.name}</p>
                    <p className="text-xs text-gray-500">{user?.email}</p>
                  </div>
                )}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuLabel>My Account</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => navigate('/profile')}>
                <User className="mr-2 h-4 w-4" />
                My Profile
              </DropdownMenuItem>
              {hasRole('admin') && (
                <DropdownMenuItem onClick={() => navigate('/settings')}>
                  <Settings className="mr-2 h-4 w-4" />
                  Settings
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={logout} className="text-red-600">
                <LogOut className="mr-2 h-4 w-4" />
                Logout
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <div className="p-8">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
