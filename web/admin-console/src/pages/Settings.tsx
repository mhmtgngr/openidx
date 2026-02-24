import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Save, Moon, Sun, Monitor } from 'lucide-react'
import { adminApi } from '@/lib/api/admin'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useToast } from '@/components/ui/use-toast'
import { useAppStore } from '@/lib/store'
import type { SystemSettings } from '@/lib/api/types'

export function Settings() {
  const { theme, setTheme } = useAppStore()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const { data: settings, isLoading } = useQuery({
    queryKey: ['settings'],
    queryFn: () => adminApi.getSettings(),
  })

  const [formData, setFormData] = useState<Partial<SystemSettings>>({})

  // Update form data when settings are loaded
  useEffect(() => {
    if (settings) {
      setFormData(settings)
    }
  }, [settings])

  const updateMutation = useMutation({
    mutationFn: (data: Partial<SystemSettings>) => adminApi.updateSettings(data),
    onSuccess: (newSettings) => {
      queryClient.setQueryData(['settings'], newSettings)
      toast({
        title: 'Success',
        description: 'Settings updated successfully',
      })
    },
    onError: (error: any) => {
      toast({
        title: 'Error',
        description: error.message || 'Failed to update settings',
        variant: 'destructive',
      })
    },
  })

  const handleSave = () => {
    updateMutation.mutate(formData)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-muted-foreground">
          Configure system-wide settings and preferences
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle>General Settings</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="siteName">Site Name</Label>
                <Input
                  id="siteName"
                  value={formData.site_name || ''}
                  onChange={(e) =>
                    setFormData({ ...formData, site_name: e.target.value })
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="siteUrl">Site URL</Label>
                <Input
                  id="siteUrl"
                  type="url"
                  value={formData.site_url || ''}
                  onChange={(e) =>
                    setFormData({ ...formData, site_url: e.target.value })
                  }
                />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Session Settings</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="sessionTimeout">
                Session Timeout (minutes): {formData.session_timeout_minutes}
              </Label>
              <Input
                id="sessionTimeout"
                type="range"
                min="5"
                max="1440"
                step="5"
                value={formData.session_timeout_minutes || 30}
                onChange={(e) =>
                  setFormData({ ...formData, session_timeout_minutes: Number(e.target.value) })
                }
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="maxLoginAttempts">
                Max Login Attempts: {formData.max_login_attempts}
              </Label>
              <Input
                id="maxLoginAttempts"
                type="range"
                min="3"
                max="10"
                value={formData.max_login_attempts || 5}
                onChange={(e) =>
                  setFormData({ ...formData, max_login_attempts: Number(e.target.value) })
                }
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Password Policy</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="minLength">
                Minimum Length: {formData.password_min_length}
              </Label>
              <Input
                id="minLength"
                type="range"
                min="8"
                max="32"
                value={formData.password_min_length || 12}
                onChange={(e) =>
                  setFormData({ ...formData, password_min_length: Number(e.target.value) })
                }
              />
            </div>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label htmlFor="requireUppercase">Require Uppercase</Label>
                <Switch
                  id="requireUppercase"
                  checked={formData.password_require_uppercase}
                  onCheckedChange={(checked) =>
                    setFormData({ ...formData, password_require_uppercase: checked })
                  }
                />
              </div>
              <div className="flex items-center justify-between">
                <Label htmlFor="requireLowercase">Require Lowercase</Label>
                <Switch
                  id="requireLowercase"
                  checked={formData.password_require_lowercase}
                  onCheckedChange={(checked) =>
                    setFormData({ ...formData, password_require_lowercase: checked })
                  }
                />
              </div>
              <div className="flex items-center justify-between">
                <Label htmlFor="requireNumbers">Require Numbers</Label>
                <Switch
                  id="requireNumbers"
                  checked={formData.password_require_numbers}
                  onCheckedChange={(checked) =>
                    setFormData({ ...formData, password_require_numbers: checked })
                  }
                />
              </div>
              <div className="flex items-center justify-between">
                <Label htmlFor="requireSymbols">Require Symbols</Label>
                <Switch
                  id="requireSymbols"
                  checked={formData.password_require_symbols}
                  onCheckedChange={(checked) =>
                    setFormData({ ...formData, password_require_symbols: checked })
                  }
                />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Multi-Factor Authentication</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <Label htmlFor="mfaEnabled">Enable MFA</Label>
                <p className="text-xs text-muted-foreground">
                  Require multi-factor authentication for all users
                </p>
              </div>
              <Switch
                id="mfaEnabled"
                checked={formData.mfa_enabled}
                onCheckedChange={(checked) =>
                  setFormData({ ...formData, mfa_enabled: checked })
                }
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mfaMethod">MFA Method</Label>
              <Select
                value={formData.mfa_method}
                onValueChange={(v: any) => setFormData({ ...formData, mfa_method: v })}
                disabled={!formData.mfa_enabled}
              >
                <SelectTrigger id="mfaMethod">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="totp">TOTP (Authenticator App)</SelectItem>
                  <SelectItem value="sms">SMS</SelectItem>
                  <SelectItem value="email">Email</SelectItem>
                  <SelectItem value="none">None</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Appearance</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Theme</Label>
              <div className="flex items-center gap-2">
                <Button
                  variant={theme === 'light' ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setTheme('light')}
                >
                  <Sun className="h-4 w-4 mr-2" />
                  Light
                </Button>
                <Button
                  variant={theme === 'dark' ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setTheme('dark')}
                >
                  <Moon className="h-4 w-4 mr-2" />
                  Dark
                </Button>
                <Button
                  variant={theme === 'system' ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setTheme('system')}
                >
                  <Monitor className="h-4 w-4 mr-2" />
                  System
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="flex justify-end">
        <Button onClick={handleSave} disabled={updateMutation.isPending}>
          <Save className="h-4 w-4 mr-2" />
          {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
        </Button>
      </div>
    </div>
  )
}
