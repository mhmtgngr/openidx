import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Trash2, UserPlus } from 'lucide-react'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from './ui/dialog'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from './ui/select'

interface AppAssignment {
  principal_type: 'user' | 'group'
  principal_id: string
  principal_name: string
  assigned_at: string
}

interface PickerItem {
  id: string
  name: string
}

interface ManageAppAccessDialogProps {
  appId: string
  appName: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

// ManageAppAccessDialog is the one-click way an admin grants an application to a
// user or a group (group grants apply to every member). It lists current
// assignees and lets the admin revoke them.
export function ManageAppAccessDialog({ appId, appName, open, onOpenChange }: ManageAppAccessDialogProps) {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [principalType, setPrincipalType] = useState<'user' | 'group'>('group')
  const [principalId, setPrincipalId] = useState('')

  const assignmentsKey = ['app-assignments', appId]

  const { data: assignments, isLoading } = useQuery({
    queryKey: assignmentsKey,
    enabled: open,
    queryFn: async () => {
      const res = await api.get<{ assignments: AppAssignment[] }>(
        `/api/v1/identity/portal/applications/${appId}/assignments`,
      )
      return res.assignments || []
    },
  })

  const { data: groups } = useQuery({
    queryKey: ['groups-for-app-access'],
    enabled: open,
    queryFn: async (): Promise<PickerItem[]> => {
      const raw = await api.get<Array<Record<string, unknown>>>('/api/v1/identity/groups')
      return (raw || []).map((g) => ({ id: String(g.id ?? ''), name: String(g.displayName ?? g.name ?? '') }))
    },
  })

  const { data: users } = useQuery({
    queryKey: ['users-for-app-access'],
    enabled: open,
    queryFn: async (): Promise<PickerItem[]> => {
      const raw = await api.get<Array<Record<string, unknown>>>('/api/v1/identity/users?limit=200')
      return (raw || []).map((u) => ({
        id: String(u.id ?? ''),
        name: String(u.userName ?? u.username ?? u.email ?? u.id ?? ''),
      }))
    },
  })

  const assignMutation = useMutation({
    mutationFn: () =>
      api.post(`/api/v1/identity/portal/applications/${appId}/assignments`, {
        principal_type: principalType,
        principal_id: principalId,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: assignmentsKey })
      setPrincipalId('')
      toast({ title: 'Access granted', description: `${appName} assigned.`, variant: 'success' })
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to grant access', description: err.message, variant: 'destructive' })
    },
  })

  const revokeMutation = useMutation({
    mutationFn: (a: AppAssignment) =>
      api.delete(
        `/api/v1/identity/portal/applications/${appId}/assignments/${a.principal_id}?type=${a.principal_type}`,
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: assignmentsKey })
      toast({ title: 'Access revoked', variant: 'success' })
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to revoke', description: err.message, variant: 'destructive' })
    },
  })

  const options = principalType === 'group' ? groups : users

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Manage access — {appName}</DialogTitle>
          <DialogDescription>
            Grant this application to a user or a group. Group grants apply to every member.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="flex items-end gap-2">
            <div className="w-32">
              <label className="text-sm font-medium">Assign to</label>
              <Select
                value={principalType}
                onValueChange={(v) => {
                  setPrincipalType(v as 'user' | 'group')
                  setPrincipalId('')
                }}
              >
                <SelectTrigger className="mt-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="group">Group</SelectItem>
                  <SelectItem value="user">User</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex-1">
              <label className="text-sm font-medium capitalize">{principalType}</label>
              <Select value={principalId} onValueChange={setPrincipalId}>
                <SelectTrigger className="mt-1">
                  <SelectValue placeholder={`Select a ${principalType}…`} />
                </SelectTrigger>
                <SelectContent>
                  {(options || []).map((o) => (
                    <SelectItem key={o.id} value={o.id}>
                      {o.name || o.id}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button
              onClick={() => assignMutation.mutate()}
              disabled={!principalId || assignMutation.isPending}
            >
              <UserPlus className="mr-2 h-4 w-4" />
              Assign
            </Button>
          </div>

          <div className="border-t pt-3">
            <p className="mb-2 text-sm font-medium">Current access</p>
            {isLoading ? (
              <p className="text-sm text-muted-foreground">Loading…</p>
            ) : !assignments || assignments.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No one is assigned yet. Assign a user or group above.
              </p>
            ) : (
              <ul className="space-y-2">
                {assignments.map((a) => (
                  <li
                    key={`${a.principal_type}:${a.principal_id}`}
                    className="flex items-center justify-between rounded border p-2"
                  >
                    <span className="flex items-center gap-2 text-sm">
                      <Badge variant={a.principal_type === 'group' ? 'default' : 'secondary'} className="capitalize">
                        {a.principal_type}
                      </Badge>
                      {a.principal_name || a.principal_id}
                    </span>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => revokeMutation.mutate(a)}
                      disabled={revokeMutation.isPending}
                      aria-label={`Revoke ${a.principal_name || a.principal_id}`}
                    >
                      <Trash2 className="h-4 w-4 text-red-600" />
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
