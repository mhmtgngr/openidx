import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Trash2, UserPlus } from 'lucide-react'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from './ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from './ui/alert-dialog'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Label } from './ui/label'
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
  /**
   * Current value of applications.require_assignment, from the applications
   * list. Undefined means the caller did not supply it (an older read path);
   * the control then renders unchecked, matching the column's default.
   */
  requireAssignment?: boolean
}

// ManageAppAccessDialog is the one-click way an admin grants an application to a
// user or a group (group grants apply to every member). It lists current
// assignees and lets the admin revoke them.
export function ManageAppAccessDialog({
  appId,
  appName,
  open,
  onOpenChange,
  requireAssignment = false,
}: ManageAppAccessDialogProps) {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [principalType, setPrincipalType] = useState<'user' | 'group'>('group')
  const [principalId, setPrincipalId] = useState('')
  // Mirrors the server value so the checkbox reflects a save immediately. When
  // the dialog is pointed at a different application (or the server value
  // changes underneath it) the mirror is re-seeded during render — React's
  // documented way to reset state from a prop, and quieter than an effect.
  const [gateOn, setGateOn] = useState(requireAssignment)
  const [gateSeed, setGateSeed] = useState({ appId, requireAssignment })
  if (gateSeed.appId !== appId || gateSeed.requireAssignment !== requireAssignment) {
    setGateSeed({ appId, requireAssignment })
    setGateOn(requireAssignment)
  }
  const [confirmLockout, setConfirmLockout] = useState(false)

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

  // The only write path for applications.require_assignment. It rides the same
  // allowlisted application updater as every other field, so nothing else on the
  // application row is touched.
  const requireAssignmentMutation = useMutation({
    mutationFn: (next: boolean) =>
      api.put(`/api/v1/applications/${appId}`, { require_assignment: next }),
    onSuccess: (_data, next) => {
      setGateOn(next)
      queryClient.invalidateQueries({ queryKey: ['applications'] })
      toast({
        title: next ? 'Assignment now required' : 'Assignment no longer required',
        description: next
          ? // Future-conditional on purpose. Assignment enforcement is a
            // deployment-level flag (ACCESS_ASSIGNMENT_ENFORCE) and it is off
            // here: authorizeAssignmentDecision still issues the token and
            // records a would-deny. Saying "only assigned users can sign in"
            // would describe enforcement that is not happening -- the same
            // display-vs-enforcement defect this project already shipped once.
            // This wording is correct whether the flag is on or off.
            `Once assignment enforcement is enabled, only assigned users and groups can sign in to ${appName}.`
          : `Any user who can reach ${appName} may sign in to it.`,
        variant: 'success',
      })
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to save', description: err.message, variant: 'destructive' })
    },
  })

  const assigneeCount = assignments?.length ?? 0

  // Turning the gate ON with nothing assigned locks every user out, so that one
  // combination asks first. It is a warning, not a veto: an admin may be about
  // to assign principals. Every other transition saves straight away.
  const onToggleRequireAssignment = (next: boolean) => {
    if (next && !isLoading && assigneeCount === 0) {
      setConfirmLockout(true)
      return
    }
    requireAssignmentMutation.mutate(next)
  }

  const options = principalType === 'group' ? groups : users

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Manage access — {appName}</DialogTitle>
          <DialogDescription>
            This is the grant: it decides who can actually reach {appName}, on the web
            and over the network. Assign a user or a group here — group grants apply to
            every member. Any route restrictions shown elsewhere for this application are
            derived from this list, not a separate grant.
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
            <div className="flex items-start gap-2">
              <input
                type="checkbox"
                id="require_assignment"
                className="mt-1 rounded"
                checked={gateOn}
                disabled={requireAssignmentMutation.isPending}
                onChange={(e) => onToggleRequireAssignment(e.target.checked)}
              />
              <div className="space-y-1">
                <Label htmlFor="require_assignment">Require assignment to sign in</Label>
                <p className="text-sm text-muted-foreground">
                  When enabled, only users or groups assigned above can obtain a token for
                  this application. Once assignment enforcement is enabled, users who are not
                  assigned will be refused at sign-in. Leave this off until the assignment
                  list below is complete.
                </p>
                {/* The gate is per-application, but whether it REFUSES anyone is
                    a deployment-level decision. With assignment enforcement off
                    the authorize gate still issues the token and only records a
                    would-deny, so a control that promised a refusal here would
                    be describing enforcement that is not happening. This line is
                    true in both states. */}
                <p className="text-sm text-muted-foreground">
                  This setting only refuses anyone while assignment enforcement is enabled for
                  the deployment. Until then it is recorded, and the assignment report shows who
                  would be refused, but no sign-in is denied.
                </p>
                {!isLoading && (
                  <p className="text-sm text-muted-foreground">
                    {assigneeCount === 0
                      ? 'No principals are assigned — enabling this would refuse everyone.'
                      : `${assigneeCount} principal${assigneeCount === 1 ? '' : 's'} assigned and would keep access.`}
                  </p>
                )}
              </div>
            </div>
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

      <AlertDialog open={confirmLockout} onOpenChange={setConfirmLockout}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Require assignment for {appName}?</AlertDialogTitle>
            <AlertDialogDescription>
              Nobody is assigned to {appName} yet. Once assignment enforcement is enabled,
              turning this on refuses every user at sign-in until you assign a user or a
              group.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                setConfirmLockout(false)
                requireAssignmentMutation.mutate(true)
              }}
            >
              Require assignment
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Dialog>
  )
}
