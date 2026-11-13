import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, VaultSecretMeta, VaultRotationPolicy } from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '../components/ui/alert-dialog'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table'
import { RefreshCw, Plus, Trash2, Pencil } from 'lucide-react'
import { useToast } from '../hooks/use-toast'
import { RotationPolicyDialog } from '../components/rotation-policy-dialog'
import { connectorColors, connectorLabel, formatInterval } from '../lib/rotation-policy-form'

export function RotationPoliciesPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const [showDialog, setShowDialog] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<VaultRotationPolicy | null>(null)

  // Queries
  const { data: policiesData, isLoading, isError, error } = useQuery({
    queryKey: ['rotation-policies'],
    queryFn: () => api.vault.listPolicies(),
  })

  const { data: secretsData } = useQuery({
    queryKey: ['vault-secrets'],
    queryFn: () => api.vault.listSecrets(),
  })

  const policies: VaultRotationPolicy[] = policiesData?.policies || []
  const secrets: VaultSecretMeta[] = secretsData?.secrets || []

  function secretName(secretId: string): string {
    return secrets.find((s) => s.id === secretId)?.name ?? secretId
  }

  // Mutations


  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.vault.deletePolicy(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rotation-policies'] })
      toast({ title: t('pages.rotationPolicies.toasts.deleted') })
    },
  })

  function openCreate() {
    setEditingPolicy(null)
    setShowDialog(true)
  }

  function openEdit(p: VaultRotationPolicy) {
    setEditingPolicy(p)
    setShowDialog(true)
  }


  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{t('nav.items.rotationPolicies')}</h1>
          <p className="text-muted-foreground">{t('pages.rotationPolicies.subtitle')}</p>
        </div>
        <Button onClick={openCreate}>
          <Plus className="h-4 w-4 mr-2" />
          {t('pages.rotationPolicies.newPolicy')}
        </Button>
      </div>

      {/* List */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <RefreshCw className="h-5 w-5" />
            {t('pages.rotationPolicies.list.title', { count: policies.length })}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-12">
              <LoadingSpinner size="lg" />
            </div>
          ) : isError ? (
            <QueryError error={error} resource={t('pages.rotationPolicies.resourceName')} />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('pages.rotationPolicies.list.table.secret')}</TableHead>
                  <TableHead>{t('pages.rotationPolicies.list.table.connector')}</TableHead>
                  <TableHead>{t('pages.rotationPolicies.list.table.interval')}</TableHead>
                  <TableHead>{t('pages.rotationPolicies.list.table.onCheckout')}</TableHead>
                  <TableHead>{t('pages.rotationPolicies.list.table.enabled')}</TableHead>
                  <TableHead>{t('pages.rotationPolicies.list.table.lastStatus')}</TableHead>
                  <TableHead>{t('pages.rotationPolicies.list.table.lastRun')}</TableHead>
                  <TableHead>{t('pages.rotationPolicies.list.table.nextRun')}</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {policies.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell className="font-medium">{secretName(p.secret_id)}</TableCell>
                    <TableCell>
                      <Badge className={connectorColors[p.connector_type] || 'bg-muted text-foreground'}>
                        {connectorLabel(p.connector_type)}
                      </Badge>
                    </TableCell>
                    <TableCell>{formatInterval(p.interval_seconds)}</TableCell>
                    <TableCell>
                      {p.rotate_on_checkout ? (
                        <Badge className="bg-purple-100 text-purple-800">
                          {t('pages.rotationPolicies.list.yes')}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground text-sm">
                          {t('pages.rotationPolicies.list.no')}
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge
                        className={
                          p.enabled ? 'bg-green-100 text-green-800' : 'bg-muted text-foreground'
                        }
                      >
                        {p.enabled
                          ? t('pages.rotationPolicies.list.enabled')
                          : t('pages.rotationPolicies.list.disabled')}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {p.last_status ? (
                        <Badge
                          className={
                            p.last_status === 'success'
                              ? 'bg-green-100 text-green-800'
                              : p.last_status === 'failed'
                              ? 'bg-red-100 text-red-800'
                              : 'bg-yellow-100 text-yellow-800'
                          }
                        >
                          {p.last_status}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground text-sm">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {p.last_run_at ? new Date(p.last_run_at).toLocaleString() : '—'}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {p.next_run_at ? new Date(p.next_run_at).toLocaleString() : '—'}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => openEdit(p)}
                          data-testid={`edit-${p.id}`}
                        >
                          <Pencil className="h-3 w-3" />
                        </Button>
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-red-600 hover:bg-red-50"
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>{t('pages.rotationPolicies.confirmDelete.title')}</AlertDialogTitle>
                              <AlertDialogDescription>
                                {t('pages.rotationPolicies.confirmDelete.descriptionBefore')}
                                <strong>{secretName(p.secret_id)}</strong>
                                {t('pages.rotationPolicies.confirmDelete.descriptionAfter')}
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => deleteMutation.mutate(p.id)}
                                className="bg-red-600 hover:bg-red-700"
                              >
                                {t('common.delete')}
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {policies.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={9} className="text-center text-muted-foreground py-8">
                      {t('pages.rotationPolicies.list.empty')}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {showDialog && <RotationPolicyDialog
        key={editingPolicy?.id ?? 'new'}
        open={showDialog}
        onOpenChange={setShowDialog}
        policy={editingPolicy}
      />}
    </div>
  )
}
