import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Trash2 } from 'lucide-react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Label } from './ui/label'
import { ConfirmAction } from './confirm-action'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface LoginAddress { id: string; address: string; created_at: string }
interface LoginAddresses { email: string; mail: string; addresses: LoginAddress[] }

const errorCode = (e: unknown): string | undefined =>
  (e as { response?: { data?: { error?: string } } })?.response?.data?.error

/**
 * The addresses a person signs in with, besides their account name: the
 * account's own email and the directory's mail address (they already work, shown
 * read only) and the ones an administrator gives here. A directory sync never
 * touches the administrator's list, and a local account can have one too.
 */
export function LoginAddressesSection({ userId }: { userId: string }) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [address, setAddress] = useState('')
  const key = ['login-addresses', userId]

  const list = useQuery({
    queryKey: key,
    queryFn: () => api.get<LoginAddresses>(`/api/v1/identity/users/${userId}/login-addresses`),
  })

  const add = useMutation({
    mutationFn: (value: string) => api.post(`/api/v1/identity/users/${userId}/login-addresses`, { address: value }),
    onSuccess: () => {
      setAddress('')
      queryClient.invalidateQueries({ queryKey: key })
    },
    onError: (e) => {
      const code = errorCode(e)
      toast({
        title: t(
          code === 'address_in_use' ? 'loginAddresses.inUse'
            : code === 'too_many' ? 'loginAddresses.tooMany'
              : code === 'invalid_address' ? 'loginAddresses.invalid'
                : 'loginAddresses.failed',
        ),
        variant: 'destructive',
      })
    },
  })

  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/identity/users/${userId}/login-addresses/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: key }),
    onError: () => toast({ title: t('loginAddresses.failed'), variant: 'destructive' }),
  })

  const data = list.data
  const own = [data?.email, data?.mail].filter((a, i, all): a is string => !!a && all.indexOf(a) === i)

  return (
    <div className="space-y-3 rounded-md border p-3" data-testid="login-addresses">
      <div>
        <p className="text-sm font-medium">{t('loginAddresses.title')}</p>
        <p className="text-xs text-muted-foreground">{t('loginAddresses.help')}</p>
      </div>

      {list.isError && <p className="text-sm text-destructive">{t('loginAddresses.loadFailed')}</p>}

      <ul className="space-y-1 text-sm">
        {own.map((a) => (
          <li key={a} className="flex items-center justify-between">
            <span>{a}</span>
            <span className="text-xs text-muted-foreground">{t('loginAddresses.fromAccount')}</span>
          </li>
        ))}
        {data?.addresses?.map((a) => (
          <li key={a.id} className="flex items-center justify-between">
            <span>{a.address}</span>
            <ConfirmAction
              title={t('loginAddresses.removeTitle')}
              description={t('loginAddresses.removeDescription', { address: a.address })}
              confirmLabel={t('loginAddresses.remove')}
              destructive
              onConfirm={() => remove.mutateAsync(a.id)}
            >
              {(open) => (
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label={t('loginAddresses.removeAria', { address: a.address })}
                  onClick={open}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              )}
            </ConfirmAction>
          </li>
        ))}
      </ul>

      <div className="space-y-1">
        <Label htmlFor={`login-address-${userId}`}>{t('loginAddresses.add')}</Label>
        <div className="flex gap-2">
          <Input
            id={`login-address-${userId}`}
            type="email"
            autoComplete="off"
            placeholder={t('loginAddresses.placeholder')}
            value={address}
            onChange={(e) => setAddress(e.target.value)}
          />
          <Button
            type="button"
            variant="outline"
            disabled={!address.trim() || add.isPending}
            onClick={() => add.mutate(address.trim())}
          >
            {t('loginAddresses.addButton')}
          </Button>
        </div>
      </div>
    </div>
  )
}
