import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, VaultSecretMeta, VaultRotationPolicy, VaultRotationPolicyInput } from '../lib/api'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from './ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select'
import { useToast } from '../hooks/use-toast'
import {
  CONNECTOR_FIELDS,
  CONNECTOR_TYPES,
  ConnectorField,
  IntervalUnit,
  PolicyFormState,
  SCHEMA_CONNECTORS,
  blankForm,
  connectorConfigValid,
  formToInput,
  policyToForm,
  seedConnectorConfig,
} from '../lib/rotation-policy-form'

/**
 * Create/edit dialog for a rotation policy. Pass `policy` to edit, or
 * `initial` to open a create form prefilled (e.g. with a fixed secret).
 */
export function RotationPolicyDialog({
  open,
  onOpenChange,
  policy,
  initial,
  onSaved,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  policy?: VaultRotationPolicy | null
  initial?: Partial<PolicyFormState>
  onSaved?: (p: VaultRotationPolicy) => void
}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  // The form is seeded when the dialog mounts; callers remount it per open.
  const [form, setForm] = useState<PolicyFormState>(() =>
    policy ? policyToForm(policy) : { ...blankForm(), ...initial },
  )

  const { data: secretsData } = useQuery({
    queryKey: ['vault-secrets'],
    queryFn: () => api.vault.listSecrets(),
    enabled: open,
  })
  const secrets: VaultSecretMeta[] = secretsData?.secrets || []

  function done(p: VaultRotationPolicy, key: string) {
    queryClient.invalidateQueries({ queryKey: ['rotation-policies'] })
    onOpenChange(false)
    toast({ title: t(`pages.rotationPolicies.toasts.${key}`) })
    onSaved?.(p)
  }

  const createMutation = useMutation({
    mutationFn: (body: VaultRotationPolicyInput) => api.vault.createPolicy(body),
    onSuccess: (p) => done(p, 'created'),
    onError: () => {
      toast({ title: t('pages.rotationPolicies.toasts.createFailed'), variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: VaultRotationPolicyInput }) =>
      api.vault.updatePolicy(id, body),
    onSuccess: (p) => done(p, 'updated'),
    onError: () => {
      toast({ title: t('pages.rotationPolicies.toasts.updateFailed'), variant: 'destructive' })
    },
  })

  function handleSubmit() {
    const body = formToInput(form)
    if (policy) {
      updateMutation.mutate({ id: policy.id, body })
    } else {
      createMutation.mutate(body)
    }
  }

  const isPending = createMutation.isPending || updateMutation.isPending
  const isFormValid = !!form.secretId && !!form.connectorType && connectorConfigValid(form)

  return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {policy
                ? t('pages.rotationPolicies.dialog.editTitle')
                : t('pages.rotationPolicies.dialog.createTitle')}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            {/* Secret */}
            <div>
              <label htmlFor="rotation-policies-secret" className="text-sm font-medium">{t('pages.rotationPolicies.dialog.secret')}</label>
              <Select
                value={form.secretId}
                onValueChange={(v) => setForm((f) => ({ ...f, secretId: v }))}
              >
                <SelectTrigger id="rotation-policies-secret" className="mt-1" data-testid="secret-select">
                  <SelectValue placeholder={t('pages.rotationPolicies.dialog.secretPlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  {secrets.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Connector type */}
            <div>
              <label htmlFor="rotation-policies-connector-type" className="text-sm font-medium">{t('pages.rotationPolicies.dialog.connectorType')}</label>
              <Select
                value={form.connectorType}
                onValueChange={(v) =>
                  setForm((f) => ({ ...f, connectorType: v, connectorConfig: seedConnectorConfig(v) }))
                }
              >
                <SelectTrigger id="rotation-policies-connector-type" className="mt-1" data-testid="connector-select">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CONNECTOR_TYPES.map((c) => (
                    <SelectItem key={c} value={c}>
                      {t(`pages.rotationPolicies.connectors.${c}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Directory-specific fields */}
            {form.connectorType === 'directory' && (
              <>
                <div>
                  <label className="text-sm font-medium">{t('pages.rotationPolicies.dialog.directoryId')}</label>
                  <Input
                    className="mt-1"
                    placeholder={t('pages.rotationPolicies.dialog.directoryIdPlaceholder')}
                    value={form.directoryId}
                    onChange={(e) => setForm((f) => ({ ...f, directoryId: e.target.value }))}
                    data-testid="directory-id-input"
                  />
                </div>
                <div>
                  <label className="text-sm font-medium">{t('pages.rotationPolicies.dialog.username')}</label>
                  <Input
                    className="mt-1"
                    placeholder={t('pages.rotationPolicies.dialog.usernamePlaceholder')}
                    value={form.username}
                    onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
                    data-testid="username-input"
                  />
                </div>
              </>
            )}

            {/* Schema-driven connector fields (ssh / ssh_key / postgres / mysql) */}
            {SCHEMA_CONNECTORS.includes(form.connectorType) && (
              <div className="space-y-3">
                {CONNECTOR_FIELDS[form.connectorType].map((field) => (
                  <ConnectorFieldInput
                    key={field.key}
                    field={field}
                    value={form.connectorConfig[field.key] ?? ''}
                    secrets={secrets}
                    onChange={(val) =>
                      setForm((f) => ({
                        ...f,
                        connectorConfig: { ...f.connectorConfig, [field.key]: val },
                      }))
                    }
                  />
                ))}
              </div>
            )}

            {/* Interval */}
            <div>
              <label htmlFor="rotation-policies-interval" className="text-sm font-medium">{t('pages.rotationPolicies.dialog.interval')}</label>
              <div className="flex gap-2 mt-1">
                <Input id="rotation-policies-interval"
                  type="number"
                  min={0}
                  className="flex-1"
                  value={form.intervalValue}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, intervalValue: parseInt(e.target.value, 10) || 0 }))
                  }
                />
                <Select
                  value={form.intervalUnit}
                  onValueChange={(v) => setForm((f) => ({ ...f, intervalUnit: v as IntervalUnit }))}
                >
                  <SelectTrigger aria-label={t('pages.rotationPolicies.intervalUnitLabel')} className="w-32">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="seconds">{t('pages.rotationPolicies.dialog.units.seconds')}</SelectItem>
                    <SelectItem value="minutes">{t('pages.rotationPolicies.dialog.units.minutes')}</SelectItem>
                    <SelectItem value="hours">{t('pages.rotationPolicies.dialog.units.hours')}</SelectItem>
                    <SelectItem value="days">{t('pages.rotationPolicies.dialog.units.days')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Rotate on checkout */}
            <div className="flex items-center gap-3">
              <input
                type="checkbox"
                id="rotateOnCheckout"
                checked={form.rotateOnCheckout}
                onChange={(e) => setForm((f) => ({ ...f, rotateOnCheckout: e.target.checked }))}
                className="h-4 w-4"
              />
              <label htmlFor="rotateOnCheckout" className="text-sm font-medium">
                {t('pages.rotationPolicies.dialog.rotateOnCheckout')}
              </label>
            </div>

            {/* Generation policy */}
            <div className="space-y-2 border rounded-lg p-3">
              <p className="text-sm font-medium">{t('pages.rotationPolicies.dialog.generation')}</p>
              <div>
                <label htmlFor="rotation-policies-length" className="text-xs text-muted-foreground">{t('pages.rotationPolicies.dialog.length')}</label>
                <Input id="rotation-policies-length"
                  type="number"
                  min={8}
                  max={256}
                  className="mt-1"
                  value={form.genLength}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, genLength: parseInt(e.target.value, 10) || 24 }))
                  }
                />
              </div>
              <div className="flex gap-4">
                {(
                  [
                    ['genUpper', 'upper'],
                    ['genLower', 'lower'],
                    ['genDigits', 'digits'],
                    ['genSymbols', 'symbols'],
                  ] as const
                ).map(([key, labelKey]) => (
                  <label key={key} className="flex items-center gap-1 text-sm">
                    <input
                      type="checkbox"
                      checked={form[key]}
                      onChange={(e) =>
                        setForm((f) => ({ ...f, [key]: e.target.checked }))
                      }
                      className="h-4 w-4"
                    />
                    {t(`pages.rotationPolicies.dialog.charsets.${labelKey}`)}
                  </label>
                ))}
              </div>
            </div>

            {/* Enabled toggle */}
            <div className="flex items-center gap-3">
              <input
                type="checkbox"
                id="enabled"
                checked={form.enabled}
                onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
                className="h-4 w-4"
              />
              <label htmlFor="enabled" className="text-sm font-medium">
                {t('pages.rotationPolicies.dialog.enabled')}
              </label>
            </div>

            <Button
              onClick={handleSubmit}
              disabled={!isFormValid || isPending}
              className="w-full"
            >
              {isPending
                ? policy
                  ? t('pages.rotationPolicies.dialog.saving')
                  : t('pages.rotationPolicies.dialog.creating')
                : policy
                ? t('pages.rotationPolicies.dialog.save')
                : t('pages.rotationPolicies.dialog.create')}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
  )
}

function ConnectorFieldInput({
  field,
  value,
  secrets,
  onChange,
}: {
  field: ConnectorField
  value: string
  secrets: VaultSecretMeta[]
  onChange: (val: string) => void
}) {
  const { t } = useTranslation()
  const fieldLabel = t(`pages.rotationPolicies.fields.${field.labelKey}`)
  const label = `${fieldLabel}${field.required ? ' *' : ''}`
  const testId = `cc-${field.key}`

  if (field.type === 'secret') {
    return (
      <div>
        <label htmlFor={testId} className="text-sm font-medium">{label}</label>
        <Select value={value} onValueChange={onChange}>
          <SelectTrigger id={testId} className="mt-1" data-testid={testId}>
            <SelectValue placeholder={t('pages.rotationPolicies.fields.selectSecret')} />
          </SelectTrigger>
          <SelectContent>
            {secrets.map((s) => (
              <SelectItem key={s.id} value={s.id}>
                {s.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    )
  }

  if (field.type === 'select') {
    return (
      <div>
        <label htmlFor={testId} className="text-sm font-medium">{label}</label>
        <Select value={value} onValueChange={onChange}>
          <SelectTrigger id={testId} className="mt-1" data-testid={testId}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {(field.options ?? []).map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.labelKey ? t(`pages.rotationPolicies.fields.${o.labelKey}`) : o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    )
  }

  if (field.type === 'textarea') {
    return (
      <div>
        <label htmlFor={testId} className="text-sm font-medium">{label}</label>
        <textarea
          id={testId}
          className="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
          rows={2}
          placeholder={field.placeholder}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          data-testid={testId}
        />
      </div>
    )
  }

  if (field.type === 'checkbox') {
    return (
      <div className="flex items-center gap-3">
        <input
          type="checkbox"
          id={testId}
          checked={value === 'true'}
          onChange={(e) => onChange(e.target.checked ? 'true' : '')}
          data-testid={testId}
        />
        <label htmlFor={testId} className="text-sm font-medium">
          {fieldLabel}
        </label>
      </div>
    )
  }

  // 'text' | 'number'
  return (
    <div>
      <label htmlFor={testId} className="text-sm font-medium">{label}</label>
      <Input
        id={testId}
        className="mt-1"
        type={field.type === 'number' ? 'number' : 'text'}
        placeholder={field.placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        data-testid={testId}
      />
    </div>
  )
}
