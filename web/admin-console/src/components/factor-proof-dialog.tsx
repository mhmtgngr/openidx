import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from './ui/dialog'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Label } from './ui/label'
import type { FactorProof, ProofField } from '../lib/factor-proof'

export interface FactorProofRequest {
  accepts: ProofField[]
  // failed: the last proof given was wrong.
  failed: boolean
  busy: boolean
  // attempt counts the prompts for one change; each starts with empty fields.
  attempt: number
}

interface FactorProofDialogProps {
  request: FactorProofRequest | null
  onSubmit: (proof: FactorProof) => void
  onCancel: () => void
}

// FactorProofDialog asks for the proof a change to the account's second
// factors needs: the password, or a code from the authenticator app where the
// change accepts one.
export function FactorProofDialog({ request, onSubmit, onCancel }: FactorProofDialogProps) {
  const { t } = useTranslation()
  const acceptsPassword = !!request?.accepts.includes('current_password')
  const acceptsCode = !!request?.accepts.includes('totp_code')
  const description =
    acceptsPassword && acceptsCode
      ? t('components.factorProof.descriptionEither')
      : acceptsCode
        ? t('components.factorProof.descriptionCode')
        : t('components.factorProof.descriptionPassword')

  return (
    <Dialog open={request !== null} onOpenChange={(next) => { if (!next) onCancel() }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('components.factorProof.title')}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        {request && (
          // Keyed by the attempt, so every prompt starts with empty fields.
          <ProofFields
            key={request.attempt}
            request={request}
            acceptsPassword={acceptsPassword}
            acceptsCode={acceptsCode}
            onSubmit={onSubmit}
            onCancel={onCancel}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}

interface ProofFieldsProps {
  request: FactorProofRequest
  acceptsPassword: boolean
  acceptsCode: boolean
  onSubmit: (proof: FactorProof) => void
  onCancel: () => void
}

function ProofFields({ request, acceptsPassword, acceptsCode, onSubmit, onCancel }: ProofFieldsProps) {
  const { t } = useTranslation()
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const ready = password !== '' || code.length === 6

  const submit = () => {
    if (!ready || request.busy) return
    onSubmit(password !== '' ? { current_password: password } : { totp_code: code })
  }

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault()
        submit()
      }}
    >
      {request.failed && (
        <p role="alert" className="text-sm font-medium text-red-600">
          {acceptsCode ? t('components.factorProof.failedEither') : t('components.factorProof.failedPassword')}
        </p>
      )}
      {acceptsPassword && (
        <div className="space-y-2">
          <Label htmlFor="factor-proof-password">{t('components.factorProof.passwordLabel')}</Label>
          <Input
            id="factor-proof-password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={request.busy}
            autoFocus
          />
        </div>
      )}
      {acceptsCode && (
        <div className="space-y-2">
          <Label htmlFor="factor-proof-code">{t('components.factorProof.codeLabel')}</Label>
          <Input
            id="factor-proof-code"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            disabled={request.busy}
          />
        </div>
      )}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel} disabled={request.busy}>
          {t('common.cancel')}
        </Button>
        <Button type="submit" disabled={!ready || request.busy}>
          {t('components.factorProof.confirm')}
        </Button>
      </DialogFooter>
    </form>
  )
}
