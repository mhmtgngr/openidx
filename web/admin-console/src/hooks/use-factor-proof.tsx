import { useCallback, useRef, useState } from 'react'
import { FactorProofDialog, type FactorProofRequest } from '../components/factor-proof-dialog'
import { ProofCancelled, proofRefusal, type FactorProof } from '../lib/factor-proof'

// useFactorProof runs a change to the account's second factors, and when the
// server asks for proof, asks the user for it and runs the change again with
// it. A wrong proof asks again, saying so; closing the prompt fails the change
// with ProofCancelled. A lockout, or an account with no password here, fails
// it with the server's refusal, which proofRefusalMessageKey explains.
//
// The page renders `dialog` once and wraps each change in `withProof`:
//
//   mutationFn: () => withProof((proof) => api.post(url, { ...body, ...proof }))
export function useFactorProof() {
  const [request, setRequest] = useState<FactorProofRequest | null>(null)
  const pending = useRef<{ resolve: (proof: FactorProof) => void; reject: (err: unknown) => void } | null>(null)

  const withProof = useCallback(async <T,>(action: (proof: FactorProof) => Promise<T>): Promise<T> => {
    let proof: FactorProof = {}
    let attempt = 0
    for (;;) {
      try {
        const result = await action(proof)
        setRequest(null)
        return result
      } catch (err) {
        const refusal = proofRefusal(err)
        const answerable =
          refusal !== null &&
          (refusal.code === 'reauthentication_required' || refusal.code === 'reauthentication_failed') &&
          refusal.accepts.length > 0
        if (!answerable) {
          setRequest(null)
          throw err
        }
        proof = await new Promise<FactorProof>((resolve, reject) => {
          pending.current = { resolve, reject }
          setRequest({ accepts: refusal.accepts, failed: attempt > 0, busy: false, attempt })
        })
        attempt++
      }
    }
  }, [])

  const onSubmit = useCallback((proof: FactorProof) => {
    setRequest((current) => (current ? { ...current, busy: true } : current))
    pending.current?.resolve(proof)
    pending.current = null
  }, [])

  const onCancel = useCallback(() => {
    setRequest(null)
    pending.current?.reject(new ProofCancelled())
    pending.current = null
  }, [])

  const dialog = <FactorProofDialog request={request} onSubmit={onSubmit} onCancel={onCancel} />
  return { withProof, dialog }
}
