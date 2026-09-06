import { ReactNode } from 'react'
import type { UseQueryResult } from '@tanstack/react-query'
import { QueryError } from './query-error'
import { LoadingSpinner } from './ui/loading-spinner'

interface QueryGateProps<T> {
  /** The react-query result for the page's primary query. */
  query: Pick<UseQueryResult<T>, 'isLoading' | 'isError' | 'error' | 'data'>
  /** Human-readable name for the QueryError message, e.g. "users". */
  resource: string
  /** Optional element shown when the loaded data is empty (empty array / null). */
  empty?: ReactNode
  children: (data: T) => ReactNode
}

function isEmptyData(data: unknown): boolean {
  if (Array.isArray(data)) return data.length === 0
  return data == null
}

/**
 * Single choke-point for read-state rendering: a failed query renders QueryError
 * (which distinguishes 401/403 from a generic failure) instead of falling through
 * to a page's empty state. This is the structural fix for "401/403 masked as empty".
 */
export function QueryGate<T>({ query, resource, empty, children }: QueryGateProps<T>) {
  if (query.isLoading) return <LoadingSpinner />
  if (query.isError) return <QueryError error={query.error} resource={resource} />
  const data = query.data as T
  if (empty !== undefined && isEmptyData(data)) return <>{empty}</>
  return <>{children(data)}</>
}

interface QueryGateAllProps {
  /**
   * Every query whose data the children read. Unlike QueryGate this yields no
   * data — the page reads each `.data` itself — because the point here is the
   * READ STATE, not the payload.
   */
  queries: Array<Pick<UseQueryResult<unknown>, 'isLoading' | 'isError' | 'error'>>
  /** Human-readable name for the QueryError message, e.g. "the network topology". */
  resource: string
  children: ReactNode
}

/**
 * QueryGate for a view assembled from several queries.
 *
 * A page that renders one picture out of N calls and gates only the first one
 * is the masking defect with extra steps: the other N-1 fall through `?? []`,
 * so a 403 on services or a controller that is down draws a clean, believable,
 * mostly-empty diagram. The operator reads "no services" and it means "we
 * could not ask". Fail the whole view if ANY of its inputs failed — a diagram
 * assembled from partial data is not a smaller truth, it is a wrong one.
 *
 * Only for views where the parts are one picture. A dashboard of independent
 * cards wants a gate per card, so one dead subsystem does not blank the rest.
 */
export function QueryGateAll({ queries, resource, children }: QueryGateAllProps) {
  if (queries.some((q) => q.isLoading)) return <LoadingSpinner />
  const failed = queries.find((q) => q.isError)
  if (failed) return <QueryError error={failed.error} resource={resource} />
  return <>{children}</>
}
