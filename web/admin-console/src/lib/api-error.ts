/**
 * The response body of a failed API call, which the axios client keeps on the
 * error's response. Error handlers that read a code from the body read it
 * here: the error itself carries only "Request failed with status code ...".
 */
export function apiErrorBody(err: unknown): Record<string, unknown> | undefined {
  const data = (err as { response?: { data?: unknown } }).response?.data
  return data && typeof data === 'object' ? (data as Record<string, unknown>) : undefined
}
