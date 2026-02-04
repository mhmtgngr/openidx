import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { PlayCircle, Loader2, CheckCircle2, XCircle, AlertCircle, Clock } from 'lucide-react'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from './ui/dialog'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface TestResult {
  success: boolean
  latency_ms: number
  status_code?: number
  error_message?: string
  details?: Record<string, unknown>
}

interface ConnectionTestResult {
  success: boolean
  tests: Record<string, TestResult>
  overall_latency_ms: number
  tested_at: string
}

interface ConnectionTestButtonProps {
  routeId: string
  variant?: 'default' | 'outline' | 'secondary'
  size?: 'default' | 'sm' | 'lg' | 'icon'
}

export function ConnectionTestButton({ routeId, variant = 'outline', size = 'default' }: ConnectionTestButtonProps) {
  const { toast } = useToast()
  const [showResults, setShowResults] = useState(false)
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null)

  const testConnection = useMutation({
    mutationFn: async () => {
      return api.post<ConnectionTestResult>(`/api/v1/access/services/${routeId}/test-connection`, {
        test_type: 'full',
        timeout_seconds: 15,
      })
    },
    onSuccess: (data) => {
      setTestResult(data)
      setShowResults(true)
      if (data.success) {
        toast({ title: 'Connection Test Passed', description: `All tests completed in ${data.overall_latency_ms}ms` })
      } else {
        toast({ title: 'Connection Test Failed', description: 'One or more tests failed', variant: 'destructive' })
      }
    },
    onError: (error: Error) => {
      toast({ title: 'Test Error', description: error.message, variant: 'destructive' })
    },
  })

  return (
    <>
      <Button
        variant={variant}
        size={size}
        onClick={() => testConnection.mutate()}
        disabled={testConnection.isPending}
      >
        {testConnection.isPending ? (
          <Loader2 className="h-4 w-4 mr-2 animate-spin" />
        ) : (
          <PlayCircle className="h-4 w-4 mr-2" />
        )}
        {testConnection.isPending ? 'Testing...' : 'Test Connection'}
      </Button>

      <Dialog open={showResults} onOpenChange={setShowResults}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              Connection Test Results
              {testResult?.success ? (
                <CheckCircle2 className="h-5 w-5 text-green-500" />
              ) : (
                <XCircle className="h-5 w-5 text-red-500" />
              )}
            </DialogTitle>
          </DialogHeader>
          {testResult && (
            <div className="space-y-4">
              {/* Overall Stats */}
              <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                <div className="flex items-center gap-2">
                  <Clock className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm text-muted-foreground">Total Time</span>
                </div>
                <span className="font-mono font-medium">{testResult.overall_latency_ms}ms</span>
              </div>

              {/* Individual Test Results */}
              <div className="space-y-3">
                {Object.entries(testResult.tests).map(([name, result]) => (
                  <div key={name} className="border rounded-lg p-3">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        {result.success ? (
                          <CheckCircle2 className="h-4 w-4 text-green-500" />
                        ) : (
                          <XCircle className="h-4 w-4 text-red-500" />
                        )}
                        <span className="font-medium capitalize">{name.replace('_', ' ')}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={result.success ? 'default' : 'destructive'}>
                          {result.success ? 'Pass' : 'Fail'}
                        </Badge>
                        <span className="text-sm text-muted-foreground font-mono">
                          {result.latency_ms}ms
                        </span>
                      </div>
                    </div>
                    {result.status_code && (
                      <div className="text-sm text-muted-foreground">
                        HTTP Status: {result.status_code}
                      </div>
                    )}
                    {result.error_message && (
                      <div className="mt-2 p-2 bg-red-50 dark:bg-red-950 rounded text-sm text-red-600 dark:text-red-400 flex items-start gap-2">
                        <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                        <span>{result.error_message}</span>
                      </div>
                    )}
                    {result.details && Object.keys(result.details).length > 0 && (
                      <div className="mt-2 text-xs text-muted-foreground">
                        <div className="font-medium mb-1">Details:</div>
                        <pre className="bg-muted p-2 rounded overflow-auto max-h-32">
                          {JSON.stringify(result.details, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                ))}
              </div>

              {/* Timestamp */}
              <div className="text-xs text-muted-foreground text-center">
                Tested at {new Date(testResult.tested_at).toLocaleString()}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}
