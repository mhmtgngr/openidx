import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  Search,
  Copy,
  ChevronDown,
  ChevronRight,
  AlertCircle,
  Filter,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import {
  Card,
  CardContent,
} from '../components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table'
import { api } from '../lib/api'
import { QueryError } from '../components/query-error'
import { useToast } from '../hooks/use-toast'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ErrorEntry {
  code: string
  http_status: number
  category: string
  description: string
  resolution: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * The categories the error registry assigns. The filter names them in
 * title case and a row's badge in lowercase, and both resolve off this one
 * list, so the filter cannot come to offer a set the rows do not use.
 */
const CATEGORIES = ['auth', 'resource', 'validation', 'system'] as const

const CATEGORY_COLORS: Record<string, string> = {
  auth: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  resource: 'bg-blue-100 text-blue-800 border-blue-200',
  validation: 'bg-orange-100 text-orange-800 border-orange-200',
  system: 'bg-red-100 text-red-800 border-red-200',
}

const HTTP_STATUS_COLORS: Record<string, string> = {
  '4': 'bg-yellow-100 text-yellow-800',
  '5': 'bg-red-100 text-red-800',
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ErrorCatalogPage() {
  const { toast } = useToast()
  const { t } = useTranslation()

  const [searchTerm, setSearchTerm] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())

  const { data: errors = [], isLoading, isError, error } = useQuery({
    queryKey: ['error-catalog'],
    // The backend wraps the list as { errors: [...], total }. Unwrap to the
    // array the UI filters over (a bare array would crash with
    // "j.filter is not a function").
    queryFn: async () => {
      const res = await api.get<{ errors: ErrorEntry[]; total: number }>(
        '/api/v1/error-catalog'
      )
      return res.errors ?? []
    },
  })

  // Filter errors
  const filteredErrors = useMemo(() => {
    return errors.filter((err) => {
      const matchesSearch =
        !searchTerm.trim() ||
        err.code.toLowerCase().includes(searchTerm.toLowerCase()) ||
        err.description.toLowerCase().includes(searchTerm.toLowerCase())
      const matchesCategory =
        !categoryFilter || err.category === categoryFilter
      return matchesSearch && matchesCategory
    })
  }, [errors, searchTerm, categoryFilter])

  const toggleRow = (code: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev)
      if (next.has(code)) {
        next.delete(code)
      } else {
        next.add(code)
      }
      return next
    })
  }

  const copyErrorCode = (code: string) => {
    navigator.clipboard.writeText(code)
    toast({
      title: t('common.copied'),
      description: t('pages.errorCatalog.copied', { code }),
    })
  }

  const httpStatusColor = (status: number) => {
    const prefix = String(status).charAt(0)
    return HTTP_STATUS_COLORS[prefix] || 'bg-muted text-foreground'
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">
            {t('nav.items.errorCatalog')}
          </h1>
          <p className="text-muted-foreground">
            {t('pages.errorCatalog.subtitle')}
          </p>
        </div>
      </div>

      {/* Search and filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder={t('pages.errorCatalog.searchPlaceholder')}
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-9"
              />
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <select
                aria-label={t('pages.errorCatalog.categoryFilterLabel')}
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="flex h-10 rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                <option value="">{t('pages.errorCatalog.allCategories')}</option>
                {CATEGORIES.map((cat) => (
                  <option key={cat} value={cat}>
                    {t(`pages.errorCatalog.categoryOptions.${cat}`)}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <p className="text-xs text-muted-foreground mt-2">
            {t('pages.errorCatalog.shown', {
              shown: filteredErrors.length,
              total: errors.length,
            })}
          </p>
        </CardContent>
      </Card>

      {/* Error table */}
      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <p className="text-center py-8 text-muted-foreground">
              {t('pages.errorCatalog.loading')}
            </p>
          ) : isError ? (
            <QueryError error={error} resource={t('pages.errorCatalog.resource')} />
          ) : filteredErrors.length === 0 ? (
            <div className="text-center py-12">
              <AlertCircle className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
              <p className="text-muted-foreground">
                {t('pages.errorCatalog.empty')}
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>{t('pages.errorCatalog.colCode')}</TableHead>
                  <TableHead className="w-24">{t('pages.errorCatalog.colStatus')}</TableHead>
                  <TableHead className="w-32">{t('pages.errorCatalog.colCategory')}</TableHead>
                  <TableHead>{t('pages.errorCatalog.colDescription')}</TableHead>
                  <TableHead className="w-12" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredErrors.map((err) => {
                  const isExpanded = expandedRows.has(err.code)
                  const catColor =
                    CATEGORY_COLORS[err.category] || 'bg-muted text-foreground border-border'

                  return (
                    <>
                      <TableRow
                        key={err.code}
                        className="cursor-pointer"
                        onClick={() => toggleRow(err.code)}
                      >
                        <TableCell className="w-8 pr-0">
                          {isExpanded ? (
                            <ChevronDown className="h-4 w-4 text-muted-foreground" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-muted-foreground" />
                          )}
                        </TableCell>
                        {/* The code, its status, description and resolution are
                            the registry's own text: an operator matches them
                            against a log line or quotes them in a ticket. */}
                        <TableCell>
                          <code className="text-sm font-mono font-semibold">{err.code}</code>
                        </TableCell>
                        <TableCell>
                          <span
                            className={`inline-block text-xs font-semibold px-2 py-0.5 rounded ${httpStatusColor(
                              err.http_status
                            )}`}
                          >
                            {err.http_status}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span
                            className={`inline-block text-xs font-medium px-2 py-0.5 rounded-full border ${catColor}`}
                          >
                            {t(`pages.errorCatalog.categories.${err.category}`, {
                              defaultValue: err.category,
                            })}
                          </span>
                        </TableCell>
                        <TableCell className="text-sm">{err.description}</TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation()
                              copyErrorCode(err.code)
                            }}
                          >
                            <Copy className="h-3.5 w-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                      {isExpanded && (
                        <TableRow key={`${err.code}-detail`}>
                          <TableCell colSpan={6} className="bg-muted/30">
                            <div className="p-3 space-y-2">
                              <h4 className="text-sm font-semibold">
                                {t('pages.errorCatalog.resolution')}
                              </h4>
                              <p className="text-sm text-muted-foreground leading-relaxed">
                                {err.resolution}
                              </p>
                            </div>
                          </TableCell>
                        </TableRow>
                      )}
                    </>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
