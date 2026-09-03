import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import SwaggerUI from 'swagger-ui-react'
import 'swagger-ui-react/swagger-ui.css'
import '../styles/swagger-overrides.css'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '../components/ui/card'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/tabs'

/** Each tab names a service; the spec file behind it is a path, not prose. */
const API_SPECS = [
  { id: 'identity', file: 'identity-service.yaml' },
  { id: 'oauth', file: 'oauth-service.yaml' },
  { id: 'admin', file: 'admin-api.yaml' },
  { id: 'access', file: 'access-service.yaml' },
  { id: 'governance', file: 'governance-service.yaml' },
  { id: 'provisioning', file: 'provisioning-service.yaml' },
  { id: 'audit', file: 'audit-service.yaml' },
  { id: 'notifications', file: 'notifications-service.yaml' },
  { id: 'organization', file: 'organization-service.yaml' },
  { id: 'portal', file: 'portal-service.yaml' },
] as const

const requestInterceptor = (req: Record<string, any>) => {
  const token = localStorage.getItem('token')
  if (token) {
    req.headers = { ...(req.headers as object), Authorization: `Bearer ${token}` }
  }
  return req
}

export function ApiDocsPage() {
  const { t } = useTranslation()
  const [activeSpec, setActiveSpec] = useState('identity')

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t('pages.apiDocs.title')}</h1>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t('pages.apiDocs.cardTitle')}</CardTitle>
          <CardDescription>
            {t('pages.apiDocs.cardDesc')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs value={activeSpec} onValueChange={setActiveSpec}>
            <TabsList className="flex flex-wrap gap-1 h-auto mb-4">
              {API_SPECS.map((spec) => (
                <TabsTrigger key={spec.id} value={spec.id} className="text-xs">
                  {t(`pages.apiDocs.specs.${spec.id}`)}
                </TabsTrigger>
              ))}
            </TabsList>
            {API_SPECS.map((spec) => (
              <TabsContent key={spec.id} value={spec.id}>
                <div className="swagger-wrapper">
                  <SwaggerUI
                    url={`/api-specs/${spec.file}`}
                    requestInterceptor={requestInterceptor}
                    docExpansion="list"
                    defaultModelsExpandDepth={1}
                    filter={true}
                  />
                </div>
              </TabsContent>
            ))}
          </Tabs>
        </CardContent>
      </Card>
    </div>
  )
}
