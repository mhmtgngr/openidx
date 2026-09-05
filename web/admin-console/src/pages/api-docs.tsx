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
import { API_SPECS } from '@/lib/api-specs'

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
