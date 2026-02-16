import { useState } from 'react'
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

const API_SPECS = [
  { id: 'identity', label: 'Identity', file: 'identity-service.yaml' },
  { id: 'oauth', label: 'OAuth/OIDC', file: 'oauth-service.yaml' },
  { id: 'admin', label: 'Admin API', file: 'admin-api.yaml' },
  { id: 'access', label: 'Access', file: 'access-service.yaml' },
  { id: 'governance', label: 'Governance', file: 'governance-service.yaml' },
  { id: 'provisioning', label: 'SCIM', file: 'provisioning-service.yaml' },
  { id: 'audit', label: 'Audit', file: 'audit-service.yaml' },
  { id: 'notifications', label: 'Notifications', file: 'notifications-service.yaml' },
  { id: 'organization', label: 'Organizations', file: 'organization-service.yaml' },
  { id: 'portal', label: 'Portal', file: 'portal-service.yaml' },
]

const requestInterceptor = (req: Record<string, any>) => {
  const token = localStorage.getItem('token')
  if (token) {
    req.headers = { ...(req.headers as object), Authorization: `Bearer ${token}` }
  }
  return req
}

export function ApiDocsPage() {
  const [activeSpec, setActiveSpec] = useState('identity')

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">API Documentation</h1>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Interactive API Reference</CardTitle>
          <CardDescription>
            Explore and test OpenIDX APIs. Your authentication token is automatically included in requests.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs value={activeSpec} onValueChange={setActiveSpec}>
            <TabsList className="flex flex-wrap gap-1 h-auto mb-4">
              {API_SPECS.map((spec) => (
                <TabsTrigger key={spec.id} value={spec.id} className="text-xs">
                  {spec.label}
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
