/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL: string
  readonly VITE_OAUTH_URL: string
  readonly VITE_OAUTH_CLIENT_ID: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

declare module 'swagger-ui-react' {
  import { ComponentType } from 'react'
  interface SwaggerUIProps {
    url?: string
    spec?: object
    requestInterceptor?: (req: any) => any
    responseInterceptor?: (res: any) => any
    docExpansion?: 'list' | 'full' | 'none'
    defaultModelsExpandDepth?: number
    filter?: boolean | string
    [key: string]: any
  }
  const SwaggerUI: ComponentType<SwaggerUIProps>
  export default SwaggerUI
}
