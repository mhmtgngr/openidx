// Package routes provides API documentation route registration for the gateway
package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RegisterDocsRoutes registers API documentation endpoints
func RegisterDocsRoutes(router *gin.Engine, provider ServiceURLProvider) {
	// Combined OpenAPI spec
	router.GET("/api/docs", combinedOpenAPISpecHandler())

	// Service-specific OpenAPI specs
	router.GET("/api/docs/identity", identityOpenAPISpecHandler())
	router.GET("/api/docs/oauth", oauthOpenAPISpecHandler())
	router.GET("/api/docs/governance", governanceOpenAPISpecHandler())
	router.GET("/api/docs/audit", auditOpenAPISpecHandler())
	router.GET("/api/docs/admin", adminOpenAPISpecHandler())
	router.GET("/api/docs/risk", riskOpenAPISpecHandler())

	// API documentation in HTML format
	router.GET("/api/docs/html", docsHTMLHandler())

	// API schema
	router.GET("/api/docs/schema", jsonSchemaHandler())
}

// combinedOpenAPISpecHandler returns a combined OpenAPI specification for all services
func combinedOpenAPISpecHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		spec := generateCombinedOpenAPISpec()
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusOK, spec)
	}
}

// identityOpenAPISpecHandler returns the OpenAPI spec for the identity service
func identityOpenAPISpecHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		spec := generateServiceOpenAPISpec("Identity Service", "1.0.0")
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusOK, spec)
	}
}

// oauthOpenAPISpecHandler returns the OpenAPI spec for the OAuth service
func oauthOpenAPISpecHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		spec := generateServiceOpenAPISpec("OAuth Service", "1.0.0")
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusOK, spec)
	}
}

// governanceOpenAPISpecHandler returns the OpenAPI spec for the governance service
func governanceOpenAPISpecHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		spec := generateServiceOpenAPISpec("Governance Service", "1.0.0")
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusOK, spec)
	}
}

// auditOpenAPISpecHandler returns the OpenAPI spec for the audit service
func auditOpenAPISpecHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		spec := generateServiceOpenAPISpec("Audit Service", "1.0.0")
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusOK, spec)
	}
}

// adminOpenAPISpecHandler returns the OpenAPI spec for the admin API
func adminOpenAPISpecHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		spec := generateServiceOpenAPISpec("Admin API", "1.0.0")
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusOK, spec)
	}
}

// riskOpenAPISpecHandler returns the OpenAPI spec for the risk service
func riskOpenAPISpecHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		spec := generateServiceOpenAPISpec("Risk Service", "1.0.0")
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusOK, spec)
	}
}

// docsHTMLHandler returns an HTML page for API documentation
func docsHTMLHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		html := generateDocsHTML()
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, html)
	}
}

// jsonSchemaHandler returns the JSON schema for the API
func jsonSchemaHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		schema := generateJSONSchema()
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusOK, schema)
	}
}

// generateCombinedOpenAPISpec generates a combined OpenAPI specification
func generateCombinedOpenAPISpec() map[string]interface{} {
	return map[string]interface{}{
		"openapi": "3.0.0",
		"info": map[string]interface{}{
			"title":       "OpenIDX API Gateway",
			"description": "Unified API for all OpenIDX services",
			"version":     "1.0.0",
		},
		"servers": []map[string]interface{}{
			{
				"url":         "http://localhost:8500",
				"description": "Development server",
			},
		},
		"paths": map[string]interface{}{
			"/api/v1/identity/users": map[string]interface{}{
				"get": map[string]interface{}{
					"summary": "List users",
					"tags":   []string{"identity"},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
						},
					},
				},
			},
			"/api/v1/oauth/token": map[string]interface{}{
				"post": map[string]interface{}{
					"summary": "Get OAuth token",
					"tags":   []string{"oauth"},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
						},
					},
				},
			},
			"/api/v1/governance/reviews": map[string]interface{}{
				"get": map[string]interface{}{
					"summary": "List access reviews",
					"tags":   []string{"governance"},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
						},
					},
				},
			},
			"/api/v1/audit/events": map[string]interface{}{
				"get": map[string]interface{}{
					"summary": "List audit events",
					"tags":   []string{"audit"},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
						},
					},
				},
			},
			"/api/v1/admin/users": map[string]interface{}{
				"get": map[string]interface{}{
					"summary": "List users (admin)",
					"tags":   []string{"admin"},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
						},
					},
				},
			},
			"/api/v1/risk/score": map[string]interface{}{
				"post": map[string]interface{}{
					"summary": "Calculate risk score",
					"tags":   []string{"risk"},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
						},
					},
				},
			},
		},
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"bearerAuth": map[string]interface{}{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
				},
			},
		},
	}
}

// generateServiceOpenAPISpec generates an OpenAPI spec for a single service
func generateServiceOpenAPISpec(title, version string) map[string]interface{} {
	return map[string]interface{}{
		"openapi": "3.0.0",
		"info": map[string]interface{}{
			"title":   "OpenIDX " + title,
			"version": version,
		},
		"paths": map[string]interface{}{},
	}
}

// generateDocsHTML generates an HTML page for API documentation
func generateDocsHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenIDX API Documentation</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .service { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .service h2 { color: #0066cc; }
        a { color: #0066cc; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>OpenIDX API Documentation</h1>
    <p>Welcome to the OpenIDX API Gateway. Select a service below to view its documentation:</p>

    <div class="service">
        <h2>Identity Service</h2>
        <p>User management, authentication, and session handling.</p>
        <a href="/api/docs/identity">View OpenAPI Spec</a>
    </div>

    <div class="service">
        <h2>OAuth Service</h2>
        <p>OAuth 2.0 and OpenID Connect endpoints.</p>
        <a href="/api/docs/oauth">View OpenAPI Spec</a>
    </div>

    <div class="service">
        <h2>Governance Service</h2>
        <p>Access reviews, policies, and certifications.</p>
        <a href="/api/docs/governance">View OpenAPI Spec</a>
    </div>

    <div class="service">
        <h2>Audit Service</h2>
        <p>Audit logging and compliance reports.</p>
        <a href="/api/docs/audit">View OpenAPI Spec</a>
    </div>

    <div class="service">
        <h2>Admin API</h2>
        <p>Administrative operations and settings.</p>
        <a href="/api/docs/admin">View OpenAPI Spec</a>
    </div>

    <div class="service">
        <h2>Risk Service</h2>
        <p>Risk scoring and anomaly detection.</p>
        <a href="/api/docs/risk">View OpenAPI Spec</a>
    </div>

    <p><a href="/api/docs">View Combined OpenAPI Spec</a></p>
</body>
</html>`
}

// generateJSONSchema generates the JSON schema for the API
func generateJSONSchema() map[string]interface{} {
	return map[string]interface{}{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"title":   "OpenIDX API Schema",
		"type":    "object",
		"properties": map[string]interface{}{
			"user": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id":       map[string]interface{}{"type": "string"},
					"email":    map[string]interface{}{"type": "string", "format": "email"},
					"name":     map[string]interface{}{"type": "string"},
					"roles":    map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
				},
			},
			"error": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"code":    map[string]interface{}{"type": "string"},
					"message": map[string]interface{}{"type": "string"},
				},
			},
		},
	}
}

// DocsHandler returns a handler for the combined OpenAPI spec
func DocsHandler() gin.HandlerFunc {
	return combinedOpenAPISpecHandler()
}
