// Package middleware provides a registry for composable middleware.
// Middleware can be registered with priorities and conditions,
// then automatically composed into the correct order.
package middleware

import (
	"sort"
	"sync"

	"github.com/gin-gonic/gin"
)

// MiddlewareFunc is a gin middleware function
type MiddlewareFunc = gin.HandlerFunc

// Condition determines if middleware should be applied
type Condition func(*gin.Context) bool

// Entry represents a registered middleware
type Entry struct {
	Name      string
	Handler   MiddlewareFunc
	Priority  int  // Lower = runs first
	Enabled   bool
	Condition Condition
	Groups    []string // Route groups this applies to
}

// Registry manages middleware registration and composition
type Registry struct {
	mu          sync.RWMutex
	middlewares map[string]*Entry
	order       []string
}

// NewRegistry creates a new middleware registry
func NewRegistry() *Registry {
	return &Registry{
		middlewares: make(map[string]*Entry),
		order:       make([]string, 0),
	}
}

// RegisterOption configures middleware registration
type RegisterOption func(*Entry)

// WithPriority sets the middleware priority (lower = earlier)
func WithPriority(priority int) RegisterOption {
	return func(e *Entry) {
		e.Priority = priority
	}
}

// WithCondition sets a condition for when to apply middleware
func WithCondition(cond Condition) RegisterOption {
	return func(e *Entry) {
		e.Condition = cond
	}
}

// WithGroups sets which route groups the middleware applies to
func WithGroups(groups ...string) RegisterOption {
	return func(e *Entry) {
		e.Groups = groups
	}
}

// Disabled marks the middleware as disabled
func Disabled() RegisterOption {
	return func(e *Entry) {
		e.Enabled = false
	}
}

// Register registers a middleware
func (r *Registry) Register(name string, handler MiddlewareFunc, opts ...RegisterOption) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry := &Entry{
		Name:     name,
		Handler:  handler,
		Priority: 100, // Default priority
		Enabled:  true,
		Groups:   []string{"*"}, // Apply to all by default
	}

	for _, opt := range opts {
		opt(entry)
	}

	r.middlewares[name] = entry
	r.order = append(r.order, name)
	r.sortOrder()
}

// Unregister removes a middleware
func (r *Registry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.middlewares, name)

	// Remove from order
	newOrder := make([]string, 0, len(r.order)-1)
	for _, n := range r.order {
		if n != name {
			newOrder = append(newOrder, n)
		}
	}
	r.order = newOrder
}

// Enable enables a middleware
func (r *Registry) Enable(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if entry, ok := r.middlewares[name]; ok {
		entry.Enabled = true
	}
}

// Disable disables a middleware
func (r *Registry) Disable(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if entry, ok := r.middlewares[name]; ok {
		entry.Enabled = false
	}
}

// SetPriority changes middleware priority
func (r *Registry) SetPriority(name string, priority int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if entry, ok := r.middlewares[name]; ok {
		entry.Priority = priority
		r.sortOrder()
	}
}

// Build returns all enabled middlewares in priority order
func (r *Registry) Build() []MiddlewareFunc {
	r.mu.RLock()
	defer r.mu.RUnlock()

	handlers := make([]MiddlewareFunc, 0)
	for _, name := range r.order {
		entry := r.middlewares[name]
		if !entry.Enabled {
			continue
		}

		if entry.Condition != nil {
			// Wrap with condition check
			handlers = append(handlers, func(c *gin.Context) {
				if entry.Condition(c) {
					entry.Handler(c)
				} else {
					c.Next()
				}
			})
		} else {
			handlers = append(handlers, entry.Handler)
		}
	}

	return handlers
}

// BuildForGroup returns middlewares for a specific route group
func (r *Registry) BuildForGroup(group string) []MiddlewareFunc {
	r.mu.RLock()
	defer r.mu.RUnlock()

	handlers := make([]MiddlewareFunc, 0)
	for _, name := range r.order {
		entry := r.middlewares[name]
		if !entry.Enabled {
			continue
		}

		// Check if middleware applies to this group
		applies := false
		for _, g := range entry.Groups {
			if g == "*" || g == group {
				applies = true
				break
			}
		}
		if !applies {
			continue
		}

		if entry.Condition != nil {
			h := entry.Handler
			cond := entry.Condition
			handlers = append(handlers, func(c *gin.Context) {
				if cond(c) {
					h(c)
				} else {
					c.Next()
				}
			})
		} else {
			handlers = append(handlers, entry.Handler)
		}
	}

	return handlers
}

// List returns info about all registered middlewares
func (r *Registry) List() []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Entry, 0, len(r.order))
	for _, name := range r.order {
		if entry, ok := r.middlewares[name]; ok {
			result = append(result, *entry)
		}
	}
	return result
}

// Get gets a middleware by name
func (r *Registry) Get(name string) *Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.middlewares[name]
}

// Apply applies all middlewares to a router
func (r *Registry) Apply(router *gin.Engine) {
	for _, handler := range r.Build() {
		router.Use(handler)
	}
}

// ApplyToGroup applies group-specific middlewares
func (r *Registry) ApplyToGroup(group *gin.RouterGroup, groupName string) {
	for _, handler := range r.BuildForGroup(groupName) {
		group.Use(handler)
	}
}

func (r *Registry) sortOrder() {
	sort.Slice(r.order, func(i, j int) bool {
		pi := r.middlewares[r.order[i]].Priority
		pj := r.middlewares[r.order[j]].Priority
		return pi < pj
	})
}

// Predefined priorities
const (
	PriorityFirst       = 0
	PriorityRecovery    = 10
	PrioritySecurity    = 20
	PriorityLogging     = 30
	PriorityMetrics     = 40
	PriorityRateLimit   = 50
	PriorityCORS        = 60
	PriorityAuth        = 70
	PriorityAuthorization = 80
	PriorityValidation  = 90
	PriorityDefault     = 100
	PriorityLast        = 1000
)

// Predefined conditions
var (
	// IsAPI checks if request is to /api/*
	IsAPI Condition = func(c *gin.Context) bool {
		return len(c.Request.URL.Path) >= 4 && c.Request.URL.Path[:4] == "/api"
	}

	// IsAdmin checks if request is to /admin/*
	IsAdmin Condition = func(c *gin.Context) bool {
		return len(c.Request.URL.Path) >= 6 && c.Request.URL.Path[:6] == "/admin"
	}

	// IsPublic checks if request is to public endpoints
	IsPublic Condition = func(c *gin.Context) bool {
		publicPaths := []string{"/health", "/metrics", "/ready", "/.well-known"}
		for _, p := range publicPaths {
			if len(c.Request.URL.Path) >= len(p) && c.Request.URL.Path[:len(p)] == p {
				return true
			}
		}
		return false
	}

	// NotPublic is the inverse of IsPublic
	NotPublic Condition = func(c *gin.Context) bool {
		return !IsPublic(c)
	}

	// HasAuthHeader checks if Authorization header is present
	HasAuthHeader Condition = func(c *gin.Context) bool {
		return c.GetHeader("Authorization") != ""
	}
)

// Builder provides fluent API for building middleware chain
type Builder struct {
	registry *Registry
}

// NewBuilder creates a new middleware builder
func NewBuilder() *Builder {
	return &Builder{
		registry: NewRegistry(),
	}
}

// Use adds a middleware
func (b *Builder) Use(name string, handler MiddlewareFunc, opts ...RegisterOption) *Builder {
	b.registry.Register(name, handler, opts...)
	return b
}

// UseIf adds a middleware with a condition
func (b *Builder) UseIf(name string, handler MiddlewareFunc, cond Condition, opts ...RegisterOption) *Builder {
	opts = append(opts, WithCondition(cond))
	b.registry.Register(name, handler, opts...)
	return b
}

// Build returns the registry
func (b *Builder) Build() *Registry {
	return b.registry
}

// Apply applies to router
func (b *Builder) Apply(router *gin.Engine) {
	b.registry.Apply(router)
}

// Global registry
var globalRegistry = NewRegistry()

// Register registers to global registry
func Register(name string, handler MiddlewareFunc, opts ...RegisterOption) {
	globalRegistry.Register(name, handler, opts...)
}

// Build builds from global registry
func Build() []MiddlewareFunc {
	return globalRegistry.Build()
}

// Apply applies global registry to router
func Apply(router *gin.Engine) {
	globalRegistry.Apply(router)
}

// GlobalRegistry returns the global registry
func GlobalRegistry() *Registry {
	return globalRegistry
}
