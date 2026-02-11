// Package container provides a dependency injection container for service management.
// Services are registered with factories and resolved lazily, enabling
// flexible composition of application components.
package container

import (
	"context"
	"fmt"
	"reflect"
	"sync"
)

// ServiceFactory creates a service instance
type ServiceFactory func(c Container) (interface{}, error)

// ServiceLifetime defines when a service instance is created
type ServiceLifetime int

const (
	// Singleton - one instance for the lifetime of the container
	Singleton ServiceLifetime = iota
	// Transient - new instance every time
	Transient
	// Scoped - one instance per scope (e.g., per request)
	Scoped
)

// ServiceDescriptor describes a registered service
type ServiceDescriptor struct {
	Name     string
	Type     reflect.Type
	Factory  ServiceFactory
	Lifetime ServiceLifetime
	Instance interface{}
	Tags     []string
}

// Container manages service registration and resolution
type Container interface {
	// Register registers a service factory
	Register(name string, factory ServiceFactory, opts ...RegisterOption) error

	// RegisterInstance registers an existing instance
	RegisterInstance(name string, instance interface{}, opts ...RegisterOption) error

	// Resolve resolves a service by name
	Resolve(name string) (interface{}, error)

	// MustResolve resolves a service or panics
	MustResolve(name string) interface{}

	// ResolveByType resolves services by type
	ResolveByType(serviceType reflect.Type) ([]interface{}, error)

	// ResolveByTag resolves services by tag
	ResolveByTag(tag string) ([]interface{}, error)

	// Has checks if a service is registered
	Has(name string) bool

	// CreateScope creates a new scoped container
	CreateScope() Container

	// Close closes the container and all services
	Close() error
}

// RegisterOption configures service registration
type RegisterOption func(*ServiceDescriptor)

// WithLifetime sets the service lifetime
func WithLifetime(lifetime ServiceLifetime) RegisterOption {
	return func(d *ServiceDescriptor) {
		d.Lifetime = lifetime
	}
}

// WithTags adds tags to the service
func WithTags(tags ...string) RegisterOption {
	return func(d *ServiceDescriptor) {
		d.Tags = append(d.Tags, tags...)
	}
}

// SimpleContainer is a basic DI container implementation
type SimpleContainer struct {
	mu          sync.RWMutex
	services    map[string]*ServiceDescriptor
	parent      *SimpleContainer
	scopedCache map[string]interface{}
	closed      bool
}

// NewContainer creates a new container
func NewContainer() *SimpleContainer {
	return &SimpleContainer{
		services:    make(map[string]*ServiceDescriptor),
		scopedCache: make(map[string]interface{}),
	}
}

// Register registers a service factory
func (c *SimpleContainer) Register(name string, factory ServiceFactory, opts ...RegisterOption) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.services[name]; exists {
		return fmt.Errorf("service %q already registered", name)
	}

	desc := &ServiceDescriptor{
		Name:     name,
		Factory:  factory,
		Lifetime: Singleton, // Default
		Tags:     make([]string, 0),
	}

	for _, opt := range opts {
		opt(desc)
	}

	c.services[name] = desc
	return nil
}

// RegisterInstance registers an existing instance
func (c *SimpleContainer) RegisterInstance(name string, instance interface{}, opts ...RegisterOption) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.services[name]; exists {
		return fmt.Errorf("service %q already registered", name)
	}

	desc := &ServiceDescriptor{
		Name:     name,
		Type:     reflect.TypeOf(instance),
		Instance: instance,
		Lifetime: Singleton,
		Tags:     make([]string, 0),
	}

	for _, opt := range opts {
		opt(desc)
	}

	c.services[name] = desc
	return nil
}

// Resolve resolves a service by name
func (c *SimpleContainer) Resolve(name string) (interface{}, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, fmt.Errorf("container is closed")
	}

	desc, exists := c.services[name]
	c.mu.RUnlock()

	// Check parent if not found
	if !exists && c.parent != nil {
		return c.parent.Resolve(name)
	}

	if !exists {
		return nil, fmt.Errorf("service %q not found", name)
	}

	// Return existing instance for singletons
	if desc.Lifetime == Singleton && desc.Instance != nil {
		return desc.Instance, nil
	}

	// Check scoped cache
	if desc.Lifetime == Scoped {
		c.mu.RLock()
		if instance, ok := c.scopedCache[name]; ok {
			c.mu.RUnlock()
			return instance, nil
		}
		c.mu.RUnlock()
	}

	// Create new instance
	if desc.Factory == nil {
		return nil, fmt.Errorf("service %q has no factory", name)
	}

	instance, err := desc.Factory(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create service %q: %w", name, err)
	}

	// Cache based on lifetime
	c.mu.Lock()
	defer c.mu.Unlock()

	switch desc.Lifetime {
	case Singleton:
		desc.Instance = instance
		desc.Type = reflect.TypeOf(instance)
	case Scoped:
		c.scopedCache[name] = instance
	}

	return instance, nil
}

// MustResolve resolves a service or panics
func (c *SimpleContainer) MustResolve(name string) interface{} {
	instance, err := c.Resolve(name)
	if err != nil {
		panic(err)
	}
	return instance
}

// ResolveByType resolves all services matching a type
func (c *SimpleContainer) ResolveByType(serviceType reflect.Type) ([]interface{}, error) {
	c.mu.RLock()
	names := make([]string, 0)
	for name, desc := range c.services {
		if desc.Type != nil && desc.Type.AssignableTo(serviceType) {
			names = append(names, name)
		}
	}
	c.mu.RUnlock()

	results := make([]interface{}, 0, len(names))
	for _, name := range names {
		instance, err := c.Resolve(name)
		if err != nil {
			return nil, err
		}
		results = append(results, instance)
	}

	return results, nil
}

// ResolveByTag resolves all services with a specific tag
func (c *SimpleContainer) ResolveByTag(tag string) ([]interface{}, error) {
	c.mu.RLock()
	names := make([]string, 0)
	for name, desc := range c.services {
		for _, t := range desc.Tags {
			if t == tag {
				names = append(names, name)
				break
			}
		}
	}
	c.mu.RUnlock()

	results := make([]interface{}, 0, len(names))
	for _, name := range names {
		instance, err := c.Resolve(name)
		if err != nil {
			return nil, err
		}
		results = append(results, instance)
	}

	return results, nil
}

// Has checks if a service is registered
func (c *SimpleContainer) Has(name string) bool {
	c.mu.RLock()
	_, exists := c.services[name]
	c.mu.RUnlock()

	if !exists && c.parent != nil {
		return c.parent.Has(name)
	}

	return exists
}

// CreateScope creates a new scoped container
func (c *SimpleContainer) CreateScope() Container {
	return &SimpleContainer{
		services:    c.services, // Share service descriptors
		parent:      c,
		scopedCache: make(map[string]interface{}),
	}
}

// Close closes the container and calls Close on all closable services
func (c *SimpleContainer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true

	// Close all singleton instances that implement io.Closer
	for _, desc := range c.services {
		if desc.Instance != nil {
			if closer, ok := desc.Instance.(interface{ Close() error }); ok {
				closer.Close()
			}
		}
	}

	// Close scoped instances
	for _, instance := range c.scopedCache {
		if closer, ok := instance.(interface{ Close() error }); ok {
			closer.Close()
		}
	}

	return nil
}

// Builder provides a fluent API for container configuration
type Builder struct {
	container *SimpleContainer
	errors    []error
}

// NewBuilder creates a new container builder
func NewBuilder() *Builder {
	return &Builder{
		container: NewContainer(),
		errors:    make([]error, 0),
	}
}

// Register registers a service
func (b *Builder) Register(name string, factory ServiceFactory, opts ...RegisterOption) *Builder {
	if err := b.container.Register(name, factory, opts...); err != nil {
		b.errors = append(b.errors, err)
	}
	return b
}

// RegisterInstance registers an instance
func (b *Builder) RegisterInstance(name string, instance interface{}, opts ...RegisterOption) *Builder {
	if err := b.container.RegisterInstance(name, instance, opts...); err != nil {
		b.errors = append(b.errors, err)
	}
	return b
}

// Build builds the container
func (b *Builder) Build() (*SimpleContainer, error) {
	if len(b.errors) > 0 {
		return nil, fmt.Errorf("container build failed: %v", b.errors)
	}
	return b.container, nil
}

// MustBuild builds the container or panics
func (b *Builder) MustBuild() *SimpleContainer {
	container, err := b.Build()
	if err != nil {
		panic(err)
	}
	return container
}

// Closable is an interface for services that need cleanup
type Closable interface {
	Close() error
}

// Initializable is an interface for services that need initialization
type Initializable interface {
	Init(ctx context.Context) error
}

// InitAll initializes all services that implement Initializable
func InitAll(ctx context.Context, c Container, names ...string) error {
	for _, name := range names {
		instance, err := c.Resolve(name)
		if err != nil {
			return err
		}
		if init, ok := instance.(Initializable); ok {
			if err := init.Init(ctx); err != nil {
				return fmt.Errorf("failed to initialize %s: %w", name, err)
			}
		}
	}
	return nil
}

// Global container instance
var globalContainer Container = NewContainer()

// SetGlobal sets the global container
func SetGlobal(c Container) {
	globalContainer = c
}

// Global returns the global container
func Global() Container {
	return globalContainer
}

// Register registers to the global container
func Register(name string, factory ServiceFactory, opts ...RegisterOption) error {
	return globalContainer.(*SimpleContainer).Register(name, factory, opts...)
}

// Resolve resolves from the global container
func Resolve(name string) (interface{}, error) {
	return globalContainer.Resolve(name)
}

// MustResolve resolves from the global container or panics
func MustResolve(name string) interface{} {
	return globalContainer.MustResolve(name)
}
