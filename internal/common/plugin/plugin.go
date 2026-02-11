// Package plugin provides a plugin registry for extensible components.
// Plugins can be registered at startup and discovered at runtime,
// enabling a modular "Lego block" architecture.
package plugin

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// PluginType identifies the category of plugin
type PluginType string

const (
	PluginTypeMFA          PluginType = "mfa"
	PluginTypeSMS          PluginType = "sms"
	PluginTypeEmail        PluginType = "email"
	PluginTypeDirectory    PluginType = "directory"
	PluginTypeStorage      PluginType = "storage"
	PluginTypeAudit        PluginType = "audit"
	PluginTypeNotification PluginType = "notification"
	PluginTypeAuth         PluginType = "auth"
	PluginTypePolicy       PluginType = "policy"
)

// HealthStatus represents the health of a plugin
type HealthStatus struct {
	Healthy   bool      `json:"healthy"`
	Message   string    `json:"message,omitempty"`
	LastCheck time.Time `json:"last_check"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// Plugin is the base interface all plugins must implement
type Plugin interface {
	// Name returns the unique identifier for this plugin
	Name() string

	// Version returns the plugin version
	Version() string

	// Type returns the plugin category
	Type() PluginType

	// Init initializes the plugin with configuration
	Init(ctx context.Context, config map[string]interface{}) error

	// Start starts the plugin (called after Init)
	Start(ctx context.Context) error

	// Stop gracefully stops the plugin
	Stop(ctx context.Context) error

	// Health returns the current health status
	Health() HealthStatus
}

// PluginInfo contains metadata about a registered plugin
type PluginInfo struct {
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Type        PluginType             `json:"type"`
	Description string                 `json:"description,omitempty"`
	Author      string                 `json:"author,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Status      string                 `json:"status"` // registered, initialized, running, stopped, error
	Health      HealthStatus           `json:"health"`
}

// PluginFactory creates a new plugin instance
type PluginFactory func() Plugin

// Lifecycle hooks for plugins
type LifecycleHook func(ctx context.Context, plugin Plugin) error

// Registry manages plugin registration and lifecycle
type Registry struct {
	mu        sync.RWMutex
	plugins   map[string]Plugin
	factories map[string]PluginFactory
	info      map[string]*PluginInfo

	// Lifecycle hooks
	onInit  []LifecycleHook
	onStart []LifecycleHook
	onStop  []LifecycleHook
}

// NewRegistry creates a new plugin registry
func NewRegistry() *Registry {
	return &Registry{
		plugins:   make(map[string]Plugin),
		factories: make(map[string]PluginFactory),
		info:      make(map[string]*PluginInfo),
		onInit:    make([]LifecycleHook, 0),
		onStart:   make([]LifecycleHook, 0),
		onStop:    make([]LifecycleHook, 0),
	}
}

// RegisterFactory registers a plugin factory for lazy instantiation
func (r *Registry) RegisterFactory(name string, factory PluginFactory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.factories[name]; exists {
		return fmt.Errorf("plugin factory %q already registered", name)
	}

	r.factories[name] = factory
	return nil
}

// Register registers a plugin instance
func (r *Registry) Register(plugin Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := plugin.Name()
	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("plugin %q already registered", name)
	}

	r.plugins[name] = plugin
	r.info[name] = &PluginInfo{
		Name:    name,
		Version: plugin.Version(),
		Type:    plugin.Type(),
		Status:  "registered",
	}

	return nil
}

// Get retrieves a plugin by name
func (r *Registry) Get(name string) (Plugin, error) {
	r.mu.RLock()
	plugin, exists := r.plugins[name]
	r.mu.RUnlock()

	if exists {
		return plugin, nil
	}

	// Try to create from factory
	r.mu.Lock()
	defer r.mu.Unlock()

	factory, hasFactory := r.factories[name]
	if !hasFactory {
		return nil, fmt.Errorf("plugin %q not found", name)
	}

	plugin = factory()
	r.plugins[name] = plugin
	r.info[name] = &PluginInfo{
		Name:    name,
		Version: plugin.Version(),
		Type:    plugin.Type(),
		Status:  "registered",
	}

	return plugin, nil
}

// MustGet retrieves a plugin or panics if not found
func (r *Registry) MustGet(name string) Plugin {
	plugin, err := r.Get(name)
	if err != nil {
		panic(err)
	}
	return plugin
}

// GetByType returns all plugins of a specific type
func (r *Registry) GetByType(pluginType PluginType) []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Plugin
	for _, plugin := range r.plugins {
		if plugin.Type() == pluginType {
			result = append(result, plugin)
		}
	}
	return result
}

// List returns info about all registered plugins
func (r *Registry) List() []PluginInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]PluginInfo, 0, len(r.info))
	for _, info := range r.info {
		// Update health status
		if plugin, ok := r.plugins[info.Name]; ok {
			info.Health = plugin.Health()
		}
		result = append(result, *info)
	}
	return result
}

// Init initializes a plugin with configuration
func (r *Registry) Init(ctx context.Context, name string, config map[string]interface{}) error {
	plugin, err := r.Get(name)
	if err != nil {
		return err
	}

	// Run pre-init hooks
	for _, hook := range r.onInit {
		if err := hook(ctx, plugin); err != nil {
			return fmt.Errorf("init hook failed: %w", err)
		}
	}

	if err := plugin.Init(ctx, config); err != nil {
		r.updateStatus(name, "error")
		return fmt.Errorf("failed to init plugin %q: %w", name, err)
	}

	r.updateStatus(name, "initialized")
	r.updateConfig(name, config)
	return nil
}

// Start starts a plugin
func (r *Registry) Start(ctx context.Context, name string) error {
	plugin, err := r.Get(name)
	if err != nil {
		return err
	}

	// Run pre-start hooks
	for _, hook := range r.onStart {
		if err := hook(ctx, plugin); err != nil {
			return fmt.Errorf("start hook failed: %w", err)
		}
	}

	if err := plugin.Start(ctx); err != nil {
		r.updateStatus(name, "error")
		return fmt.Errorf("failed to start plugin %q: %w", name, err)
	}

	r.updateStatus(name, "running")
	return nil
}

// Stop stops a plugin
func (r *Registry) Stop(ctx context.Context, name string) error {
	plugin, err := r.Get(name)
	if err != nil {
		return err
	}

	// Run pre-stop hooks
	for _, hook := range r.onStop {
		if err := hook(ctx, plugin); err != nil {
			return fmt.Errorf("stop hook failed: %w", err)
		}
	}

	if err := plugin.Stop(ctx); err != nil {
		return fmt.Errorf("failed to stop plugin %q: %w", name, err)
	}

	r.updateStatus(name, "stopped")
	return nil
}

// InitAll initializes all registered plugins
func (r *Registry) InitAll(ctx context.Context, configs map[string]map[string]interface{}) error {
	r.mu.RLock()
	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	r.mu.RUnlock()

	for _, name := range names {
		config := configs[name]
		if config == nil {
			config = make(map[string]interface{})
		}
		if err := r.Init(ctx, name, config); err != nil {
			return err
		}
	}
	return nil
}

// StartAll starts all initialized plugins
func (r *Registry) StartAll(ctx context.Context) error {
	r.mu.RLock()
	names := make([]string, 0)
	for name, info := range r.info {
		if info.Status == "initialized" {
			names = append(names, name)
		}
	}
	r.mu.RUnlock()

	for _, name := range names {
		if err := r.Start(ctx, name); err != nil {
			return err
		}
	}
	return nil
}

// StopAll stops all running plugins
func (r *Registry) StopAll(ctx context.Context) error {
	r.mu.RLock()
	names := make([]string, 0)
	for name, info := range r.info {
		if info.Status == "running" {
			names = append(names, name)
		}
	}
	r.mu.RUnlock()

	var lastErr error
	for _, name := range names {
		if err := r.Stop(ctx, name); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// OnInit adds a lifecycle hook called before plugin initialization
func (r *Registry) OnInit(hook LifecycleHook) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onInit = append(r.onInit, hook)
}

// OnStart adds a lifecycle hook called before plugin start
func (r *Registry) OnStart(hook LifecycleHook) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onStart = append(r.onStart, hook)
}

// OnStop adds a lifecycle hook called before plugin stop
func (r *Registry) OnStop(hook LifecycleHook) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onStop = append(r.onStop, hook)
}

// Helper methods

func (r *Registry) updateStatus(name, status string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if info, ok := r.info[name]; ok {
		info.Status = status
	}
}

func (r *Registry) updateConfig(name string, config map[string]interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if info, ok := r.info[name]; ok {
		info.Config = config
	}
}

// Global registry instance
var globalRegistry = NewRegistry()

// Global functions for convenience

// Register registers a plugin to the global registry
func Register(plugin Plugin) error {
	return globalRegistry.Register(plugin)
}

// Get retrieves a plugin from the global registry
func Get(name string) (Plugin, error) {
	return globalRegistry.Get(name)
}

// MustGet retrieves a plugin or panics
func MustGet(name string) Plugin {
	return globalRegistry.MustGet(name)
}

// GetByType returns plugins by type from the global registry
func GetByType(pluginType PluginType) []Plugin {
	return globalRegistry.GetByType(pluginType)
}

// List returns all plugins from the global registry
func List() []PluginInfo {
	return globalRegistry.List()
}

// Global returns the global registry instance
func Global() *Registry {
	return globalRegistry
}
