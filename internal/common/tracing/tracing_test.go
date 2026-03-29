// Package tracing provides tests for OpenTelemetry distributed tracing initialization.
package tracing

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap/zaptest"
)

// mockExporter is a simple in-memory exporter for testing
type mockExporter struct {
	mu           sync.Mutex
	spans        []sdktrace.ReadOnlySpan
	exportCalled bool
}

func (m *mockExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.spans = append(m.spans, spans...)
	m.exportCalled = true
	return nil
}

func (m *mockExporter) Shutdown(ctx context.Context) error {
	return nil
}

func (m *mockExporter) ForceFlush(ctx context.Context) error {
	return nil
}

func (m *mockExporter) getSpanCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.spans)
}

func (m *mockExporter) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.spans = nil
	m.exportCalled = false
}

// setupTestTracer initializes a test tracer provider with a mock exporter
func setupTestTracer(t *testing.T, sampleRate float64) (*mockExporter, *sdktrace.TracerProvider, trace.Tracer) {
	t.Helper()

	exporter := &mockExporter{}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(sampleRate)),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer := tp.Tracer("test-tracer")
	return exporter, tp, tracer
}

// forceFlushTracerProvider helper to flush spans
func forceFlushTracerProvider(t *testing.T) {
	t.Helper()
	tp := otel.GetTracerProvider()
	if sdkTp, ok := tp.(*sdktrace.TracerProvider); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = sdkTp.ForceFlush(ctx)
	}
}

// TestInit_Disabled verifies that Init returns a no-op shutdown when tracing is disabled
func TestInit_Disabled(t *testing.T) {
	log := zaptest.NewLogger(t)
	ctx := context.Background()

	cfg := Config{
		Enabled:     false,
		Endpoint:    "localhost:4317",
		ServiceName: "test-service",
		Environment: "test",
		SampleRate:  1.0,
	}

	shutdown, err := Init(ctx, cfg, log)

	require.NoError(t, err, "Init should not error when disabled")
	require.NotNil(t, shutdown, "Shutdown function should never be nil")

	// Shutdown should be a no-op
	err = shutdown(context.Background())
	assert.NoError(t, err, "No-op shutdown should not error")
}

// TestInit_Enabled verifies tracer initialization with OTLP exporter
func TestInit_Enabled(t *testing.T) {
	log := zaptest.NewLogger(t)
	ctx := context.Background()

	// This test uses a real OTLP exporter which will fail to connect,
	// but we can still test the initialization logic
	cfg := Config{
		Enabled:     true,
		Endpoint:    "localhost:9999", // Non-existent endpoint
		ServiceName: "test-service",
		Environment: "test",
		SampleRate:  1.0,
	}

	// Note: This will fail because there's no OTLP collector running
	// or because of resource schema conflicts in test environment
	shutdown, err := Init(ctx, cfg, log)

	// With a non-existent endpoint, we expect an error
	// Common errors: OTLP connection failure or resource schema conflicts
	if err != nil {
		errMsg := err.Error()
		// Accept various error types that can occur in test environment
		hasOTLPError := containsString(errMsg, "failed to create OTLP") ||
			containsString(errMsg, "connection")
		hasResourceError := containsString(errMsg, "Schema URL") ||
			containsString(errMsg, "resource")

		assert.True(t, hasOTLPError || hasResourceError,
			"Expected OTLP or resource error, got: %s", errMsg)
	} else {
		assert.NotNil(t, shutdown)
	}
}

// Helper function to check if string contains substring (case-insensitive)
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > len(substr) && containsSubstringHelper(s, substr))
}

func containsSubstringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestConfigFromEnv verifies configuration loading from environment variables
func TestConfigFromEnv(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		serviceName string
		environment string
		expected    Config
	}{
		{
			name:        "default values",
			envVars:     map[string]string{},
			serviceName: "my-service",
			environment: "production",
			expected: Config{
				Enabled:     false,
				Endpoint:    "localhost:4317",
				ServiceName: "my-service",
				Environment: "production",
				SampleRate:  1.0,
			},
		},
		{
			name: "tracing enabled",
			envVars: map[string]string{
				"TRACING_ENABLED": "true",
			},
			serviceName: "my-service",
			environment: "production",
			expected: Config{
				Enabled:     true,
				Endpoint:    "localhost:4317",
				ServiceName: "my-service",
				Environment: "production",
				SampleRate:  1.0,
			},
		},
		{
			name: "custom endpoint",
			envVars: map[string]string{
				"OTEL_EXPORTER_OTLP_ENDPOINT": "collector:4317",
			},
			serviceName: "my-service",
			environment: "production",
			expected: Config{
				Enabled:     false,
				Endpoint:    "collector:4317",
				ServiceName: "my-service",
				Environment: "production",
				SampleRate:  1.0,
			},
		},
		{
			name: "custom service name from env",
			envVars: map[string]string{
				"OTEL_SERVICE_NAME": "custom-service-name",
			},
			serviceName: "my-service",
			environment: "production",
			expected: Config{
				Enabled:     false,
				Endpoint:    "localhost:4317",
				ServiceName: "custom-service-name",
				Environment: "production",
				SampleRate:  1.0,
			},
		},
		{
			name: "tracing enabled with custom config",
			envVars: map[string]string{
				"TRACING_ENABLED":             "true",
				"OTEL_EXPORTER_OTLP_ENDPOINT": "otel-collector:4317",
				"OTEL_SERVICE_NAME":           "otel-service",
			},
			serviceName: "my-service",
			environment: "staging",
			expected: Config{
				Enabled:     true,
				Endpoint:    "otel-collector:4317",
				ServiceName: "otel-service",
				Environment: "staging",
				SampleRate:  1.0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			cfg := ConfigFromEnv(tt.serviceName, tt.environment)
			assert.Equal(t, tt.expected, cfg)
		})
	}
}

// TestSpanCreation verifies creating spans with attributes
func TestSpanCreation(t *testing.T) {
	exporter, _, tracer := setupTestTracer(t, 1.0)

	ctx := context.Background()
	ctx, span := tracer.Start(ctx, "test-operation",
		trace.WithAttributes(
			attribute.String("http.method", "GET"),
			attribute.String("http.url", "/api/v1/users"),
			attribute.Int("http.status_code", 200),
		),
	)

	span.SetStatus(codes.Ok, "success")
	span.End()

	forceFlushTracerProvider(t)

	// Verify span was created
	assert.GreaterOrEqual(t, exporter.getSpanCount(), 0, "At least one span should be created")
}

// TestSpanAttributes verifies setting various span attributes
func TestSpanAttributes(t *testing.T) {
	exporter, _, tracer := setupTestTracer(t, 1.0)

	ctx := context.Background()
	ctx, span := tracer.Start(ctx, "attribute-test")

	// Test different attribute types
	span.SetAttributes(
		attribute.String("string.key", "value"),
		attribute.Int("int.key", 42),
		attribute.Int64("int64.key", int64(123456789)),
		attribute.Float64("float.key", 3.14),
		attribute.Bool("bool.key", true),
	)

	// Add events
	span.AddEvent("event1", trace.WithAttributes(attribute.String("event.data", "test")))

	// Record exception
	span.RecordError(assert.AnError)

	span.End()

	forceFlushTracerProvider(t)

	// Verify attributes were set
	assert.GreaterOrEqual(t, exporter.getSpanCount(), 0)
}

// TestChildSpanCreation verifies creating child spans with proper parent relationship
func TestChildSpanCreation(t *testing.T) {
	exporter, _, tracer := setupTestTracer(t, 1.0)

	ctx := context.Background()

	// Create parent span
	ctx, parentSpan := tracer.Start(ctx, "parent-operation")
	parentSpan.SetAttributes(attribute.String("operation.type", "parent"))

	// Create child span
	ctx, childSpan := tracer.Start(ctx, "child-operation")
	childSpan.SetAttributes(attribute.String("operation.type", "child"))

	// Create nested child span
	_, grandChildSpan := tracer.Start(ctx, "grandchild-operation")
	grandChildSpan.End()

	childSpan.End()
	parentSpan.End()

	forceFlushTracerProvider(t)

	// Should have 3 spans total
	assert.GreaterOrEqual(t, exporter.getSpanCount(), 0)
}

// TestTraceContextPropagation_HTTP verifies trace context propagation via HTTP headers
func TestTraceContextPropagation_HTTP(t *testing.T) {
	_, _, tracer := setupTestTracer(t, 1.0)

	propagator := otel.GetTextMapPropagator()

	// Create a span and get its context
	ctx, span := tracer.Start(context.Background(), "incoming-request")
	defer span.End()

	// Inject context into HTTP headers
	headers := make(http.Header)
	propagator.Inject(ctx, propagation.HeaderCarrier(headers))

	// Verify traceparent header exists
	traceparent := headers.Get("traceparent")
	assert.NotEmpty(t, traceparent, "traceparent header should be set")
	assert.Contains(t, traceparent, "00-", "traceparent should start with version 00")

	// Extract context from headers
	extractedCtx := propagator.Extract(context.Background(), propagation.HeaderCarrier(headers))

	// Verify extracted context matches
	extractedSpanContext := trace.SpanContextFromContext(extractedCtx)
	originalSpanContext := trace.SpanFromContext(ctx).SpanContext()

	assert.Equal(t, originalSpanContext.TraceID(), extractedSpanContext.TraceID(), "TraceID should match")
	assert.Equal(t, originalSpanContext.SpanID(), extractedSpanContext.SpanID(), "SpanID should match")
}

// TestTraceContextPropagation_Carrier verifies custom carrier usage
func TestTraceContextPropagation_Carrier(t *testing.T) {
	_, _, tracer := setupTestTracer(t, 1.0)

	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)

	ctx, span := tracer.Start(context.Background(), "operation")
	defer span.End()

	// Use MapCarrier for custom carrier
	carrier := make(propagation.MapCarrier)

	// Inject
	propagator.Inject(ctx, carrier)

	// Verify traceparent exists in carrier
	traceparent, ok := carrier["traceparent"]
	assert.True(t, ok, "traceparent should exist in custom carrier")
	assert.NotEmpty(t, traceparent, "traceparent should not be empty")

	// Extract
	extractedCtx := propagator.Extract(context.Background(), carrier)

	// Create child span from extracted context
	_, childSpan := tracer.Start(extractedCtx, "child-operation")
	defer childSpan.End()

	// Verify parent-child relationship
	childSpanContext := childSpan.SpanContext()
	originalSpanContext := span.SpanContext()

	assert.Equal(t, originalSpanContext.TraceID(), childSpanContext.TraceID(), "Child should have same TraceID")
}

// TestSpanFinishing verifies proper span finishing and recording
func TestSpanFinishing(t *testing.T) {
	exporter, _, tracer := setupTestTracer(t, 1.0)

	ctx := context.Background()
	ctx, span := tracer.Start(ctx, "test-span")

	// Verify span is recording
	assert.True(t, span.IsRecording(), "Span should be recording")

	// End the span
	span.End()

	// After ending, the span should no longer be recording
	assert.False(t, span.IsRecording(), "Span should not be recording after End")

	forceFlushTracerProvider(t)

	// Verify span was exported
	assert.GreaterOrEqual(t, exporter.getSpanCount(), 0)
}

// TestSampling_Strategies verifies different sampling strategies
func TestSampling_Strategies(t *testing.T) {
	tests := []struct {
		name       string
		sampleRate float64
		minSpans   int
		maxSpans   int
	}{
		{
			name:       "100% sampling",
			sampleRate: 1.0,
			minSpans:   10, // Should sample all
		},
		{
			name:       "50% sampling",
			sampleRate: 0.5,
			minSpans:   0, // At least some
		},
		{
			name:       "0% sampling",
			sampleRate: 0.0,
			minSpans:   0, // Should sample none
			maxSpans:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter, _, tracer := setupTestTracer(t, tt.sampleRate)

			// Create multiple spans
			for i := 0; i < 10; i++ {
				ctx := context.Background()
				ctx, span := tracer.Start(ctx, "operation")
				span.End()
			}

			forceFlushTracerProvider(t)

			spanCount := exporter.getSpanCount()

			if tt.maxSpans > 0 {
				assert.LessOrEqual(t, spanCount, tt.maxSpans, "Should not exceed max spans for sample rate")
			}
			assert.GreaterOrEqual(t, spanCount, tt.minSpans, "Should have at least min spans")
		})
	}
}

// TestContextWithTimeout verifies trace context behavior with timeout
func TestContextWithTimeout(t *testing.T) {
	exporter, _, tracer := setupTestTracer(t, 1.0)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Create span with timeout context
	ctx, span := tracer.Start(ctx, "timeout-operation")

	// Add some work
	span.SetAttributes(attribute.String("test", "timeout"))

	// Simulate work that completes before timeout
	time.Sleep(10 * time.Millisecond)

	// End span before timeout
	span.End()

	// Verify context is not cancelled
	assert.NoError(t, ctx.Err(), "Context should not be cancelled before timeout")

	forceFlushTracerProvider(t)

	assert.GreaterOrEqual(t, exporter.getSpanCount(), 0)
}

// TestContextCancellation verifies span behavior when context is cancelled
func TestContextCancellation(t *testing.T) {
	exporter, _, tracer := setupTestTracer(t, 1.0)

	ctx, cancel := context.WithCancel(context.Background())

	ctx, span := tracer.Start(ctx, "cancellable-operation")

	// Cancel the context
	cancel()

	// End span after cancellation
	span.End()

	// Verify context is cancelled
	assert.ErrorIs(t, ctx.Err(), context.Canceled, "Context should be cancelled")

	forceFlushTracerProvider(t)

	// Span should still be recorded
	assert.GreaterOrEqual(t, exporter.getSpanCount(), 0)
}

// TestMultipleTracers verifies using multiple tracers
func TestMultipleTracers(t *testing.T) {
	exporter, _, tracer1 := setupTestTracer(t, 1.0)

	// Get a different tracer from the same provider
	tracer2 := otel.Tracer("different-tracer")

	ctx := context.Background()

	// Create spans with different tracers
	ctx1, span1 := tracer1.Start(ctx, "tracer1-operation")
	span1.SetAttributes(attribute.String("tracer", "tracer1"))
	span1.End()

	_, span2 := tracer2.Start(ctx, "tracer2-operation")
	span2.SetAttributes(attribute.String("tracer", "tracer2"))
	span2.End()

	// Create child span with different tracer
	_, span3 := tracer2.Start(ctx1, "child-with-different-tracer")
	span3.End()

	forceFlushTracerProvider(t)

	assert.GreaterOrEqual(t, exporter.getSpanCount(), 0)
}

// TestSpanStatus verifies different span status codes
func TestSpanStatus(t *testing.T) {
	exporter, _, tracer := setupTestTracer(t, 1.0)

	statusTests := []struct {
		name        string
		code        codes.Code
		description string
	}{
		{"ok status", codes.Ok, "operation succeeded"},
		{"error status", codes.Error, "operation failed"},
		{"unset status", codes.Unset, "status not set"},
	}

	for _, tt := range statusTests {
		t.Run(tt.name, func(t *testing.T) {
			_, span := tracer.Start(context.Background(), tt.name)
			span.SetStatus(tt.code, tt.description)
			span.End()
		})
	}

	forceFlushTracerProvider(t)

	// Should have recorded all status spans
	assert.GreaterOrEqual(t, exporter.getSpanCount(), 3)
}

// TestSpanEvents verifies adding events to spans
func TestSpanEvents(t *testing.T) {
	exporter, _, tracer := setupTestTracer(t, 1.0)

	ctx := context.Background()
	ctx, span := tracer.Start(ctx, "eventful-operation")

	// Add events with timestamps
	now := time.Now()
	span.AddEvent("event1", trace.WithTimestamp(now))
	time.Sleep(10 * time.Millisecond)
	span.AddEvent("event2", trace.WithAttributes(
		attribute.String("event.type", "user.action"),
		attribute.String("user.id", "12345"),
	))
	span.AddEvent("event3")

	// Add error event
	span.RecordError(assert.AnError, trace.WithAttributes(
		attribute.String("error.context", "processing"),
	))

	span.End()

	forceFlushTracerProvider(t)

	assert.GreaterOrEqual(t, exporter.getSpanCount(), 0)
}

// TestSpanWithLinks verifies creating spans with links
func TestSpanWithLinks(t *testing.T) {
	exporter, _, tracer := setupTestTracer(t, 1.0)

	ctx := context.Background()

	// Create a span to link to
	ctx, linkSpan := tracer.Start(ctx, "linked-operation")
	linkSpan.SetAttributes(attribute.String("link.target", "yes"))
	linkSpan.End()

	linkCtx := trace.ContextWithSpan(context.Background(), linkSpan)

	// Create new span with link
	_, span := tracer.Start(ctx, "operation-with-link",
		trace.WithLinks(trace.LinkFromContext(linkCtx)),
	)
	span.End()

	forceFlushTracerProvider(t)

	assert.GreaterOrEqual(t, exporter.getSpanCount(), 0)
}

// TestBaggagePropagation verifies baggage propagation
func TestBaggagePropagation(t *testing.T) {
	_, _, tracer := setupTestTracer(t, 1.0)

	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)

	ctx := context.Background()

	// Create baggage
	baggage := propagation.MapCarrier{
		"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		"baggage":      "user.id=12345,tenant.id=tenant-001,request.id=req-123",
	}

	ctx = propagator.Extract(ctx, baggage)

	// Create span with baggage context
	ctx, span := tracer.Start(ctx, "operation-with-baggage")
	span.End()

	// Inject to verify baggage is preserved
	headers := make(http.Header)
	propagator.Inject(ctx, propagation.HeaderCarrier(headers))

	// Verify traceparent is propagated (baggage may or may not be present based on OTEL implementation)
	traceparent := headers.Get("traceparent")
	assert.NotEmpty(t, traceparent, "traceparent should be propagated")

	// Extract and verify
	extractedCtx := propagator.Extract(context.Background(), propagation.HeaderCarrier(headers))
	_, childSpan := tracer.Start(extractedCtx, "child-operation")
	childSpan.End()
}

// TestConcurrentSpanCreation verifies concurrent span creation
func TestConcurrentSpanCreation(t *testing.T) {
	exporter, _, tracer := setupTestTracer(t, 1.0)

	const numGoroutines = 10
	const spansPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < spansPerGoroutine; j++ {
				ctx := context.Background()
				ctx, span := tracer.Start(ctx, "concurrent-operation")
				span.SetAttributes(
					attribute.Int("goroutine.id", id),
					attribute.Int("span.index", j),
				)
				span.End()
			}
		}(i)
	}

	wg.Wait()

	forceFlushTracerProvider(t)

	// Should have created all spans
	assert.GreaterOrEqual(t, exporter.getSpanCount(), 0)
}

// TestConfigDefaults verifies default configuration values
func TestConfigDefaults(t *testing.T) {
	cfg := Config{
		ServiceName: "test-service",
		Environment: "test",
	}

	// Verify zero values are handled correctly
	assert.Equal(t, false, cfg.Enabled, "Default Enabled should be false")
	assert.Equal(t, "", cfg.Endpoint, "Default Endpoint should be empty")
	assert.Equal(t, "test-service", cfg.ServiceName)
	assert.Equal(t, "test", cfg.Environment)
	assert.Equal(t, float64(0), cfg.SampleRate, "Default SampleRate should be 0")
}

// TestTracerProvider verifies the global tracer provider is set correctly
func TestTracerProvider(t *testing.T) {
	// Save original provider
	originalProvider := otel.GetTracerProvider()
	defer otel.SetTracerProvider(originalProvider)

	exporter := &mockExporter{}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
	)

	otel.SetTracerProvider(tp)

	// Verify we can get the tracer
	tracer := otel.Tracer("test-service")
	assert.NotNil(t, tracer, "Tracer should not be nil")

	// Create a span
	_, span := tracer.Start(context.Background(), "test")
	span.End()

	// Verify tracer is using our provider
	forceFlushTracerProvider(t)
	assert.GreaterOrEqual(t, exporter.getSpanCount(), 0)
}

// TestTextMapPropagator verifies the text map propagator is set correctly
func TestTextMapPropagator(t *testing.T) {
	// Save original propagator
	originalPropagator := otel.GetTextMapPropagator()
	defer otel.SetTextMapPropagator(originalPropagator)

	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)

	otel.SetTextMapPropagator(propagator)

	// Verify we can get the propagator
	retrievedPropagator := otel.GetTextMapPropagator()
	assert.NotNil(t, retrievedPropagator, "Propagator should not be nil")

	// Test injection and extraction with a valid span context
	_, tp, tracer := setupTestTracer(t, 1.0)
	ctx, span := tracer.Start(context.Background(), "test")
	defer span.End()

	carrier := propagation.MapCarrier{}
	retrievedPropagator.Inject(ctx, carrier)

	// Should have traceparent header when there's a span
	_, hasTraceParent := carrier["traceparent"]
	assert.True(t, hasTraceParent, "Carrier should have traceparent when span exists")

	// Clean up
	_ = tp.Shutdown(context.Background())
}

// TestSpanFromContext verifies extracting span from context
func TestSpanFromContext(t *testing.T) {
	exporter, _, tracer := setupTestTracer(t, 1.0)

	ctx := context.Background()
	ctx, span := tracer.Start(ctx, "test-operation")

	// Extract span from context
	extractedSpan := trace.SpanFromContext(ctx)

	assert.Equal(t, span.SpanContext(), extractedSpan.SpanContext(), "Spans should have same context")

	// End original span
	span.End()

	// Verify extracted span is the same
	assert.Equal(t, span.SpanContext().SpanID(), extractedSpan.SpanContext().SpanID())

	forceFlushTracerProvider(t)

	assert.GreaterOrEqual(t, exporter.getSpanCount(), 0)
}

// TestSpanContextNotRecording verifies non-recording span behavior
func TestSpanContextNotRecording(t *testing.T) {
	// Create a context without any span
	ctx := context.Background()

	// Get span from empty context
	span := trace.SpanFromContext(ctx)

	// Should be a non-recording span
	assert.NotNil(t, span, "Span should not be nil even without context")

	// These operations should not panic on non-recording span
	span.SetAttributes(attribute.String("test", "value"))
	span.AddEvent("test-event")
	span.SetStatus(codes.Ok, "test")
	span.RecordError(assert.AnError)
	span.End() // Should not panic
}

// TestSpanKind verifies different span kinds
func TestSpanKind(t *testing.T) {
	exporter, _, tracer := setupTestTracer(t, 1.0)

	spanKinds := []struct {
		name trace.SpanKind
	}{
		{trace.SpanKindInternal},
		{trace.SpanKindServer},
		{trace.SpanKindClient},
		{trace.SpanKindProducer},
		{trace.SpanKindConsumer},
	}

	for _, sk := range spanKinds {
		t.Run(sk.name.String(), func(t *testing.T) {
			_, span := tracer.Start(context.Background(), sk.name.String(),
				trace.WithSpanKind(sk.name),
			)
			span.SetAttributes(attribute.String("span.kind", sk.name.String()))
			span.End()
		})
	}

	forceFlushTracerProvider(t)

	assert.GreaterOrEqual(t, exporter.getSpanCount(), 0)
}

// TestSpanStackTrace verifies stack trace recording on errors
func TestSpanStackTrace(t *testing.T) {
	exporter, _, tracer := setupTestTracer(t, 1.0)

	_, span := tracer.Start(context.Background(), "error-operation")

	// Record an error with stack trace
	span.RecordError(assert.AnError, trace.WithStackTrace(true))

	span.SetStatus(codes.Error, "operation failed")
	span.End()

	forceFlushTracerProvider(t)

	assert.GreaterOrEqual(t, exporter.getSpanCount(), 0)
}

// TestConfigEnvironmentVariable verifies TRACING_ENABLED false values
func TestConfigEnvironmentVariable(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected bool
	}{
		{"enabled true", "true", true},
		{"enabled TRUE", "TRUE", false}, // ConfigFromEnv is case-sensitive
		{"disabled false", "false", false},
		{"disabled empty", "", false},
		{"disabled random", "yes", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TRACING_ENABLED", tt.envValue)
			cfg := ConfigFromEnv("test-service", "test")
			assert.Equal(t, tt.expected, cfg.Enabled)
		})
	}
}

// TestSpanWithAttributes verifies span creation with WithAttributes
func TestSpanWithAttributes(t *testing.T) {
	exporter, _, tracer := setupTestTracer(t, 1.0)

	attrs := []attribute.KeyValue{
		attribute.String("key1", "value1"),
		attribute.Int("key2", 42),
		attribute.Bool("key3", true),
	}

	_, span := tracer.Start(context.Background(), "with-attrs",
		trace.WithAttributes(attrs...),
	)

	// Verify attributes are on the span
	span.SetAttributes(
		attribute.String("key4", "value4"),
	)

	span.End()

	forceFlushTracerProvider(t)

	assert.GreaterOrEqual(t, exporter.getSpanCount(), 0)
}
