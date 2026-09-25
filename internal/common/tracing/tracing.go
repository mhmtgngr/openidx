// Package tracing provides OpenTelemetry distributed tracing initialization for OpenIDX services.
package tracing

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.uber.org/zap"
)

// Config holds tracing configuration
type Config struct {
	Enabled     bool
	Endpoint    string // OTLP gRPC endpoint (e.g., "localhost:4317")
	ServiceName string
	Environment string
	SampleRate  float64 // 0.0 to 1.0; default 1.0
}

// ConfigFromEnv loads tracing config from environment variables
func ConfigFromEnv(serviceName, environment string) Config {
	enabled := os.Getenv("TRACING_ENABLED") == "true"
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "localhost:4317"
	}
	svcName := os.Getenv("OTEL_SERVICE_NAME")
	if svcName == "" {
		svcName = serviceName
	}
	return Config{
		Enabled:     enabled,
		Endpoint:    endpoint,
		ServiceName: svcName,
		Environment: environment,
		SampleRate:  1.0,
	}
}

// Init initializes the OpenTelemetry tracer provider with OTLP gRPC export.
// Returns a shutdown function that flushes pending spans. When tracing is
// disabled, returns a no-op shutdown function.
func Init(ctx context.Context, cfg Config, log *zap.Logger) (func(context.Context) error, error) {
	if !cfg.Enabled {
		log.Info("Tracing disabled")
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	res, err := newResource(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(cfg.SampleRate)),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	log.Info("Tracing initialized",
		zap.String("endpoint", cfg.Endpoint),
		zap.String("service", cfg.ServiceName))

	return tp.Shutdown, nil
}

// newResource describes the service to the tracing backend: the SDK's default
// resource (telemetry.sdk.*, host and process attributes) plus service.name and
// deployment.environment.
//
// The service attributes are schemaless on purpose. resource.Merge refuses two
// resources whose schema URLs differ, and resource.Default() carries the schema
// of whichever semconv version the SDK was built with, which moves on every SDK
// upgrade. Pinning this package's semconv schema made Init fail with
// "conflicting Schema URL" as soon as the SDK moved past it, and every service
// logged a warning and ran untraced. A schemaless resource merges with any
// schema, and the attribute keys are the same.
func newResource(cfg Config) (*resource.Resource, error) {
	return resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			semconv.ServiceName(cfg.ServiceName),
			semconv.DeploymentEnvironment(cfg.Environment),
		),
	)
}
