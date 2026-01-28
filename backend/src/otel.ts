import { diag, DiagConsoleLogger, DiagLogLevel } from '@opentelemetry/api'
import { NodeSDK } from '@opentelemetry/sdk-node'
import { JaegerExporter } from '@opentelemetry/exporter-jaeger'
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node'

let started = false

export async function initOtel() {
  if (started) return
  started = true

  const enabled = String(process.env.OTEL_ENABLED ?? 'true').toLowerCase() !== 'false'
  if (!enabled) return

  const debug = String(process.env.OTEL_DEBUG ?? '').toLowerCase() === 'true'
  if (debug) {
    diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.DEBUG)
  }

  const exporter = new JaegerExporter({
    endpoint: process.env.OTEL_EXPORTER_JAEGER_ENDPOINT, // e.g. http://jaeger:14268/api/traces
    host: process.env.JAEGER_AGENT_HOST || process.env.OTEL_EXPORTER_JAEGER_AGENT_HOST, // UDP agent
    port: process.env.JAEGER_AGENT_PORT
      ? Number.parseInt(process.env.JAEGER_AGENT_PORT, 10)
      : process.env.OTEL_EXPORTER_JAEGER_AGENT_PORT
        ? Number.parseInt(process.env.OTEL_EXPORTER_JAEGER_AGENT_PORT, 10)
        : undefined,
  })

  const sdk = new NodeSDK({
    serviceName: process.env.OTEL_SERVICE_NAME || process.env.JAEGER_SERVICE_NAME || 'stageplanner-backend',
    traceExporter: exporter,
    instrumentations: [
      getNodeAutoInstrumentations({
        // keep noise low but still get HTTP/Express spans
        '@opentelemetry/instrumentation-fs': { enabled: false },
      }),
    ],
  })

  await sdk.start()

  process.on('SIGTERM', () => {
    void sdk.shutdown()
  })
  process.on('SIGINT', () => {
    void sdk.shutdown()
  })
}

