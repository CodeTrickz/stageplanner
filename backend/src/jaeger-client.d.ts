// Type declarations for jaeger-client
declare module 'jaeger-client' {
  import { Tracer } from 'opentracing'

  interface JaegerConfig {
    serviceName: string
    sampler?: {
      type: string
      param: number
    }
    reporter?: {
      agentHost?: string
      agentPort?: number
      logSpans?: boolean
    }
  }

  interface JaegerLogger {
    info: (msg: string) => void
    error: (msg: string) => void
  }

  function initTracer(
    config: JaegerConfig,
    options?: { logger?: JaegerLogger }
  ): Tracer

  export = initTracer
}
