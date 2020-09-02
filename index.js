const express = require('express')
const http = require('http')
const morgan = require('morgan')
const rateLimit = require('express-rate-limit')
const Rollbar = require('rollbar')

const IS_PROD = process.env.NODE_ENV === 'production'

// Time (in ms) to cache the HTTP "Strict-Transport-Security" (HSTS)
// setting. This value is sent as the "max-age" attribute in the header.
const MAX_AGE_HSTS = IS_PROD
  ? 365 * 24 * 60 * 60 * 1000 // 1 year
  : 0

// Time (in ms) to cache static resources. This value is sent in the HTTP
// "Cache-Control" header.
const MAX_AGE_STATIC = IS_PROD
  ? 365 * 24 * 60 * 60 * 1000 // 1 year
  : 0

function createServer ({
  host,
  maxRequestsPerSecond = 5
}) {
  const app = express()
  const httpServer = http.createServer()
  httpServer.on('request', app)

  useExpressConfig()
  useSecurityHeaders()
  useLogger()
  useRateLimit()

  return { app, httpServer }

  function useExpressConfig () {
    app.set('trust proxy', true) // Trust the nginx reverse proxy
    app.set('json spaces', IS_PROD ? 0 : 2) // Pretty JSON (in dev)
    app.set('x-powered-by', false) // Prevent server fingerprinting
  }

  function useSecurityHeaders () {
    app.use((req, res, next) => {
      // Redirect to canonical origin, over https
      if (IS_PROD && req.method === 'GET' &&
          (req.protocol !== 'https' || req.hostname !== host)) {
        return res.redirect(301, `https://${host}${req.url}`)
      }

      // Use HTTP Strict Transport Security (HSTS), cached for 2 years,
      // including on subdomains, and allow browser preload.
      res.header(
        'Strict-Transport-Security',
        `max-age=${MAX_AGE_HSTS / 1000}; includeSubDomains; preload`
      )

      // Disable browser mime-type sniffing to reduce exposure to drive-by
      // download attacks when serving user uploaded content
      res.header('X-Content-Type-Options', 'nosniff')

      next()
    })
  }

  function useLogger () {
    // Log HTTP requests
    const logger = morgan(IS_PROD ? 'combined' : 'dev', { immediate: !IS_PROD })
    app.use(logger)
  }

  function useRateLimit () {
    if (!IS_PROD) return

    // Rate limit HTTP requests
    morgan.format(
      'rate-limit',
      'Blocked for too many requests - :remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent"'
    )
    const rateLimitLogger = morgan('rate-limit', { immediate: !IS_PROD })

    const windowMs = 60 * 1000
    const max = 60 * maxRequestsPerSecond

    const rateLimiter = rateLimit({
      windowMs,
      max,
      headers: false,
      handler: (req, res, next) => {
        rateLimitLogger(req, res, () => {})
        res.status(503).send('Blocked for too many requests')
      }
    })
    app.use(rateLimiter)
  }
}

function createRollbar ({ accessToken }) {
  if (!IS_PROD) return

  globalThis.rollbar = new Rollbar({
    accessToken: accessToken,
    captureUncaught: true,
    captureUnhandledRejections: true,
    checkIgnore: (isUncaught, args) => {
      const err = args[0]

      // Never ignore uncaught errors
      if (isUncaught) return false

      // Ignore 'Bad Request' errors
      if (err.status === 400) return true

      // Ignore 'Forbidden' errors
      if (err.status === 403) return true

      // Ignore 'Not Found' errors
      if (err.status === 404) return true

      // Ignore 'Precondition Failed' errors
      if (err.status === 412) return true

      // Ignore 'Range Not Satisfiable' errors
      if (err.status === 416) return true

      return false
    }
  })
}

function getRollbarHandler () {
  if (globalThis.rollbar) return globalThis.rollbar.errorHandler()
  else return (req, res, next) => next()
}

function runMiddleware (req, res, fn) {
  return new Promise((resolve, reject) => {
    fn(req, res, (result) => {
      if (result instanceof Error) {
        return reject(result)
      }

      return resolve(result)
    })
  })
}

// Returns an express.static middleware, configured correctly
function serveStatic (path, opts) {
  return express.static(path, {
    maxAge: MAX_AGE_STATIC,
    ...opts
  })
}

module.exports = {
  createServer,
  createRollbar,
  getRollbarHandler,
  runMiddleware,
  serveStatic
}
