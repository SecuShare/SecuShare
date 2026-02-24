import { defineConfig, type Plugin } from 'vite'
import { createHash } from 'crypto'
import { readFileSync } from 'fs'
import { resolve } from 'path'
import react from '@vitejs/plugin-react'

function validateEnvPlugin(): Plugin {
  return {
    name: 'validate-env',
    configResolved(config) {
      if (config.command === 'build') {
        const apiUrl = config.env?.VITE_API_URL ?? process.env.VITE_API_URL
        if (!apiUrl) {
          throw new Error(
            'VITE_API_URL environment variable is required for production builds. ' +
            'Set it in .env.production or pass it via the environment.'
          )
        }
      }
    },
  }
}

function sriPlugin(): Plugin {
  let rootDir = ''

  return {
    name: 'vite-plugin-sri',
    enforce: 'post',
    apply: 'build',
    configResolved(config) {
      rootDir = config.root
    },
    transformIndexHtml: {
      order: 'post',
      handler(html, ctx) {
        const bundle = ctx.bundle ?? {}

        return html.replace(
          /<(script|link)\b([^>]*?)(\s*\/?>)/g,
          (match, tag, attrs, close) => {
            if (attrs.includes('integrity=')) return match

            const srcMatch = attrs.match(/(?:src|href)="([^"]*)"/)
            if (!srcMatch) return match

            const assetPath = srcMatch[1]
            if (assetPath.startsWith('http')) return match

            const bundleKey = assetPath.replace(/^\//, '')
            let content: Buffer | null = null

            // Try to get content from the in-memory bundle first
            const chunk = bundle[bundleKey]
            if (chunk) {
              if (chunk.type === 'chunk') {
                content = Buffer.from(chunk.code, 'utf-8')
              } else if (chunk.type === 'asset' && chunk.source) {
                content = Buffer.from(chunk.source)
              }
            }

            // Fall back to reading from public dir (for static assets like favicon)
            if (!content) {
              try {
                content = readFileSync(resolve(rootDir, 'public', assetPath.replace(/^\//, '')))
              } catch {
                return match
              }
            }

            const hash = createHash('sha384').update(content).digest('base64')
            // Remove existing crossorigin attr, we'll add our own
            const cleanAttrs = attrs.replace(/\s*crossorigin(?:="[^"]*")?/, '')
            return `<${tag}${cleanAttrs} integrity="sha384-${hash}" crossorigin="anonymous"${close}`
          }
        )
      },
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), validateEnvPlugin(), sriPlugin()],
  build: {
    sourcemap: false,
  },
  optimizeDeps: {
    exclude: ['@serenity-kit/opaque'],
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
