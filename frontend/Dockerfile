# Build stage
FROM node:25-alpine AS builder

WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Required by Vite build validation (defaults to same-origin API path)
ARG VITE_API_URL=/api/v1
ENV VITE_API_URL=${VITE_API_URL}

# Build the application
RUN npm run build

# Runtime stage with nginx (unprivileged)
FROM nginxinc/nginx-unprivileged:alpine

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built files from builder
COPY --from=builder /app/dist /usr/share/nginx/html

# Expose unprivileged port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
