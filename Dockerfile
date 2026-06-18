FROM node:20-alpine

WORKDIR /app

# Create non-root user early
RUN addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup

# Copy package files first for better caching
COPY package*.json ./

RUN npm ci --omit=dev && \
    chown -R appuser:appgroup /app

# Copy source (respect .dockerignore)
COPY --chown=appuser:appgroup . .

# Expose the app port
EXPOSE 5173

# Production environment
ENV NODE_ENV=production
ENV PORT=5173

# Switch to non-root
USER appuser

# Healthcheck (uses Node built-in fetch)
HEALTHCHECK --interval=30s --timeout=6s --start-period=12s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:5173/api/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

CMD ["npm", "start"]
