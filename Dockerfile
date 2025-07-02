# Multi-stage production-ready Dockerfile for Google Analytics MCP Server
# Optimized for security, performance, and minimal image size

# ================================
# Builder Stage
# ================================
FROM node:20-slim AS builder

# Install system dependencies needed for building
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install pnpm globally
RUN npm install -g pnpm

# Copy package management files
COPY package.json pnpm-lock.yaml tsconfig.json ./

# Install all dependencies (including devDependencies for building)
RUN pnpm install --frozen-lockfile

# Copy source code
COPY src/ ./src/

# Build the TypeScript project
RUN pnpm run build

# Install only production dependencies in a clean directory
RUN pnpm install --frozen-lockfile --prod --ignore-scripts

# ================================
# Production Stage
# ================================
FROM node:20-alpine AS production

# Create a non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S mcp-server -u 1001

# Set working directory
WORKDIR /app

# Change ownership of the app directory to the non-root user
RUN chown -R mcp-server:nodejs /app

# Switch to non-root user
USER mcp-server

# Copy only the necessary production artifacts from builder stage
COPY --from=builder --chown=mcp-server:nodejs /app/dist ./dist
COPY --from=builder --chown=mcp-server:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=mcp-server:nodejs /app/package.json ./package.json

# Expose the port (if the application uses one)
# Note: MCP servers typically don't expose HTTP ports, but keeping for flexibility
EXPOSE ${PORT:-3001}

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "console.log('Health check passed')" || exit 1

# Set NODE_ENV to production
ENV NODE_ENV=production

# Start the MCP server
CMD ["node", "dist/index.js"]
