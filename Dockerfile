# Copyright 2026 Optima Solutions GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0

# Stage 1: Builder (Build native dependencies)
# Using Debian-based node image which includes build tools (python3, make, g++, etc.)
FROM node:22-bookworm AS builder

WORKDIR /src

# Copy package files
COPY package*.json ./

# Install dependencies (including dev/build deps)
# npm ci ensures clean install from lockfile and builds native modules like better-sqlite3
RUN npm ci

# Create data directory here (so we can copy it with permissions later)
RUN mkdir -p data

# Stage 2: Runner (Lightweight Node.js image)
# Switch to official public image to avoid authorization errors
# Using Bookworm to match the builder stage and avoid glibc version mismatches
FROM node:22-bookworm-slim

# Set production environment
ENV NODE_ENV=production
ENV PORT=3232
ENV HOST=0.0.0.0

WORKDIR /app

# Switch to non-root user for security (UID 1000 is standard for 'node' user)
USER node

# Copy data directory from builder with correct ownership
COPY --from=builder --chown=node:node /src/data ./data

# Copy installed node_modules from builder
COPY --from=builder --chown=node:node /src/node_modules ./node_modules

# Copy application source code
# Since we are restricted to specific files based on .dockerignore, we can copy .
COPY --chown=node:node . .

# Expose the application port
EXPOSE 3232

# Start the server directly
CMD ["node", "server.js"]

