# Octopus CSIRT, multi-stage build producing a tiny standalone image.
# Runs anywhere Node runs: Linux or Windows containers, Docker, Kubernetes, bare VM.
#
#   docker build -t octopus-csirt .
#   docker run -p 3000:3000 octopus-csirt
#
# For k3s see deploy/k3s/. The image runs as a non-root user with a READ-ONLY root
# filesystem provided /tmp and /app/.next/cache are mounted; the manifest does both.
#
# Env (the app runs without any of it, and says what is missing rather than faking it):
#   LEAKOSINT_TOKEN          → the leak source. Absent: no report, stated as such.
#   POSTGRES_URL             → accounts, credits, cases, audit trail. Absent: single
#                              operator, unmetered, unlogged, and no cases at all.
#   OCTOPUS_SESSION_SECRET   → required for sessions to be issued at all.
#   OCTOPUS_AUDIT_SECRET     → signs the audit chain. Falls back to the session secret.
#
# LEAKOSINT_TOKEN is optional: an owner can paste it into /admin instead, where it is
# stored in the database and never reaches a pod's environment.

# ---- deps ----
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# ---- build ----
FROM node:20-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# The commit this image was built from, so a running deployment can say what it is.
# Without it, "I pushed a fix" and "the fix is running" are two different claims and
# nobody on either end can tell them apart.
#
#   docker build --build-arg GIT_SHA=$(git rev-parse --short HEAD) -t ... .
ARG GIT_SHA=unknown

# ---- run ----
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ARG GIT_SHA
ENV OCTOPUS_BUILD=$GIT_SHA
RUN addgroup -g 1001 -S nodejs && adduser -S nextjs -u 1001
# standalone output bundles only what's needed to run
COPY --from=build /app/public ./public
COPY --from=build --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=build --chown=nextjs:nodejs /app/.next/static ./.next/static
USER nextjs
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD wget -qO- http://localhost:3000/ >/dev/null 2>&1 || exit 1
CMD ["node", "server.js"]
