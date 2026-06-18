FROM node:18-alpine AS base

WORKDIR /workspace

ENV NEXT_TELEMETRY_DISABLED=1

FROM base AS deps

RUN apk add --no-cache libc6-compat

COPY package.json package-lock.json ./
RUN npm ci

FROM base AS builder

COPY --from=deps /workspace/node_modules ./node_modules
COPY . .

RUN npm run build

FROM base AS runner

ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

COPY --from=builder /workspace/public ./public
COPY --from=builder /workspace/.next ./.next
COPY --from=builder /workspace/node_modules ./node_modules
COPY --from=builder /workspace/package.json ./package.json

EXPOSE 3000

CMD ["npm", "run", "start"]
