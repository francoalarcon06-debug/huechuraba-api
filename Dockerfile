# Etapa 1: deps
FROM node:20-alpine AS deps
WORKDIR /app

# Solo los package*.json primero (mejor cache)
COPY package*.json ./

# 👇 NO uses `npm ci` (requiere package-lock). Usamos `npm install`.
RUN npm install --omit=dev

# Etapa 2: app final
FROM node:20-alpine
WORKDIR /app

# Copiamos node_modules desde la etapa deps
COPY --from=deps /app/node_modules ./node_modules

# Copiamos el resto del código
COPY . .

# Vars/puerto (Easypanel te inyecta PORT, pero dejamos defaults)
ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

# Arranque
CMD ["node", "server.js"]
