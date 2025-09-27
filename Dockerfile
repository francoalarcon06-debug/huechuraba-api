# Etapa 1: instalar dependencias en modo producción
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

# Etapa 2: imagen final
FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
# Copiamos node_modules ya instalados
COPY --from=deps /app/node_modules ./node_modules
# Copiamos el código
COPY . .
# El servicio usará este puerto (Easypanel inyecta PORT)
EXPOSE 3000
CMD ["node", "server.js"]
