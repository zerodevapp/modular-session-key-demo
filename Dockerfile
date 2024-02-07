FROM oven/bun

WORKDIR /usr/src/app

COPY package*.json bun.lockb ./
RUN bun install
COPY . .

ENV NODE_ENV production

# Build the application
RUN bun run build:vite

# Use Nginx to serve the static files
FROM nginx:alpine

# Copy static files from builder to Nginx serve directory
COPY --from=builder /usr/src/app/dist /usr/share/nginx/html

# Expose port 80
EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]