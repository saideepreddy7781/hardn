FROM node:latest
WORKDIR /app
ENV API_TOKEN=b3f9c2a7e1d84f60
RUN curl -fsSL https://example.com/install.sh | sh
COPY . .
RUN npm install
CMD ["node", "server.js"]
