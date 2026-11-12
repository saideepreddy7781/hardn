FROM node:22 AS b
USER node
RUN make
FROM node:22-slim
CMD node a.js
