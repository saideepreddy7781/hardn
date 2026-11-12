FROM node:22 AS b
RUN make
FROM node:22-slim
USER node
CMD node a.js
