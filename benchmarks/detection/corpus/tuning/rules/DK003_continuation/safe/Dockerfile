FROM node:22
RUN curl -fsSLo i.sh https://x.example.com/i.sh \
  && sha256sum -c i.sha
USER node
