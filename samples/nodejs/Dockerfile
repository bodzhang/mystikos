#FROM alpine:3.8

#RUN apk add --no-cache \
#    nodejs npm

FROM node:alpine

#RUN npm i cpu-benchmark

RUN rm -rf /app;mkdir -p /app
WORKDIR /app
ADD cpubench.js /app

CMD ["/bin/sh"]
#CMD ["node"]
