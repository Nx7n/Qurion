FROM node:18

WORKDIR /opt/open5gs-webui

COPY src/open5gs/webui .
COPY docker/open5gs-webui/create-admin.js .

RUN npm install
RUN npm run build

ENV DB_URI=mongodb://mongodb/open5gs
ENV HOSTNAME=0.0.0.0
ENV PORT=3000
ENV NODE_ENV=production

EXPOSE 3000

CMD ["npm","start"]