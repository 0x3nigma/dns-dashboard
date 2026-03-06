FROM node:20-alpine
RUN addgroup app && adduser -S -G app app
WORKDIR /app
COPY package.json .
RUN npm install --production
COPY . .
RUN chown -R app:app /app
USER app
EXPOSE 3000
CMD ["node", "index.js"]
