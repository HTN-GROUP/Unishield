FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

# Dependencies install karein sath hi ajv fix add karein
RUN npm install --legacy-peer-deps
RUN npm install ajv@^7 ajv-keywords@^5 --save-dev --legacy-peer-deps

COPY . .

EXPOSE 3000

CMD ["npm", "start"]