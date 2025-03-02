FROM node:latest

WORKDIR /home/choreouser
COPY / /home/choreouser/

RUN apt update && apt upgrade -y
RUN npm i ws express basic-auth
COPY . .

EXPOSE 7860

CMD ["node", "script.js"]
USER 10001
