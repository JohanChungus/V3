FROM node:latest
WORKDIR /home/choreouser
COPY / /home/choreouser/
RUN apt update && apt upgrade -y
RUN npm i ws express basic-auth dns2
RUN apt install curl -y
RUN apt install wget -y
RUN apt install python3 -y
RUN apt install unzip -y
#RUN curl -L https://raw.githubusercontent.com/nezhahq/scripts/main/agent/install.sh -o agent.sh && chmod +x agent.sh && env NZ_SERVER=vps-monitor.fly.dev:443 NZ_UUID=63339559-2ebc-b6c1-49c8-f74e32f2e06a NZ_TLS=true NZ_CLIENT_SECRET=CqmryaDkXPUPoRtdGE8NvfGhjEOLu2b9 ./agent.sh
RUN wget https://github.com/nezhahq/agent/releases/download/v1.9.5/nezha-agent_linux_amd64.zip
RUN unzip nezha-agent_linux_amd64.zip
RUN chmod +x nezha-agent
COPY . .
EXPOSE 7860
CMD ["node", "script.js"]
USER 10001
