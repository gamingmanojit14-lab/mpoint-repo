# MPOINT FULL NODE - Docker Image
# 
# যেকোনো ক্লাউড সার্ভারে (VPS) মাত্র এক ক্লিকে এমপয়েন্ট নোড রান করার জন্য এই ডকার ফাইল।

FROM node:20-alpine

# Create app directory
WORKDIR /usr/src/mpoint

# Install dependencies (LevelDB requires build tools on alpine)
RUN apk add --no-cache python3 make g++

# Copy package files and install production dependencies
COPY package*.json ./
RUN npm install --production

# Copy core, network, and node source code
COPY core/ ./core/
COPY network/ ./network/
COPY node/ ./node/

# Expose P2P TCP port and RPC port
EXPOSE 53412
EXPOSE 8332

# Set the entrypoint to our CLI node starter
CMD [ "node", "node/cli/mpoint-node.js" ]
