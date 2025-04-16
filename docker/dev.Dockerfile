FROM node:22-alpine

# Alpine node image doesn't come with bash
RUN apk --no-cache add \
    curl \
    bash \
    make \ 
    python3 \
    g++ \
    build-base

WORKDIR /app

# install and cache app dependencies
COPY package.json yarn.lock ./

RUN yarn install --frozen-lockfile

COPY . .

# add `/app/node_modules/.bin` to $PATH
ENV PATH=/app/node_modules/.bin:$PATH

CMD [ "yarn", "run", "start:dev" ] 