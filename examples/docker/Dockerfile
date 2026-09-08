# This dockerfile uses docker secrets mechanism to handle the datadog api and app keys
# If your secret is in your environment variables (for the example we assume its called DD_API_KEY and DD_APP_KEY), you should call it as 
# docker build --secret id=dd_api_key,env=DD_API_KEY --secret id=dd_app_key,env=DD_APP_KEY
FROM node:alpine

ENV SCFW_VERSION="v4.0.0"
ENV SCFW_CHECKSUM="2ab70f95c83d774cc5ec804be8e0e2996f43fa87104c7801663e933413287419"
ENV ARCH="arm64"
ARG DD_SITE="datadoghq.com"
ENV DD_SITE="${DD_SITE}"

# Install curl to download SCFW
RUN apk add curl

# Install SCFW
WORKDIR /usr/bin
RUN tmp=$(mktemp) && \
    curl -fL https://github.com/DataDog/supply-chain-firewall/releases/download/$SCFW_VERSION/scfw-linux-$ARCH -o "${tmp}" && \
    echo "${SCFW_CHECKSUM}  ${tmp}" | sha256sum -c - && \
    mv "${tmp}" scfw
RUN chmod +x scfw

# Add your project and install your dependencies
WORKDIR /usr/app
ADD package.json .
ADD package-lock.json .

# This run mount the secrets which will be available only for that command, SCFW will read those to connect to Datadog
RUN --mount=type=secret,id=dd_api_key,env=DD_API_KEY --mount=type=secret,id=dd_app_key,env=DD_APP_KEY \
    scfw run --error-on-block -- npm install
