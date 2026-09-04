# Docker installation example

This example shows how to install Supply Chain Firewall (`scfw`) in a Docker image and use it to inspect an `npm install` command during the image build.

The Dockerfile:

1. Starts from the Alpine-based Node.js image.
2. Downloads the pinned Linux ARM64 `scfw` binary and verifies its SHA-256 checksum.
3. Copies the example `package.json` and `package-lock.json` files into the image.
4. Mounts the Datadog API and application keys as Docker BuildKit secrets while `scfw run -- npm install` runs.

The secret values are available only to that build step and are not stored in the resulting image.

## Build the example

Export your Datadog credentials in the shell that will run Docker (preferably through a secret distribution system):

```sh
export DD_API_KEY="<your-api-key>"
export DD_APP_KEY="<your-application-key>"
```

From this directory, build the image with:

```sh
docker build \
  --secret id=dd_api_key,env=DD_API_KEY \
  --secret id=dd_app_key,env=DD_APP_KEY \
  --tag scfw-docker-example \
  .
```

Alternatively, run the build from the repository root:

```sh
docker build \
  --file examples/docker/Dockerfile \
  --secret id=dd_api_key,env=DD_API_KEY \
  --secret id=dd_app_key,env=DD_APP_KEY \
  --tag scfw-docker-example \
  examples/docker
```

Docker BuildKit must be enabled because the Dockerfile uses secret mounts. The example currently downloads the ARM64 build of `scfw`; update `ARCH` and/or `SCFW_CHECKSUM` if you target another architecture or version.

This image has no default command. It demonstrates how to protect dependency installation during a Docker build and is intended to be adapted to an application's Dockerfile.
