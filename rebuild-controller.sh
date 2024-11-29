#!/usr/bin/env bash

set -eu -o pipefail

docker buildx create --name mybuilder || :

docker buildx build -f Dockerfile.controller --platform linux/arm64 \
	-t ghcr.io/cert-manager/print-your-cert-controller:latest \
	-o type=docker,dest=print-your-cert-controller.tar .

# Example scp command over tailscale
# scp print-your-cert-controller.tar certmanager@100.84.86.89:
