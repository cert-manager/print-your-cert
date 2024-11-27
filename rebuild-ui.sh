#!/usr/bin/env bash

set -eu -o pipefail

KO_DOCKER_REPO=ghcr.io/cert-manager/print-your-cert-ui ko build . --platform linux/arm64 --tarball print-your-cert-ui.tar --push=false --bare

# Example scp command over tailscale
# scp print-your-cert-ui.tar certmanager@100.84.86.89:
