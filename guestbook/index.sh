#!/usr/bin/env bash

set -eu -o pipefail

curl --cert /tmp/chain.pem --key /tmp/pkey.pem https://guestbook.print-your-cert.cert-manager.io/
