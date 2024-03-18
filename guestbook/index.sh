#!/usr/bin/env bash

set -eu -o pipefail

curl --cacert root-ca.pem --cert /tmp/chain.pem --key /tmp/pkey.pem https://guestbook.print-your-cert.cert-manager.io/
