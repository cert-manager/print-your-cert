#!/usr/bin/env bash

set -eu -o pipefail

curl --cacert root-ca.pem --cert /tmp/chain.pem --key /tmp/pkey.pem https://guestbook.print-your-cert.cert-manager.io/write \
	-X POST \
	-H "Content-Type: application/x-www-form-urlencoded" \
	-d "message=hello, world"
