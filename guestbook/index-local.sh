#!/usr/bin/env bash

set -eu -o pipefail

curl --cacert ca.crt --cert /tmp/chain.pem --key /tmp/pkey.pem --resolve guestbook.print-your-cert.cert-manager.io:9090:127.0.0.1 https://guestbook.print-your-cert.cert-manager.io:9090/
