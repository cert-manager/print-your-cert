#!/usr/bin/env bash

set -eu -o pipefail

curl --cacert ca.crt --resolve readonly-guestbook.print-your-cert.cert-manager.io:9090:127.0.0.1 https://readonly-guestbook.print-your-cert.cert-manager.io:9090/
