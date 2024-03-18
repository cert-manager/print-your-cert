#!/usr/bin/env bash


set -eu -o pipefail

helm repo add jetstack https://charts.jetstack.io --force-update
helm upgrade --install cert-manager --namespace cert-manager jetstack/cert-manager --set installCRDs=true --create-namespace

kubectl apply -f root_issuer_dev.yaml --wait
kubectl apply -f cluster_issuer.yaml --wait

kubectl apply -f guestbook/certificate.yaml --wait

sleep 10

kubectl get -n cert-manager secrets guestbook-tls -ojson | jq -r '.data."tls.crt"'  | base64 -d  > guestbook/tls.crt
kubectl get -n cert-manager secrets guestbook-tls -ojson | jq -r '.data."tls.key"'  | base64 -d  > guestbook/tls.key

kubectl get -n cert-manager secrets root-print-your-cert-ca -ojson | jq -r '.data."tls.crt"' | base64 -d > guestbook/ca.crt
