#!/usr/bin/env bash


set -eu -o pipefail

CM_VERSION=${CM_VERSION:-v1.17.1}

#kind load docker-image --name printyourcert quay.io/jetstack/cert-manager-controller:$CM_VERSION
#kind load docker-image --name printyourcert quay.io/jetstack/cert-manager-cainjector:$CM_VERSION
#kind load docker-image --name printyourcert quay.io/jetstack/cert-manager-ctl:$CM_VERSION
#kind load docker-image --name printyourcert quay.io/jetstack/cert-manager-webhook:$CM_VERSION
#helm install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --version $CM_VERSION --set installCRDs=true

helm repo add jetstack https://charts.jetstack.io --force-update
helm install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --version $CM_VERSION --set installCRDs=true

kubectl apply -f root_issuer_dev.yaml --wait
#kubectl apply -f root-print-your-cert-ca.yaml
#kubectl apply -f root_issuer_prod.yaml

kubectl apply -f cluster_issuer.yaml --wait

kubectl apply -f guestbook/certificate.yaml --wait

sleep 10

kubectl get -n cert-manager secrets guestbook-tls -ojson | jq -r '.data."tls.crt"'  | base64 -d  > guestbook/tls.crt
kubectl get -n cert-manager secrets guestbook-tls -ojson | jq -r '.data."tls.key"'  | base64 -d  > guestbook/tls.key

kubectl get -n cert-manager secrets root-print-your-cert-ca -ojson | jq -r '.data."tls.crt"' | base64 -d > guestbook/ca.crt
