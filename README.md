# The Brother printer with the Pi

## Test things

For anyone who is in the cert-manager org and wants to test or debug
things:

- [Install tailscale](https://tailscale.com/download/).
- Run `tailscale up`, it should open something in your browser → "Sign in with GitHub" → Authorize Tailscale → Multi-user Tailnet cert-manager.
- You can test the "front end" UI at <http://100.100.85.57/>.
- You can test that the printer works at <http://100.100.85.57:8013/>.
- You can SSH into the Pi (which runs a Kubernetes cluster) as long as
  you are a member of the cert-manager org:

  ```sh
  ssh pi@$(tailscale ip -4 pi)
  ```

  > The public keys have been added to the `authorized_keys` of the Pi.

## Running

Make sure that a k3s cluster is running on the Pi:

```sh
$ kubectl get nodes
NAME                       STATUS   ROLES                  AGE   VERSION
k3d-k3s-default-server-0   Ready    control-plane,master   11m   v1.22.7+k3s1
```

Make sure cert-manager is running:

```sh
kubectl apply -f- <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: self-signed
  namespace: default
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ca
  namespace: default
spec:
  isCA: true
  privateKey:
    algorithm: ECDSA
    size: 256
  secretName: ca
  commonName: The maintainers <cert-manager-maintainers@googlegroups.com>
  issuerRef:
    name: self-signed
    kind: Issuer
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: ca-issuer
  namespace: default
spec:
  ca:
    secretName: ca
EOF
```

### print-your-cert-back

```sh
docker run -d --name print-your-cert-back --privileged -v /dev/bus/usb:/dev/bus/usb -it --rm -p 0.0.0.0:8013:8013 github.com/maelvls/print-your-cert:latest brother_ql_web
```

### print-your-cert-front

```sh
docker run -d --name print-your-cert-front --net=host -v $HOME/.kube/config:/root/.kube/config github.com/maelvls/print-your-cert-front:latest print-your-cert --issuer ca-issuer --listen 0.0.0.0:80
```

## Troubleshooting

### From the CLI: `usb.core.USBError: [Errno 16] Resource busy`

On the Pi (over SSH), when running `brother_ql` with the following command:

```text
docker run --privileged -v /dev/bus/usb:/dev/bus/usb -it --rm github.com/maelvls/print-your-cert:latest brother_ql
```

you may hit the following message:

```text
usb.core.USBError: [Errno 16] Resource busy
```

I found that two reasons lead to this message:

1. The primary reason is that libusb-1.0 is installed on the host (on the Pi, that's Debian) and needs
   to be removed, and replaced with libusb-0.1. You can read more about this in https://github.com/pyusb/pyusb/issues/391.
2. A second reason is that the label settings aren't correct (e.g., you have select
   the black/red tape but the black-only tape is installed in the printer).

### From the web UI: `No such file or directory: '/dev/usb/lp1'`

This happened when the printer was disconnected.

## Testing

Test that `brother_lp` works over USB on Pi:

```shell=sh
convert -size 230x30 -background white -font /usr/share/fonts/TTF/OpenSans-Regular.ttf -pointsize 25 -fill black -gravity NorthWest caption:"OK." -flatten example.png
brother_ql --model QL-820NWB --printer usb://0x04f9:0x209d print --label 62 example.png
```

## Intial set up of the Pi

First, I used an SD card reader to set up Raspbian bullseye on the Pi using the Imager program. In the Imager program settings, I changed the username to `pi` and the password to something secret (usually the default password is `raspberry`, I changed it).

Then, mounted the micro SD card to my desktop did two things:

```shell=sh
# Enable SSH into the Pi.
touch /media/pi/boot/ssh

# Enable Wifi.
tee /media/pi/boot/wpa_supplicant.conf <<EOF
country=US
update_config=1
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
network={
  ssid="HARRYCOW_WIFI"
  psk="..."
}
EOF
```

> If the Wifi doesn't work, somehow SSH into the Pi and run `wpa_cli`:
>
> ```console
> $ sudo wpa_cli status
> Selected interface 'p2p-dev-wlan0'
> wpa_state=DISCONNECTED
> p2p_device_address=e6:5f:01:a6:66:00
> address=e6:5f:01:a6:66:00
> uuid=0fb4e5b4-b372-5253-93e9-fa6f2c4d8037
> ```
>
> To look for the right SSID, run on the Pi:
>
> ```sh
> wpa_cli scan && wpa_cli scan_results
> ```
>
> Then edit the file `/etc/wpa_supplicant/wpa_supplicant.conf` and run:
>
> ```sh
> sudo wpa_cli -i wlan0 reconfigure
> sudo ifconfig wlan0 down
> sudo ifconfig wlan0 up
> ```

When I have access, I configure `authorized_keys` to accept anyone from the cert-manager org:

```shell=sh
curl -sH "Authorization: token $(lpass show github.com -p)" https://api.github.com/orgs/cert-manager/members | jq '.[] | .login' -r | ssh -t pi@$(tailscale ip -4 pi) 'set -xe; while read -r i; do curl -LsS https://github.com/$i.keys | tee -a $HOME/.ssh/authorized_keys; done; cat $HOME/.ssh/authorized_keys | sort | sed -re 's/\s+$//' | uniq >a; mv a $HOME/.ssh/authorized_keys'
```

Then I install Tailscale, and log in using my home account `mael65@gmail.com` and share the device to the Tail-net cert-manager@github.

## Build and push the image `github.com/maelvls/print-your-cert:latest`

Install Docker, vim and jq on the Pi:

```shell=sh
sudo apt install -y vim jq
curl -fsSL https://get.docker.com | sudo bash
sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker
```

Build the image on your desktop (faster) and then push it to the Pi. In order to build for `linux/arm64/v8` on my amd64 machine, I used docker's buildx:

```sh
sudo apt install -y qemu qemu-user-static
docker buildx create --name mybuilder
docker buildx use mybuilder
docker buildx inspect --bootstrap
docker buildx build --platform linux/arm64/v8 -t github.com/maelvls/print-your-cert:latest -o type=docker,dest=print-your-cert.tar . && ssh pi@$(tailscale ip -4 pi) "docker load" <print-your-cert.tar
```

## Testing pem-to-png

```shell=sh
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -utf8 -subj "/CN=Maël Valais <mael@vls.dev>/O=Jetstack" -reqexts v3_req -extensions v3_ca -out ca.crt
step certificate create "CN=Foo Bar <foo@bar.com>" foo.crt foo.key --ca ca.crt --ca-key ca.key --password-file /dev/null
pem-to-png <foo.crt
timg pem-to-png.png
read
brother_ql --model QL-820NWB --printer usb://0x04f9:0x209d print --label 62 pem-to-png.png
```

# Public IP on my machine with f1.micro + WireGuard

Based on https://blog.kmassada.com/quickstart-wireguard-beryl-gcp/ (2020).

```shell=sh
gcloud iam service-accounts create secret-accessor \
  --description "SA for accessing Secret Manager secrets" \
  --display-name "secret accessor" \
  --project jetstack-mael-valais
gcloud projects add-iam-policy-binding jetstack-mael-valais \
  --member serviceAccount:secret-accessor@jetstack-mael-valais.iam.gserviceaccount.com \
  --role roles/secretmanager.secretAccessor \
  --project jetstack-mael-valais
```

```shell=sh
gcloud compute firewall-rules create allow-wireguard \
    --project jetstack-mael-valais \
    --network default \
    --action allow \
    --direction ingress \
    --rules udp:51820 \
    --source-ranges 0.0.0.0/0
gcloud compute instances create wireguard \
    --project jetstack-mael-valais \
    --network default \
    --machine-type=e2-micro \
    --image-family=debian-11 \
    --image-project=debian-cloud \
    --can-ip-forward \
    --boot-disk-size=10GB \
    --zone=europe-southwest1-c
```

Then, I went to <https://google.domains> and added the record:

```dns
print-your-cert.mael.pw.  300  IN   A   34.175.254.25
```

To get the IP, I ran:

```sh
gcloud compute instances describe wireguard \
    --project jetstack-mael-valais \
    --zone=europe-southwest1-c --format json \
      | jq -r '.networkInterfaces[].accessConfigs[] | select(.type=="ONE_TO_ONE_NAT") | .natIP'
```

Now, let us configure stuff on the VM:

```shell=sh
gcloud compute ssh --project jetstack-mael-valais --zone=europe-southwest1-c wireguard -- 'sudo apt install wireguard -y'
gcloud compute ssh --project jetstack-mael-valais --zone=europe-southwest1-c wireguard -- \
    "sudo perl -ni -e 'print if \!/^net.ipv4.ip_forward=1/d' /etc/sysctl.conf; \
     sudo tee -a /etc/sysctl.conf <<<net.ipv4.ip_forward=1"
gcloud compute ssh --project jetstack-mael-valais --zone=europe-southwest1-c wireguard -- sudo reboot
```

```sh
gcloud compute ssh --project jetstack-mael-valais --zone=europe-southwest1-c wireguard -- bash <<EOF
(umask 077 && wg genkey > wg-private.key)
wg pubkey < wg-private.key > wg-public.key
EOF
```

```sh
gcloud compute ssh --project jetstack-mael-valais --zone=europe-southwest1-c wireguard -- bash <<'EOF'
sudo tee /etc/wireguard/wg0.conf <<WG0
[Interface]
PrivateKey = $(cat wg-private.key)
MTU = 1380
Address = 10.0.2.1/24
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $(ip -o -4 route show to default | awk '{print $5}') -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $(ip -o -4 route show to default | awk '{print $5}') -j MASQUERADE
ListenPort = 51820
SaveConfig = True
AllowedIPs = ::/0, 0.0.0.0/0
WG0
EOF
sudo wg-quick up wg0
```

## Another way: Tailscale + Caddy

```sh
gcloud compute ssh --project jetstack-mael-valais --zone=europe-southwest1-c wireguard -- bash <<'EOF'
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo tee /etc/apt/trusted.gpg.d/caddy-stable.asc
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy
EOF
```

```sh
gcloud compute ssh --project jetstack-mael-valais --zone=europe-southwest1-c wireguard -- bash <<'EOF'
sudo tee /etc/caddy/Caddyfile <<CADDY
print-your-cert.mael.pw:443 {
        reverse_proxy $(tailscale ip -4 pi):8080
}
CADDY
sudo systemctl restart caddy.service
EOF
```

