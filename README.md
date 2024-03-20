<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>

# The "Print your certificate!" experiment at the cert-manager booth at KubeCon

This experiment was run at the cert-manager booth at KubeCon EU 2022 in
Valencia, KubeCon NA 2022 in Detroit, KubeCon EU 2023 in Amsterdam,
and KubeCon NA 2023 in Chicago.

⚠️ Except for the URL <cert-manager.github.io/print-your-cert/> which should
work forever, the other URLs and IPs presented in this README are temporary.

<img alt="Photo of the cert-manager booth when we were running the Print your certificate experiment. A participant can be seen typing their name and email on the keyboard." src="https://user-images.githubusercontent.com/2195781/170957591-0cfcfb4d-05d8-41ad-bfa6-f6162e36479f.jpeg" width="300"/> <img alt="Liz Rice met with the cert-manager maintainers Charlie Egan, Josh van Leeuwen, and Jake Sanders with the cert-manager booth in the background. All credits for this image go to Liz Rice who shared this picture on Twitter at https://twitter.com/lizrice/status/1527585297743110145." src="https://user-images.githubusercontent.com/2195781/170959280-f78822a4-1ba8-416c-91dc-5e7dbc5da24b.png" width="300"/> <img alt="Dovy came to the cert-manager booth and took a picture of the card on which a stamp of the cert-manager project is visible, as well as the label showing their X.509 certificate. All credits for this photo go to Dovy who shared this picture on Twitter at https://twitter.com/ddovys/status/1526890240568344576." src="https://user-images.githubusercontent.com/2195781/170959287-125e5fab-52ab-43f5-8781-94af0d3cbb83.png" width="300"/>

- [Video and slides](#video-and-slides)
- [Description of the experiment](#description-of-the-experiment)
- [What's the stack?](#whats-the-stack)
- [Staff: test things](#staff-test-things)
- [Running everything on the Raspberry Pi (on the booth)](#running-everything-on-the-raspberry-pi-on-the-booth)
  - [Booth: Initial set up of the Raspberry Pi](#booth-initial-set-up-of-the-raspberry-pi)
  - [Booth: Set Up Tailscale on the Raspberry Pi](#booth-set-up-tailscale-on-the-raspberry-pi)
  - [Booth: Make sure you can SSH into the Rasberry Pi](#booth-make-sure-you-can-ssh-into-the-rasberry-pi)
  - [Booth: Set Up Docker, Helm, K3d, and kubectl](#booth-set-up-docker-helm-k3d-and-kubectl)
  - [Booth: Set up the tunnel between the Internet and the Raspberry Pi](#booth-set-up-the-tunnel-between-the-internet-and-the-raspberry-pi)
  - [Prerequisite: install k3s on the Raspberry Pi](#prerequisite-install-k3s-on-the-raspberry-pi)
  - [Booth: Configure kubectl on your laptop to access the Raspberry Pi's cluster](#booth-configure-kubectl-on-your-laptop-to-access-the-raspberry-pis-cluster)
  - [Booth: Install cert-manager and the issuers on the Raspberry Pi](#booth-install-cert-manager-and-the-issuers-on-the-raspberry-pi)
  - [Booth: Run the UI on the Raspberry Pi](#booth-run-the-ui-on-the-raspberry-pi)
  - [Booth: Running the printer controller on the Raspberry Pi](#booth-running-the-printer-controller-on-the-raspberry-pi)
- [Local development](#local-development)
  - [Local development on the UI](#local-development-on-the-ui)
  - [Local development on the controller (that creates PNGs and prints them)](#local-development-on-the-controller-that-creates-pngs-and-prints-them)
    - [`pem-to-png`](#pem-to-png)
    - [Testing the printer](#testing-the-printer)
    - [Testing pem-to-png](#testing-pem-to-png)
- [Troubleshooting](#troubleshooting)
  - [From the CLI: `usb.core.USBError: [Errno 13] Access denied (insufficient permissions)`](#from-the-cli-usbcoreusberror-errno-13-access-denied-insufficient-permissions)
  - [From the CLI: `usb.core.USBError: [Errno 16] Resource busy`](#from-the-cli-usbcoreusberror-errno-16-resource-busy)
  - [From the web UI: `No such file or directory: '/dev/usb/lp1'`](#from-the-web-ui-no-such-file-or-directory-devusblp1)

## Video and slides

Here is a short video showing what the experiment looked like on Friday 20 May 2022
at KubeCon Valencia:

[![A minute at the cert-manager booth with the "Print your certificate" experiment at KubeCon 2022 in Valencia](https://user-images.githubusercontent.com/2195781/170956255-c7b4b36e-6405-431c-991c-8f1352aaf2a1.jpg)](https://www.youtube.com/watch?v=7Gyt4-yVTN8 "A minute at the cert-manager booth (KubeCon EU 2022 in València)")

Here are the slides Mael presented after KubeCon:

<img width="500" alt="Print your cert, KubeCon 2022 Valencia" src="https://user-images.githubusercontent.com/2195781/185626468-9c3f5857-cc2f-47c4-af0a-0d677fc64533.png"/><img width="500" alt="Print your cert, KubeCon 2022 Valencia (1)" src="https://user-images.githubusercontent.com/2195781/185626527-d94824b6-e68a-4624-8fa0-ade370cb0701.png"/><img width="500" alt="Print your cert, KubeCon 2022 Valencia (2)" src="https://user-images.githubusercontent.com/2195781/185626500-ba19f5e0-0bda-49aa-9972-717f820e509e.png"/><img width="500" alt="Print your cert, KubeCon 2022 Valencia (3)" src="https://user-images.githubusercontent.com/2195781/185626540-b7794961-83ad-4c28-b3e5-7b357d24d7a4.png"/><img width="500" alt="Print your cert, KubeCon 2022 Valencia (4)" src="https://user-images.githubusercontent.com/2195781/185626551-e690ff66-da3d-4fe1-8496-697530c277e8.png"/>

## Description of the experiment

When visiting the cert-manager booth, you will be welcomed and one of the staff
may suggest to visit a QR code from their phone to participate to the "Print
your certificate!" experiment, or to use the Raspberry Pi's keyboard and screen
available on the booth.

Upon opening the QR code link (or on the Raspberry Pi's screen), the participant
is shown a web page prompting for a name and email:

<img alt="landing-1" src="https://user-images.githubusercontent.com/2195781/170956946-2f39e7d9-2b02-4ff8-a77f-e731c6db4510.png" width="500"/>

The issuance takes less than a second, and the participant is redirected to a new page where they
can see a receipt of their certificate. A button "Print your certificate" appears:

<img alt="landing-4" src="https://user-images.githubusercontent.com/2195781/170957142-4ee0ab2a-067f-41ff-9e80-20c3d9b14fb1.png" width="500"/>

When clicking on "Print your certificate", the participant is told that their
certificate will shortly be printed.

The printer, installed on the booth, starts printing two labels: one for the
front side, and one for the back side. The booth staff sticks the two printed
labels onto a black-colored card (format A7), and uses the wax gun and the wax
stamp to stamp the card.

> Because the label is made of plastic, and the wax is hot, it is advised to the
> staff not to put stamp in contact of the label.

The front-side label looks like this:

<img src="https://user-images.githubusercontent.com/2195781/168418627-0952377f-5a1d-4dbe-a41f-80cf99430b77.png" width="300" alt="front"/>

The back-side label looks like this:

<img src="https://user-images.githubusercontent.com/2195781/168418632-8650a78a-d540-4831-9238-dd59b9994a2b.png" width="200" alt="back"/>

The person can choose the color of the card onto which the cert-manager booth
staff will put the two labels that were automatically printed on. I purchased
200 cards of each color (1400 total), so it should be enough:

<img alt="a7-sized-card-1" src="https://user-images.githubusercontent.com/2195781/168466048-39aa8109-01cf-44f6-ac6a-3f90ec9e355c.jpg" width="300"/><img alt="a7-sized-card-2" src="https://user-images.githubusercontent.com/2195781/168466050-d9f20184-8c96-4120-80cc-5b8b0fbd6936.jpg" width="300"/>

Here is what it may look like for real. Since I didn't have the above cards for
the prototype, I have cut a piece of cardboard with the A7 size (7.4 x 10.5 cm).
The label on the front is 6.2 x 8.7 cm, and the wax stamp is 4 cm large.

<img alt="card-draft-front" src="https://user-images.githubusercontent.com/2195781/168466186-4559cf12-ee44-42a1-bb24-0e991e09b287.jpeg" width="300"/><img alt="card-draft-back" src="https://user-images.githubusercontent.com/2195781/168466187-5ffb4c96-cd70-4612-ac43-f4169b3ee427.jpeg" width="300">

The "real" colored cards will be smaller (5.4 x 9.0 cm) meaning that I will have
to do a smaller label on both sides.

The back-side labels is a QR code containing the PEM-encoded certificate that
was issued. Since we didn't find any good use for TLS, we didn't include the
private key.

I wanted the smallest TLS certificate possible. After reading [Smallest possible
certificate for IoT
device](https://crypto.stackexchange.com/questions/83719/smallest-possible-certificate-for-iot-device),
it seems ECDSA is good for small signatures, and RSA is not good. The
configuration for the ECDSA signature is shown below in
[print-your-cert-ca](#print-your-cert-ca).

The QR code contains a URL of the form:

```sh
https://cert-manager.github.io/print-your-cert/?asn1=MIICXDCCAgOgAwIU...O7pAkqhQc%3D)
<--------------------------------->       <------------------------->
      Hosted on GitHub Pages                   The base-64 encoded and
                                               URL-encoded PEM-encoded
                                               certificate without the headers.
```

For example:

<https://cert-manager.github.io/print-your-cert/?asn1=MIICXDCCAgOgAwIBAgIQdPaTuGSUDeosii4dbdLBgTAKBggqhkjOPQQDAjAnMSUwIwYDVQQDExxUaGUgY2VydC1tYW5hZ2VyIG1haW50YWluZXJzMB4XDTIyMDUxNjEzMDkwMFoXDTIyMDgxNDEzMDkwMFowLDEqMCgGA1UEAwwhZm9vIGJhciBmb28gYmFyIDxmb28uYmFyQGJhci5mb28%2BMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtmGM5lil9Vw%2Fy5LhpgO8t5gSb5oUo%2BDp5vWw0Z5C7rjvifi0%2FeD9MbVFkxb%2B%2BhmOaaNCVgqDUio1OBOZyL90KzdnGW7nz1fRM2KCNrDF5Y1mO7uv1ZTZa8cVBjF67KjFuNkvvHp74m65bKwXeCHXJBmO3Z1FH8hudICU74%2BNl6tyjlMOsTHv%2BLY0jPfmAtO6eR%2BEf%2FHvgzwsjKds12vdlRCdHSS6u5zlrZZxF3zTO7YuAM7mN8Wbjq94YcpgsJ5ssNOtMu9FwZtPGQDHPaQyVQ86FfjhmMi1IUOUAAGwh%2FQRv8ksX%2BOupHTNdH06WmIDCaGBjWFgPkwicavMZgZG3QIDAQABo0EwPzAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH%2FBAIwADAfBgNVHSMEGDAWgBQG5XQnDhOUa748L9H7TWZN2avluTAKBggqhkjOPQQDAgNHADBEAiBXmyJ24PTG76pEyq6AQtCo6TXEidqJhsmK9O5WjGBw7wIgaPbcFI5iMMgfPGEATH2AGGutZ6MlxBmwhEO7pAkqhQc%3D>

> <a id=asn1></a> **⁉️ How do we get this URL?** First, take a PEM-encoded
> certificate. It will looks like this:
>
> ```text
> -----BEGIN CERTIFICATE-----
> MIIDBzCCAe+gAyPj/8QWMBQUAMIGLMQswCQYD
> wIBAgMIG+LMQswCQYDAOPj/8QAaDMBQEFAwUa
> ...
> -----END CERTIFICATE-----
> ```
>
> It takes three steps to turn this PEM-encoded certificate into something that
> can be given with the query parameter `?asn1=...`.
>
> 1. We remove the header and footer, i.e., we remove the lines `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----`). The result looks like
>    this:
>
>    ```text
>    MIIDBzCCAe+gAyPj/8QWMBQUAMIGLMQswCQYD
>    wIBAgMIG+LMQswCQYDAOPj/8QAaDMBQEFAwUa
>    ```
>
> 2. (optional) We can save a few bytes by removing the newlines. The result is:
>
>    ```text
>    MIIDBzCCAe+gAyPj/8QWMBQUAMIGLMQswCQYDwIBAgMIG+LMQswCQYDAOPj/8QAaDMBQEFAwUa
>    ```
>
> 3. At this point, we have the ASN.1 certificate encoded in base 64. We have to
>    URL-encode it, which gives:
>
>    ```text
>    MIIDBzCCAe%2BgAyPj%2F8QWMBQUAMIGLMQswCQYDwIBAgMIG%2BLMQswCQYDAOPj%2F8QAaDMBQEFAwUa%0A
>    ```
>
> 4. Copy this into the URL:
>
>    ```text
>    https://cert-manager.github.io/print-your-cert?asn1=MIIDBzCCAe%2BgAyPj%2F8QWMBQUAMIGLMQswCQYDwIBAgMIG%2BLMQswCQYDAOPj%2F8QAaDMBQEFAwUa%0A
>    ```
>
> One-line that takes a PEM-encoded certificate and returns a URL:
>
> ```sh
> cat <<EOF | grep -v CERTIFICATE | tr -d $'\n' | python3 -c "import urllib.parse; print(urllib.parse.quote_plus(open(0).read()))" | (printf "https://cert-manager.github.io/print-your-cert?asn1="; cat)
> -----BEGIN CERTIFICATE-----
> MIIDBzCCAe+gAyPj/8QWMBQUAMIGLMQswCQYD
> wIBAgMIG+LMQswCQYDAOPj/8QAaDMBQEFAwUa
> ...
> -----END CERTIFICATE-----
> EOF
> ```

On the certificate page, the participant can also see their certificate by
clicking on the button "Print your certificate". The PEM-encoded certificate is
shown in the browser:

<img alt="download" src="https://user-images.githubusercontent.com/2195781/168419122-1bf3d0dd-c474-4d47-a55e-56980ed16441.png" width="500"/>

On the booth, we have a 42-inch display showing the list of certificates
(<https://print-your-cert.cert-manager.io/list>):

<img alt="list" src="https://user-images.githubusercontent.com/2195781/168419219-fb3e5eb7-672e-4792-9ac3-40cf8e6b251d.png" width="300"/>

And that's it: you have a certificate that proves that you were at the KubeCon
cert-manager booth! The CA used during the conference will be available at some
point so that people can verify the signature.

## What's the stack?

```text
https://print-your-cert.cert-manager.io
                |
                |
                v
            VM on GCP
                |
                |  Caddy + Tailscale
                |  (see section below)
                |
                v
+---------------------------------+
|               Pi                |
|  K3s cluster                    |   USB   +-------------------+
|    cert-manager                 | ------> | Brother QL-820NWB |
|    print-your-cert-ui (:8080)   |         +-------------------+
|    print-your-cert-controller   |                (on the booth)
+---------------------------------+
                |    (on the booth)
          HDMI  |
                v
     +-------------------+
     | list of certs     |
     | already printed   | 42" display.
     |                   |
     +-------------------+
            (on the booth)
```

## Staff: test things

For anyone who is in the cert-manager org and wants to test or debug
things:

- [Install tailscale](https://tailscale.com/download/).
- Run `tailscale up`, it should open something in your browser → "Sign in
  with GitHub" → Authorize Tailscale → Multi-user Tailnet cert-manager.
- If <http://print-your-cert.cert-manager.io/> doesn't work, then the frontend UI
  is at <http://100.121.173.5:8080/>.
- You can test that the printer works at <http://100.121.173.5:8013/>.
- You can SSH into the Pi (which runs a Kubernetes cluster) as long as
  you are a member of the cert-manager org:

  ```sh
  ssh pi@100.121.173.5
  ```

  > The public keys of each cert-manager org member have been added to the
  > `authorized_keys` of the Pi.

## Running everything on the Raspberry Pi (on the booth)

Once on the booth, you will need to perform these ten tasks:

1. [Booth: Initial set up of the Raspberry Pi](#booth-initial-set-up-of-the-raspberry-pi)
1. [Booth: Set Up Tailscale on the Raspberry Pi](#booth-set-up-tailscale-on-the-raspberry-pi)
1. [Booth: Make sure you can SSH into the Rasberry Pi](#booth-make-sure-you-can-ssh-into-the-rasberry-pi)
1. [Booth: Set Up Docker, Helm, K3d, and kubectl](#booth-set-up-docker-helm-k3d-and-kubectl)
1. [Booth: Set up the tunnel between the Internet and the Raspberry Pi](#booth-set-up-the-tunnel-between-the-internet-and-the-raspberry-pi)
1. [Prerequisite: install k3s on the Raspberry Pi](#prerequisite-install-k3s-on-the-raspberry-pi)
1. [Booth: Configure kubectl on your laptop to access the Raspberry Pi's cluster](#booth-configure-kubectl-on-your-laptop-to-access-the-raspberry-pis-cluster)
1. [Booth: Install cert-manager and the issuers on the Raspberry Pi](#booth-install-cert-manager-and-the-issuers-on-the-raspberry-pi)
1. [Booth: Run the UI on the Raspberry Pi](#booth-run-the-ui-on-the-raspberry-pi)
1. [Booth: Running the printer controller on the Raspberry Pi](#booth-running-the-printer-controller-on-the-raspberry-pi)

### Booth: Initial set up of the Raspberry Pi

> [!WARNING]
> If you need to upgrade Debian on the Raspberry Pi (`apt upgrade`),
> please upgrade it at least a week before KubeCon so that any breakage (e.g.,
> the Raspberry UI) can be fixed before the venue! We mistakenly ran `sudo apt
upgrade` on the first day of KubeCon in Amsterdam and ended up spending half
> of the day fixing it!

First, unplug the micro SD card from the Raspberry Pi and plug it into your
laptop using a micro-SD-to-SD card adaptor.

Then, install Raspberry OS (Debian Bookworm) on the Pi using the Imager program.
In the Imager program settings, I changed the username to `pi` and the password
to something secret (usually the default password is `raspberry`, I changed it;
see the label on the side of the Raspberry Pi).

Then, you will need to mount the micro SD card to your laptop using a
SD-to-micro-SD adaptor. Once the SD card is mounted, set the following variable
to where the SD card is mounted:

```sh
# On macOS:
PI=/Volumes/bootfs
```

Then, enable SSH on the Pi:

```bash
touch $PI/ssh
```

There used to be a way to configure the Wifi password without a screen and
keyboard, but that's not possible anymore with Bookworm
([source](https://www.raspberrypi.com/documentation/computers/configuration.html#connect-to-a-wireless-network)).

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

Then, unmount the micro SD card from your laptop and plug it into the Raspberry.

### Booth: Set Up Tailscale on the Raspberry Pi

Plug a keyboard and mouse to the Raspberry and install Tailscale:

```bash
# From the Raspberry Pi:
curl -fsSL https://tailscale.com/install.sh | sh
```

Then, login with the following command. It will open a browser window, allowing
you to log in. Use your GitHub account to log in (Sign In with GitHub ->
Authorize Tailscale -> Multi-user Tailnet -> select tailnet
`cert-manager.org.github`).

```sh
tailscale up --accept-dns=false
```

> [!IMPORTANT]
>
> Make sure to disable Tailscale's DNS resolution with `--accept-dns=false`. We
> have seen a ton of problems with Tailscale's DNS resolution.

If you prefer staying logged in to your personal tailnet, feel free to share the
machine with your Tailnet in <https://login.tailscale.com/admin/machines>. That
way, you can stay logged to your tailnet but still be able to access the
Raspberry Pi.

Then, go back to your laptop and run the following command to make sure everyone
in the cert-manager org can SSH into the Pi:

```bash
curl -sH "Authorization: token $(lpass show github.com -p)" https://api.github.com/orgs/cert-manager/members \
  | jq '.[] | .login' -r \
  | ssh -t pi@100.85.65.38 \
    'set -xe; while read -r i; do curl -LsS https://github.com/$i.keys | tee -a $HOME/.ssh/authorized_keys; done; cat $HOME/.ssh/authorized_keys | sort | sed -re 's/\s+$//' | uniq >a; mv a $HOME/.ssh/authorized_keys'
```

### Booth: Make sure you can SSH into the Rasberry Pi

First, make sure you have Tailscale installed and running. Make sure to be
[login](https://login.tailscale.com/) using your GitHub account, and select the
Tailnet `cert-manager.org.github`. The Pi is shared to that Tailnet.

Then, edit your `~/.ssh/config` to add the following:

```text
Host pi
  HostName 100.85.65.38
  User pi
```

All the commands below assume that you have configured your `~/.ssh/config` as
above.

### Booth: Set Up Docker, Helm, K3d, and kubectl

Make sure you have configured `~/.ssh.config` in the section above. Then, SSH
into the Pi:

```bash
ssh pi
```

> [!NOTE]
>
> You may see the following error message when SSHing into the Pi:
>
> ```text
> bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
> ```
>
> To fix this, you can run the following command:
>
> ```sh
> # From the Raspberry Pi.
> sudo tee -a /etc/environment <<<"LC_ALL=en_US.UTF-8"
> sudo tee /etc/locale.gen <<<"en_US.UTF-8 UTF-8"
> sudo tee /etc/locale.conf <<<"LANG=en_US.UTF-8"
> sudo locale-gen en_US.UTF-8
> EOF
> ```

Then, install Docker with the command:

```bash
# From the Raspberry Pi:
curl -fsSL https://get.docker.com | sudo bash
sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker
```

`k3s` [requires the memory cgroup
v2](https://github.com/k3s-io/k3s-ansible/issues/179#issuecomment-1065685291).
To enable it, add the following flags to `/boot/cmdline.txt`:

```text
cgroup_memory=1 cgroup_enable=memory
```

Also install `vim` and `jq`:

```bash
# From the Raspberry Pi:
sudo apt install -y vim jq
```

Finally, install `k3d`, `helm`, and `kubectl`:

```bash
# From the Raspberry Pi:
curl -Ls https://raw.githubusercontent.com/rancher/k3d/main/install.sh | bash
curl -Ls https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```

### Booth: Set up the tunnel between the Internet and the Raspberry Pi

We want to expose the print-your-cert UI on the Internet at
<https://print-your-cert.cert-manager.io>. To do that, we use a f1-micro VM on
GCP and use Caddy to terminate the TLS connections and to forward the
connections to the Raspberry Pi's Tailscale IP.

```text
https://print-your-cert.cert-manager.io
              |
              |
              v  35.241.231.131 (eth0)
    +------------------------+
    |  VM "print-your-cert"  |
    |    Caddy + Tailscale   |
    +------------------------+
              |  100.106.168.42 (tailscale0)
              |
              |
              |
              v  100.85.65.38 (tailscale0)
    +-------------------+
    |       Pi          |
    |                   |
    |     :8080 (UI)    |
    +-------------------+
```

Before creating the VM, you will need to get access to the GCP project
`cert-manager-general`. You can get access by being a maintainer on the
cert-manager project and requesting to be added to the GCP project.

Then, you will need to make sure you are logged into Tailscale (see one of the
previous sections).

To create the VM `print-your-cert`, you can use the following command:

> [!NOTE]
>
> Use the GCP zone closest to the KubeCon venue. The examples below use
> `europe-west1-c` (Belgium) since the venue was in Paris (I didn't pick Paris
> as it doesn't have f1-micro VMs).

> [!NOTE]
>
> Find out the latest debian image by running:
>
> ```bash
> gcloud compute images list | grep debian
> ```

```shell
# From your laptop:
gcloud compute firewall-rules create allow-tailscale \
    --project cert-manager-general \
    --network default \
    --action allow \
    --direction ingress \
    --rules udp:41641 \
    --source-ranges 0.0.0.0/0
gcloud compute instances create print-your-cert \
    --project cert-manager-general \
    --network default \
    --machine-type=f1-micro \
    --image-family=debian-12 \
    --image-project=debian-cloud \
    --can-ip-forward \
    --boot-disk-size=10GB \
    --zone=europe-west1-c
```

Then, copy-paste the IP into the print-your-cert.cert-manager.io zone:

1. Copy the IP:

   ```bash
   IP=$(gcloud compute instances describe print-your-cert \
       --project cert-manager-general \
       --zone=europe-west1-c --format json \
         | jq -r '.networkInterfaces[].accessConfigs[] | select(.type=="ONE_TO_ONE_NAT") | .natIP')
   ```

2. The zone `print-your-cert.cert-manager.io` is a delegated zone meant for print-your-cert.
   Anyone in the Google group <team-cert-manager@jetstack.io> can update the `A` record:

   ```bash
   gcloud dns record-sets update --project cert-manager-io \
     --zone print-your-cert-cert-manager-io \
     --type=A --ttl=300 print-your-cert.cert-manager.io --rrdatas=$IP
   ```

Then, install Tailscale and make sure IP forwarding is enabled on the VM:

```sh
gcloud compute ssh --project cert-manager-general --zone=europe-west1-c print-your-cert -- 'curl -fsSL https://tailscale.com/install.sh | sh'
gcloud compute ssh --project cert-manager-general --zone=europe-west1-c print-your-cert -- \
    "sudo perl -ni -e 'print if \!/^net.ipv4.ip_forward=1/d' /etc/sysctl.conf; \
     sudo tee -a /etc/sysctl.conf <<<net.ipv4.ip_forward=1; \
     sudo sysctl -w net.ipv4.ip_forward=1"
```

We found that the default-http and default-https now require tags to be set:

```bash
gcloud compute instances add-tags print-your-cert --project cert-manager-general --zone europe-west1-c --tags http-server
gcloud compute instances add-tags print-your-cert --project cert-manager-general --zone europe-west1-c --tags https-server
```

Then, run the following. Click the link that shows and log into Tailscale using
"Login with GitHub", and then select the Tailnet `cert-manager.org.github`.

```sh
gcloud compute ssh --project cert-manager-general --zone=europe-west1-c print-your-cert -- sudo tailscale up
```

Finally, install Caddy as a systemd unit (these commands are inspired from [the
official guide](https://caddyserver.com/docs/install#debian-ubuntu-raspbian)):

```sh
gcloud compute ssh --project cert-manager-general --zone=europe-west1-c print-your-cert -- bash <<'EOF'
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy
EOF
```

```sh
gcloud compute ssh --project cert-manager-general --zone=europe-west1-c print-your-cert -- bash <<'EOF'
sudo tee /etc/caddy/Caddyfile <<CADDY
print-your-cert.cert-manager.io:443 {
        reverse_proxy 100.85.65.38:8080
}
CADDY
sudo systemctl restart caddy.service
EOF
```

### Prerequisite: install k3s on the Raspberry Pi

This prerequisite is useful both for local development and for running the
experiment on the Raspberry Pi.

First, install the following tools on the Raspberry Pi:

- [Docker](https://docs.docker.com/engine/install/debian/),
- [K3d](https://k3d.io/stable/#install-current-latest-release),
- [Helm](https://helm.sh/docs/intro/install/).

The first step is to create a cluster with a cert-manager issuer:

<a id="print-your-cert-ca"></a>

```sh
# From the Raspberry Pi:
k3d cluster create --k3s-arg="--tls-san=$(tailscale ip -4)@server:*"
```

### Booth: Configure kubectl on your laptop to access the Raspberry Pi's cluster

First, make sure you can SSH to the Raspberry Pi over Tailscale in one of the
above sections.

Then, run the following:

```sh
ssh pi 'k3d kubeconfig get -a | sed "s/0.0.0.0/$(tailscale ip -4)/g"' >/tmp/kc \
  && KUBECONFIG=/tmp/kc:$HOME/.kube/config k config view --flatten >kc \
  && mv kc ~/.kube/config
```

### Booth: Install cert-manager and the issuers on the Raspberry Pi

First install [`age`](https://age-encryption.org/) to be able to decrypt the
secrets:

```sh
# From your laptop:
brew install age
```

Install cert-manager:

```sh
# From the Raspberry Pi:
helm repo add jetstack https://charts.jetstack.io --force-update
helm upgrade --install -n cert-manager cert-manager jetstack/cert-manager \
  --create-namespace --set installCRDs=true
```

Then, apply the ClusterIssuer:

```sh
kubectl apply -f root_issuer_prod.yaml
kubectl apply -f cluster_issuer.yaml
```

Then, decrypt the root CA. The passphrase is available in the Venafi 1Password
in the `cert-manager-team` vault.

```bash
# From your laptop:
age -d root-print-your-cert-ca.yaml.age >root-print-your-cert-ca.yaml
scp root-print-your-cert-ca.yaml pi:
```

Finally, apply the decrypted root CA secret:

```bash
# From the Raspberry Pi:
kubectl apply -f root-print-your-cert-ca.yaml
```

### Booth: Run the UI on the Raspberry Pi

The UI doesn't run in Kubernetes (just because...). It runs as a container. It
is a simple Go binary that serves an HTML site. Its container image name is
`ghcr.io/cert-manager/print-your-cert-ui:latest`.

The following command will build the image on your laptop (faster than on the
Pi) and then load the image on the Pi:

```sh
# From your laptop:
KO_DOCKER_REPO=ghcr.io/cert-manager/print-your-cert-ui ko build . --platform linux/arm64 --tarball print-your-cert-ui.tar --push=false --bare
ssh pi docker load <print-your-cert-ui.tar
```

Now, ssh into the Raspberry Pi and launch the UI:

```sh
# From your laptop.
ssh pi docker rm -f print-your-cert-ui
ssh pi 'kubectl get secret -n cert-manager root-print-your-cert-ca --template="{{index .data \"tls.crt\" | base64decode}}" | tee ca.crt'
ssh pi docker run -d --restart=always --name print-your-cert-ui --net=host -v '/home/pi/.kube/config:/home/nonroot/.kube/config' -v '/home/pi/ca.crt:/home/nonroot/ca.crt' ghcr.io/cert-manager/print-your-cert-ui:latest --issuer print-your-cert-ca --issuer-kind ClusterIssuer --listen 0.0.0.0:8080 --guestbook-ca /home/nonroot/ca.crt
```

> [!NOTE]
>
> We don't actually push the image to GHCR. We just load it directly to the Raspberry Pi.

> [!NOTE]
>
> Why not skip buildx and use `ko` instead? That's because the base images that
> `ko` relies on don't support the Rasberry Pi's `arm64/v8` architecture:
>
> ```console
> $ crane manifest cgr.dev/chainguard/static | jq -r '.manifests[].platform | "\(.os)/\(.architecture)"'
> linux/amd64
> linux/arm
> linux/arm64
> linux/ppc64le
> linux/s390x
> ```

### Booth: Running the printer controller on the Raspberry Pi

The printer controller is a simple Bash script (yeah, not Go). It doesn't run in
Kubernetes just because it makes it easier to hot-reload everything on the
booth. `ghcr.io/cert-manager/print-your-cert-controller:latest` is the container
image name.

Make sure that the k3s cluster is running that cert-manager is installed. If
not, follow the section [Prerequisite: install k3s on the Raspberry
Pi](#prerequisite-install-k3s-on-the-raspberry-pi).

You may need to install Qemu if you are on Linux:

```bash
# From your laptop, only on Linux:
sudo apt install -y qemu qemu-user-static
```

Then, create a buildx builder:

```bash
docker buildx create --name mybuilder --use
```

> [!NOTE]
>
> If it says "docker: 'buildx' is not a docker command", you may need to install
> `buildx` manually. On macOS, you can do it with the following command:
>
> ```bash
> brew install docker-buildx
> mkdir -p ~/.docker/cli-plugins/
> ln -sfn $(brew --prefix)/opt/docker-buildx/bin/docker-buildx ~/.docker/cli-plugins/docker-buildx
> ```

Then, build the image on your desktop (faster than on the Pi) and then push it
to the Pi.

```sh
# From your laptop:
docker buildx build -f Dockerfile.controller --platform linux/arm64 \
  -t ghcr.io/cert-manager/print-your-cert-controller:latest \
  -o type=docker,dest=print-your-cert-controller.tar .
ssh pi docker load <print-your-cert-controller.tar
```

> [!NOTE]
>
> We don't push the image to GHCR. We just load it directly on the Pi.

Now, SSH into the Raspberry Pi and launch the controller:

```sh
ssh pi sudo chmod a+r ~/.kube/config
ssh pi docker rm -f print-your-cert-controller
ssh pi docker run -d --restart=always --name print-your-cert-controller --privileged -v /dev/bus/usb:/dev/bus/usb -v /home/pi/.kube/config:/root/.kube/config --net=host ghcr.io/cert-manager/print-your-cert-controller:latest
```

You can also run the "debug" printer UI (brother_ql_web) if you want to make
sure that the printer works:

```sh
ssh pi docker run -d --restart=always --name brother_ql_web \
  --privileged -v /dev/bus/usb:/dev/bus/usb \
  -p 0.0.0.0:8013:8013 ghcr.io/cert-manager/print-your-cert-controller:latest brother_ql_web
```

### Booth: Running the guestbook on a VM

The VM that runs the guestbook is managed by `tofu` and is defined in
[`booth.tf`](https://github.com/cert-manager/infrastructure/blob/main/gcp/booth.tf).

> [!NOTE]
>
> TBD: document <https://litestream.io/> that we use for the sqlite backups.

First, you will need to connect to the Raspberry Pi's cluster to be able to
create the guestbook certificate. You can do that by running the following:

```sh
# From your laptop:
ssh pi kubectl apply -f - --wait <guestbook/certificate.yaml
ssh pi kubectl get secret -n cert-manager root-print-your-cert-ca -ojson \
  | jq -r '.data."tls.crt" | @base64d' >ca.crt
ssh pi kubectl get secret -n cert-manager guestbook-tls -ojson \
  | jq -r '.data."tls.crt" | @base64d' >tls.crt
ssh pi kubectl get secret -n cert-manager guestbook-tls -ojson \
  | jq -r '.data."tls.key" | @base64d' >tls.key
```

Copy the root CA that you decrypted in one of the previous steps:

```bash
gcloud compute scp --project cert-manager-general --zone=europe-west1-c  \
  ca.crt tls.crt tls.key guestbook:.
gcloud compute ssh --project cert-manager-general --zone=europe-west1-c guestbook -- \
  sudo mkdir -p /var/guestbook
gcloud compute ssh --project cert-manager-general --zone=europe-west1-c guestbook -- \
  sudo mv ca.crt tls.crt tls.key /var/guestbook
```

Finally, build and push:

```bash
GOARCH=amd64 GOOS=linux go build -C guestbook .
gcloud compute scp --project cert-manager-general --zone=europe-west1-c  \
  guestbook/guestbook test:.
gcloud compute ssh --project cert-manager-general --zone=europe-west1-c guestbook -- \
  sudo install guestbook /usr/bin
```

Then, run the following to create the systemd service:

> [!NOTE]
>
> If guestbook has never run on this machine, you will first need to run:
>
> ```bash
> gcloud compute ssh --project cert-manager-general --zone=europe-west1-c guestbook -- \
>   mkdir /var/guestbook
> gcloud compute ssh --project cert-manager-general --zone=europe-west1-c guestbook -- \
>   guestbook -init-db -db-path /var/guestbook/guestbook.sqlite
> ```

Finally, run the following to create the systemd service:

```bash
gcloud compute ssh --project cert-manager-general --zone=europe-west1-c guestbook -- bash <<'EOF'
sudo tee /usr/lib/systemd/system/guestbook.service <<'SVC'
[Unit]
Description=cert-manager Booth Guestbook
After=network.target

[Service]
ExecStart=/usr/bin/guestbook -ca-cert /var/guestbook/ca.crt -tls-chain /var/guestbook/tls.crt -tls-key /var/guestbook/tls.key -db-path /var/guestbook/guestbook.sqlite -listen :443 -readonly-listen-insecure :80 -autocert-dir /var/guestbook -prod

StandardOutput=journal
StandardError=journal
Type=simple
Restart=always

[Install]
WantedBy=multi-user.target
SVC
sudo systemctl daemon-reload
EOF
```

## Local development

### Local development on the UI

You will need Go.

First, follow the steps in [Prerequisite: install k3s on the
Raspberry](#prerequisite-install-k3s-on-the-raspberry-pi) to install k3s on your
local machine (it is the same as for the Raspberry Pi).

Then, you will need to create a ClusterIssuer:

```sh
kubectl apply -f root_issuer_dev.yaml --wait
kubectl apply -f cluster_issuer.yaml --wait
kubectl get secret -n cert-manager root-print-your-cert-ca -ojson | jq -r '.data."tls.crt" | @base64d' >ca.crt
```

Then, you can run the UI:

```sh
go run . --issuer=print-your-cert-ca --issuer-kind=ClusterIssuer \
  -guestbook-ca=ca.crt -guestbook-url=guestbook.print-your-cert.cert-manager.io:9090
```

### Local development on the guestbook

First, you will need to make sure the domains
`guestbook.print-your-cert.cert-manager.io` and
`readonly-guestbook.print-your-cert.cert-manager.io` point to your machine:

```bash
sudo perl -ni -e 'print if !/ guestbook.print-your-cert.cert-manager.io$/' /etc/hosts
sudo tee -a /etc/hosts <<<"127.0.0.1 guestbook.print-your-cert.cert-manager.io"
sudo perl -ni -e 'print if !/ readonly-guestbook.print-your-cert.cert-manager.io$/' /etc/hosts
sudo tee -a /etc/hosts <<<"127.0.0.1 readonly-guestbook.print-your-cert.cert-manager.io"
```

Then:

```bash
kubectl apply -f root_issuer_dev.yaml --wait
kubectl apply -f cluster_issuer.yaml --wait
kubectl apply -f guestbook/certificate.yaml --wait
```

Grab the root CA and the certificate to serve the guestbook:

```bash
kubectl get secret -n cert-manager root-print-your-cert-ca -ojson | jq -r '.data."tls.crt" | @base64d' >ca.crt
kubectl get secret -n cert-manager guestbook-tls -ojson | jq -r '.data."tls.crt" | @base64d' >tls.crt
kubectl get secret -n cert-manager guestbook-tls -ojson | jq -r '.data."tls.key" | @base64d' >tls.key
go run -C guestbook . -init-db
go run -C guestbook . -ca-cert ../ca.crt -tls-chain ../tls.crt -tls-key ../tls.key -listen :9090
```

To use the guestbook, make sure the UI is running locally too (see above).

1. Go to the UI at <http://localhost:8080>.
2. Submit an email.
3. Wait for the cert to be ready and click "Sign the guestbook".
4. Go to the guestbook at <https://readonly-guestbook.print-your-cert.cert-manager.io:9090>. To get a "star" instead of a red cross, you need to use curl (or any HTTP client) to sign the book.
5. To get a star instead of a cross, go back to the page in (1), click "Download cert bundle tar".
6. Open a shell session and go to your `~/Downloads` folder.
7. Run:
   ```bash
   tar xf cert-manager-bundle.tar
   curl -k https://guestbook.print-your-cert.cert-manager.io/write \
     --cacert ca.crt --cert chain.pem --key pkey.pem \
     -X POST --data-urlencode message@/dev/stdin \
   <<EOF
   Excellent job, Ash!
   EOF
   ```
8. Go back to <https://readonly-guestbook.print-your-cert.cert-manager.io:9090>
   to see the guestbook. Now, you should see a ⭐!

### Local development on the controller (that creates PNGs and prints them)

The controller is made in two pieces: `pem-to-png` that turns one PEM into two
PNGs, and `print-your-cert-controller` that runs `pem-to-png` every time a
certificate object in Kubernetes becomes ready.

#### `pem-to-png`

pem-to-png is what turns a PEM file into two PNGs: `front.png` and `back.png`.

```sh
brew install imagemagick qrencode step svn
brew install homebrew/cask-fonts/font-open-sans
brew install homebrew/cask-fonts/font-dejavu
```

To run it, for example:

```sh
./pem-to-png <<EOF
-----BEGIN CERTIFICATE-----
MIICXDCCAgOgAwIBAgIQdPaTuGSUDeosii4dbdLBgTAKBggqhkjOPQQDAjAnMSUw
IwYDVQQDExxUaGUgY2VydC1tYW5hZ2VyIG1haW50YWluZXJzMB4XDTIyMDUxNjEz
MDkwMFoXDTIyMDgxNDEzMDkwMFowLDEqMCgGA1UEAwwhZm9vIGJhciBmb28gYmFy
IDxmb28uYmFyQGJhci5mb28+MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAtmGM5lil9Vw/y5LhpgO8t5gSb5oUo+Dp5vWw0Z5C7rjvifi0/eD9MbVFkxb+
+hmOaaNCVgqDUio1OBOZyL90KzdnGW7nz1fRM2KCNrDF5Y1mO7uv1ZTZa8cVBjF6
7KjFuNkvvHp74m65bKwXeCHXJBmO3Z1FH8hudICU74+Nl6tyjlMOsTHv+LY0jPfm
AtO6eR+Ef/HvgzwsjKds12vdlRCdHSS6u5zlrZZxF3zTO7YuAM7mN8Wbjq94Ycpg
sJ5ssNOtMu9FwZtPGQDHPaQyVQ86FfjhmMi1IUOUAAGwh/QRv8ksX+OupHTNdH06
WmIDCaGBjWFgPkwicavMZgZG3QIDAQABo0EwPzAOBgNVHQ8BAf8EBAMCBaAwDAYD
VR0TAQH/BAIwADAfBgNVHSMEGDAWgBQG5XQnDhOUa748L9H7TWZN2avluTAKBggq
hkjOPQQDAgNHADBEAiBXmyJ24PTG76pEyq6AQtCo6TXEidqJhsmK9O5WjGBw7wIg
aPbcFI5iMMgfPGEATH2AGGutZ6MlxBmwhEO7pAkqhQc=
-----END CERTIFICATE-----
EOF
```

#### Testing the printer

Test that `brother_lp` works over USB on Pi:

```shell=sh
convert -size 230x30 -background white -font /usr/share/fonts/TTF/OpenSans-Regular.ttf -pointsize 25 -fill black -gravity NorthWest caption:"OK." -flatten example.png
brother_ql --model QL-820NWB --printer usb://0x04f9:0x209d print --label 62 example.png
```

#### Testing pem-to-png

```shell=sh
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -utf8 -subj "/CN=Maël Valais <mael@vls.dev>/O=Jetstack" -reqexts v3_req -extensions v3_ca -out ca.crt
step certificate create "CN=Foo Bar <foo@bar.com>" foo.crt foo.key --ca ca.crt --ca-key ca.key --password-file /dev/null
pem-to-png <foo.crt
timg pem-to-png.png
read
brother_ql --model QL-820NWB --printer usb://0x04f9:0x209d print --label 62 pem-to-png.png
```

## Troubleshooting

### From the CLI: `usb.core.USBError: [Errno 13] Access denied (insufficient permissions)`

Run:

```bash
# From the Raspberry Pi.
sudo tee /etc/udev/rules.d/99-brother-ql.rules <<EOF
SUBSYSTEM=="usb", ATTR{idVendor}=="04f9", ATTR{idProduct}=="209d", MODE="0666"
EOF
```

Then, reload the udev rules:

```bash
# From the Raspberry Pi.
sudo udevadm trigger
```

Then, unplug and replug the printer.

### From the CLI: `usb.core.USBError: [Errno 16] Resource busy`

On the Pi (over SSH), when running `brother_ql` with the following command:

```bash
docker run --privileged -v /dev/bus/usb:/dev/bus/usb -it --rm ghcr.io/cert-manager/print-your-cert-ui:latest brother_ql
```

you may hit the following message:

```text
usb.core.USBError: [Errno 16] Resource busy
```

I found that two reasons lead to this message:

1. The primary reason is that libusb-1.0 is installed on the host (on the
   Pi, that's Debian) and needs to be removed, and replaced with
   libusb-0.1. You can read more about this in
   <https://github.com/pyusb/pyusb/issues/391>.
2. A second reason is that the label settings aren't correct (e.g., you
   have select the black/red tape but the black-only tape is installed in
   the printer).

### From the web UI: `No such file or directory: '/dev/usb/lp1'`

This happened when the printer was disconnected.
