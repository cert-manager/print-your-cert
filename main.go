package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"embed"
	_ "embed"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/mail"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmversioned "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	listen      = flag.String("listen", "127.0.0.1:8080", "Allows you to specify the address and port to listen on.")
	kubeconfig  = flag.String("kubeconfig", "", "Allows you to specify the path to the kubeconfig file.")
	namespace   = flag.String("namespace", "default", "Allows you to specify the namespace to use when creating the certificates.")
	issuer      = flag.String("issuer", "", "Name of the issuer resource to use when creating the certificates. When --issuer-kind=Issuer is used (which is the default), the issuer resource must be in the same namespace as in --namespace.")
	issuerKind  = flag.String("issuer-kind", "Issuer", "This flag can be used to select the namespaced 'Issuer', or to select an 'external' issuer, e.g., 'AWSPCAIssuer'.")
	issuerGroup = flag.String("issuer-group", "cert-manager.io", "This flag allows you to give a different API group when using an 'external' issuer, e.g., 'awspca.cert-manager.io'.")
	inCluster   = flag.Bool("in-cluster", false, "Use the in-cluster kube config to connect to Kubernetes. Use this flag when running in a pod.")
)

const (
	AnnotationPrint  = "print"
	ConditionPrinted = "Printed"
)

// Config attempts to load the in-cluster config and falls back to using
// the local kube config in order to run out-of-cluster.
//
// The context is only useful for the local kube config. If context is left
// empty, the default context of the local kube config is used.
//
// The kubeconfig argument lets you specify the path to a kubeconfig file.
func Config(inCluster bool, kubeconfig string) (cfg *rest.Config, err error) {
	if inCluster {
		cfg, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
		cfg.UserAgent = fmt.Sprintf("print-your-cert")
		return cfg, nil
	}

	log.Printf("Using the local kubeconfig. Note that you can use --in-cluster when running in a pod.")
	rule := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rule.ExplicitPath = kubeconfig
	}
	apiCfg, err := rule.Load()
	if err != nil {
		return nil, fmt.Errorf("error loading kubeconfig: %v", err)
	}
	cfg, err = clientcmd.NewDefaultClientConfig(*apiCfg, nil).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("error loading kube config for context: %v", err)
	}

	cfg.UserAgent = fmt.Sprintf("print-your-cert")
	return cfg, nil
}

//go:embed static/js/*.js
//go:embed static/*.css
//go:embed static/images/*
var static embed.FS

//go:embed *.html
var templates embed.FS
var tmpl = template.Must(template.ParseFS(templates, "*.html"))

// When the user lands on the website for the first time, they will get a
// blank form prompting them to fill in their name and email to receive a
// certificate.
//
//	GET / HTTP/2.0
//
// When the user submits their name and email, the user is redirected to
// the same landing page, except it remember the name and email using query
// parameters:
//
//	GET /?name=NAME&email=EMAIL HTTP/2.0
//
// For debugging purposes, one can set the query parameter "debug" to
// "true" (or any other value), and more information about the Kubernetes
// Certificate resource gets displayed:
//
//	GET /?name=NAME&email=EMAIL&debug=true HTTP/2.0
func landingPage(kclient kubernetes.Interface, cmclient cmversioned.Interface) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.Error(w, fmt.Sprintf("The path %s contains is expected to be /.", r.URL.Path), http.StatusNotFound)
			return
		}

		// We want to display the count of printed certificates.
		result, err := cmclient.CertmanagerV1().Certificates(*namespace).List(r.Context(), metav1.ListOptions{})
		if err != nil {
			w.WriteHeader(500)
			tmpl.ExecuteTemplate(w, "landing.html", landingPageData{Refresh: 5, Error: "Issue with getting the number of certificate already printed. Retrying in 5 seconds."})
			log.Printf("GET /: while listing the certificates that have Printed=True: %v", err)
			return
		}
		var printed, pending int
		for _, c := range result.Items {
			if isAlreadyPrinted(&c) {
				printed++
			}
			if isPendingPrint(&c) {
				pending++
			}
		}

		if r.Method != "GET" {
			http.Error(w, fmt.Sprintf("The method %s is not allowed on %s", r.Method, r.URL.Path), http.StatusMethodNotAllowed)
			return
		}

		personName := r.URL.Query().Get("name")
		email := r.URL.Query().Get("email")

		// Happily return early if the name or email haven't been
		// provided yet.
		if personName == "" && email == "" {
			w.WriteHeader(400)
			tmpl.ExecuteTemplate(w, "landing.html", landingPageData{Name: personName, Email: email, CountPrinted: printed, CountPending: pending, Message: "Welcome! To get your certificate, fill in your name and email."})
			return
		}

		// Let's check that both the email and name have been entered.
		if personName == "" && email != "" || personName != "" && email == "" {
			w.WriteHeader(400)
			tmpl.ExecuteTemplate(w, "landing.html", landingPageData{Name: personName, Email: email, CountPrinted: printed, CountPending: pending, Message: "Please fill in both the email and name."})
			log.Printf("GET /: the user has given an empty name %q or an empty email %q", personName, email)
			return
		}

		if !valid(email) {
			w.WriteHeader(400)
			tmpl.ExecuteTemplate(w, "landing.html", landingPageData{Name: personName, Email: email, CountPrinted: printed, CountPending: pending, Error: "The email is invalid."})
			log.Printf("GET /: the user %q has given an invalid email %q", personName, email)
			return
		}

		// Check that the "Name <email@foo.bar>" is under the common
		// name limit of 64 bytes. Hopefully, that should be enough for
		// most people, but let's help them out in case their name and
		// email go above the limit.
		commonName := fmt.Sprintf("%s <%s>", personName, email)
		if len(commonName) > 64 {
			msg := fmt.Sprintf("Oops, the common name formed using your name and email (%s) counts as %d bytes which goes beyond the common name limit of 64 bytes. Could you try abbreviating some part of your name and try again?", commonName, len(commonName))
			w.WriteHeader(400)
			tmpl.ExecuteTemplate(w, "landing.html", landingPageData{Name: personName, Email: email, CountPrinted: printed, CountPending: pending, Error: msg})
			log.Printf("GET /: the user %q has given a common name %q that is above the 64 bytes limit", personName, commonName)
			return
		}

		// The email mael@vls.dev is transformed to mael-vls.dev so
		// that we can use it as a "name" in Kubernetes. We don't
		// expect any clashes since this project is meant to be used
		// just for the duration of KubeCon EU 2022.
		certName := emailToCertName(email)

		_, err = cmclient.CertmanagerV1().Certificates(*namespace).Create(r.Context(), &certmanagerv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name: certName,
			},
			Spec: certmanagerv1.CertificateSpec{
				CommonName: commonName,
				Duration:   &metav1.Duration{Duration: 3 * 3650 * 24 * time.Hour}, // 30 years.
				SecretName: certName,
				IssuerRef: cmmetav1.ObjectReference{
					Name:  *issuer,
					Kind:  *issuerKind,
					Group: *issuerGroup,
				},
				PrivateKey: &certmanagerv1.CertificatePrivateKey{
					Algorithm: certmanagerv1.ECDSAKeyAlgorithm,
					Size:      256,
				},
			},
		}, metav1.CreateOptions{})

		switch {
		case k8serrors.IsAlreadyExists(err):
			w.WriteHeader(409)
			tmpl.ExecuteTemplate(w, "landing.html", landingPageData{Name: personName, Email: email, CountPrinted: printed, CountPending: pending, DuplicateURL: fmt.Sprintf("/certificate?certName=%s", certName)})
			log.Printf("GET /: cannot create due to duplicate certificate name %s", certName)
			return
		case err != nil:
			w.WriteHeader(500)
			tmpl.ExecuteTemplate(w, "landing.html", landingPageData{Name: personName, Email: email, CountPrinted: printed, CountPending: pending, Refresh: 5, Error: "There was an error creating your certificate. The page will be reloaded every 5 seconds until this issue is resolved."})
			log.Printf("GET /: issue while creating the Certificate named %s in namespace %s for '%s <%s>' in Kubernetes: %v", certName, *namespace, personName, email, err)
			return
		}

		// We don't display the certificate on this page. Instead, we do that in
		// the endpoint /certificate?email=...
		log.Printf("GET /: successfully created a certificate, redirecting to /certificate?certName=%s", certName)
		http.Redirect(w, r, r.Referer()+"/certificate?certName="+certName, http.StatusFound)
		tmpl.ExecuteTemplate(w, "landing.html", landingPageData{Error: "Redirecting..."})
	}
}

// When the user clicks the button "Print my certificate" on the landing
// page, this POST gets called.
//
// When the user clicks the button "Go back to my certificate", they are
// redirected to GET /.
//
//	POST /print HTTP/2.0
//	Content-Type: application/x-www-form-urlencoded
//	email=...&name=...
func printPage(kclient kubernetes.Interface, cmclient cmversioned.Interface) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/print" {
			http.Error(w, fmt.Sprintf("The path %s is expected to be /print", r.URL.Path), http.StatusNotFound)
			return
		}

		if r.Method != "POST" {
			http.Error(w, "Only the POST method is supported for the path /print.", http.StatusMethodNotAllowed)
			return
		}

		// Let's mark the certificate as "printable" in Kubernetes.
		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(400)
			tmpl.ExecuteTemplate(w, "after-print.html", printPageData{Error: "Failed parsing the POST form."})
			log.Printf("POST /: while parsing the form: %v", err)
			return
		}

		certName := r.Form.Get("certName")
		if certName == "" {
			http.Error(w, "The form is missing the 'certName' field.", http.StatusBadRequest)
			log.Printf("POST /: no 'certName' form parameter provided")
			return
		}

		// Add the annotation "print: true" to the certificate.
		cert, err := cmclient.CertmanagerV1().Certificates(*namespace).Get(r.Context(), certName, metav1.GetOptions{})
		if err != nil {
			w.WriteHeader(409)
			tmpl.ExecuteTemplate(w, "after-print.html", printPageData{CertName: certName, Error: "This email has not been used to create a certificate previously."})
			log.Printf("POST /: the certName %q has not been used to create a certificate previously", certName)
			return
		}

		if cert.ObjectMeta.Annotations == nil {
			cert.ObjectMeta.Annotations = make(map[string]string)
		}

		cert.ObjectMeta.Annotations[AnnotationPrint] = "true"
		_, err = cmclient.CertmanagerV1().Certificates(*namespace).Update(r.Context(), cert, metav1.UpdateOptions{})
		if err != nil {
			w.WriteHeader(500)
			tmpl.ExecuteTemplate(w, "after-print.html", printPageData{CertName: certName, Error: "Could not trigger the print of the certificate. Please go to the previous page and press the button again."})
			log.Printf("POST /: could not trigger the print of the certificate %s in namespace %s: %v", certName, *namespace, err)
			return
		}

		// Done!
		w.WriteHeader(200)
		tmpl.ExecuteTemplate(w, "after-print.html", printPageData{CertName: certName})
		log.Printf("POST /: the certificate %s in namespace %s was added the annotation print:true", certName, *namespace)
	}
}

func downloadPage(kclient kubernetes.Interface, cmclient cmversioned.Interface) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, fmt.Sprintf("Only the GET method is supported supported on the path %s.\n", r.URL.Path), http.StatusMethodNotAllowed)
			return
		}

		certName := r.URL.Query().Get("certName")
		if certName == "" {
			http.Error(w, "No 'certName' query parameter provided.", 400)
			log.Printf("GET /download: no 'certName' query parameter provided")
			return
		}

		cert, err := cmclient.CertmanagerV1().Certificates(*namespace).Get(r.Context(), certName, metav1.GetOptions{})
		switch {
		case k8serrors.IsNotFound(err):
			http.Error(w, "Certificate not found.", 404)
			log.Printf("GET /download: certificate %q not found", certName)
			return
		case err != nil:
			http.Error(w, "Error getting certificate.", 503)
			log.Printf("GET /download: error getting certificate %q: %v", certName, err)
			return
		}

		secret, err := kclient.CoreV1().Secrets("default").Get(r.Context(), cert.Spec.SecretName, metav1.GetOptions{})
		if err != nil {
			http.Error(w, "A certificate already exists, but the secret does not exist. Try again later.", 423)
			log.Printf("GET /download: the requested certificate %s in namespace %s exists, but the Secret %s does not.", certName, *namespace, cert.Spec.SecretName)
			return
		}

		certPem, ok := secret.Data["tls.crt"]
		if !ok {
			http.Error(w, "The Secret does not contain a certificate, try again later.", 423)
			tmpl.ExecuteTemplate(w, "certificate.html", certificatePageData{Error: "Internal issue with the stored certificate in Kubernetes."})
			log.Printf("GET /download: the requested certificate %s in namespace %s exists, but the Secret %s does not contain a key 'tls.crt'.", certName, *namespace, cert.Spec.SecretName)
			return
		}

		// Give the PEM-encoded certificate to the user.
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="cert.pem"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(certPem)))
		w.Write(certPem)
	}
}

var nameAndEmailRe = regexp.MustCompile(`^(.*) <(.*)>$`)

func parseNameAndEmail(nameAndEmail string) (name, email string, _ error) {
	if nameAndEmail == "" {
		return "", "", errors.New("empty name and email")
	}

	parts := nameAndEmailRe.FindStringSubmatch(nameAndEmail)
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return "", "", fmt.Errorf("the name-and-email string '%s' does not follow the format 'John Doe <john@doe.co>', the regex '%v' parsed this: %v", emailToCertName(email), nameAndEmailRe.String(), strings.Join(parts, ", "))
	}

	return parts[1], parts[2], nil
}

// After the user clicks "Get your certificate" on the landing page, and if the
// certificate was successfully created, the user is redirected to /certificate
// to "visualize" their certificate and to print it. This page is similar to the
// one on GitHub Pages (https://cert-manager.github.io/print-your-cert?asn1=...)
// except that is also shows whether the certificate was printed or not.
//
//	GET /certificate?certName=mael-vls.dev HTTP/2.0
func certificatePage(kclient kubernetes.Interface, cmclient cmversioned.Interface) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/certificate" {
			http.Error(w, fmt.Sprintf("The path %s contains is expected to be /.", r.URL.Path), http.StatusNotFound)
			return
		}

		if r.Method != "GET" {
			http.Error(w, fmt.Sprintf("The method %s is not allowed on %s", r.Method, r.URL.Path), http.StatusMethodNotAllowed)
			return
		}

		certName := r.URL.Query().Get("certName")

		// Happily return early if the name or email haven't been
		// provided yet.
		if certName == "" {
			w.WriteHeader(400)
			err := tmpl.ExecuteTemplate(w, "certificate.html", certificatePageData{Error: "You need to provide the query parameter '?certName=...' with a non-empty value in the URL."})
			if err != nil {
				log.Printf("GET /certificate: 400: while executing the template: %v", err)
			}
			return
		}

		cert, err := cmclient.CertmanagerV1().Certificates(*namespace).Get(r.Context(), certName, metav1.GetOptions{})
		switch {
		case k8serrors.IsNotFound(err):
			w.WriteHeader(404)
			err = tmpl.ExecuteTemplate(w, "certificate.html", certificatePageData{Error: fmt.Sprintf("The certificate named '%s' does not exist.", certName)})
			if err != nil {
				log.Printf("GET /certificate: 404: while executing the template: %v", err)
			}
			log.Printf("GET /certificate: 404: the certificate named %s in namespace %s was not found in Kubernetes: %v", certName, *namespace, err)
			return
		case err != nil:
			w.WriteHeader(500)
			err = tmpl.ExecuteTemplate(w, "certificate.html", certificatePageData{Refresh: 5, Error: "Failed getting the certificate resource in Kubernetes. The page will be reloaded every 5 seconds until this issue is resolved."})
			if err != nil {
				log.Printf("GET /certificate: 500: while executing the template: %v", err)
			}
			log.Printf("GET /certificate: 500: while getting the Certificate %s in namespace %s in Kubernetes: %v", certName, *namespace, err)
			return
		}

		debug := r.URL.Query().Get("debug") != ""
		debugMsg := ""
		if debug {
			debugMsg += fmt.Sprintf("The annotation 'print' is set to '%s'.\nThe certificate conditions are:", cert.Annotations[AnnotationPrint])
			for _, cond := range cert.Status.Conditions {
				debugMsg += fmt.Sprintf("\n  %s: %s (%s: %s)", cond.Type, cond.Status, cond.Reason, cond.Message)
			}
		}

		// Parse the email and personName out of the common personName. The common personName is
		// of the form 'John Doe <john@doe.io>'.
		personName, email, err := parseNameAndEmail(cert.Spec.CommonName)
		if err != nil {
			w.WriteHeader(500)
			tmpl.ExecuteTemplate(w, "certificate.html", certificatePageData{Error: "There is an issue with the certificate's common name. Please let know the cert-manager booth staff.", Debug: debugMsg})
			if err != nil {
				log.Printf("GET /certificate 500: while executing the template: %v", err)
			}
			log.Printf("GET /certificate: 500: certificate %s: %v", certName, err)
			return
		}

		// Success: we found the Certificate in Kubernetes. Let us see
		// if it is ready.
		if !isReady(cert) {
			w.WriteHeader(423)
			err = tmpl.ExecuteTemplate(w, "certificate.html", certificatePageData{Name: personName, Email: email, CertName: certName, CanPrint: false, MarkedToBePrinted: false, AlreadyPrinted: false, Refresh: 5, Message: "Your certificate is being issued by cert-manager. The page will reload automatically in 5 seconds.", Debug: debugMsg})
			if err != nil {
				log.Printf("GET /certificate: 423: while executing the template: %v", err)
			}
			log.Printf("GET /certificate: 423: the requested certificate %s in namespace %s is not ready yet.", certName, *namespace)
			return
		}

		// Let's show the user the Certificate.
		secret, err := kclient.CoreV1().Secrets("default").Get(r.Context(), cert.Spec.SecretName, metav1.GetOptions{})
		if err != nil {
			w.WriteHeader(423)
			err = tmpl.ExecuteTemplate(w, "certificate.html", certificatePageData{Name: personName, Email: email, CertName: certName, Refresh: 5, Error: "A certificate already exists, but the Secret does not exist; the page will be reloaded in 5 seconds until this issue is resolved.", Debug: debugMsg})
			if err != nil {
				log.Printf("GET /certificate: 423: while executing the template: %v", err)
			}
			log.Printf("GET /certificate: 423: the requested certificate %s in namespace %s exists, but the Secret %s does not.", certName, *namespace, cert.Spec.SecretName)
			return
		}

		// Let's show the user the Certificate. First, parse the X.509
		// certificate from the Secret.
		certPem, ok := secret.Data["tls.crt"]
		if !ok {
			w.WriteHeader(423)
			err = tmpl.ExecuteTemplate(w, "certificate.html", certificatePageData{Name: personName, Email: email, CertName: certName, Refresh: 5, Error: "Internal issue with the stored certificate in Kubernetes. The page will be reloaded every 5 seconds until this issue is resolved.", Debug: debugMsg})
			if err != nil {
				log.Printf("GET /certificate: 423: while executing the template: %v", err)
			}
			log.Printf("GET /certificate: 423: the requested certificate %s in namespace %s exists, but the Secret %s does not contain a key 'tls.crt'.", certName, *namespace, cert.Spec.SecretName)
			return
		}

		// Parse the certificate.
		certBlock, _ := pem.Decode(certPem)
		x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			w.WriteHeader(500)
			err = tmpl.ExecuteTemplate(w, "certificate.html", certificatePageData{Name: personName, Email: email, CertName: certName, Error: "Internal issue with parsing the issued certificate when parsing it.", Debug: debugMsg})
			if err != nil {
				log.Printf("GET /certificate: 500: while executing the template: %v", err)
			}
			log.Printf("GET /certificate: 500: the requested certificate %s in namespace %s exists, but the Secret %s contains in its tls.crt field an invalid PEM certificate", certName, *namespace, cert.Spec.SecretName)
			return
		}

		alreadyPrinted := isAlreadyPrinted(cert)
		pendingPrint := isPendingPrint(cert)

		canPressPrintButton := !pendingPrint && !alreadyPrinted

		// Let's show the user the Certificate.
		certificateHTMLData := certificateToHTML(x509Cert)

		log.Printf("GET /certificate: 200: certificate %s in namespace %s was found", certName, *namespace)
		err = tmpl.ExecuteTemplate(w, "certificate.html", certificatePageData{Name: personName, Email: email, CertName: certName, Certificate: &certificateHTMLData, CanPrint: canPressPrintButton, MarkedToBePrinted: pendingPrint, AlreadyPrinted: alreadyPrinted, Debug: debugMsg})
		if err != nil {
			log.Printf("GET /certificate: 200: while executing the template: %v", err)
		}
	}
}

func isPendingPrint(cert *certmanagerv1.Certificate) bool {
	return markedToBePrinted(cert) && !isAlreadyPrinted(cert)
}

// When the user goes to /list, they see a list of the previously submitted
// name and emails.
//
//	GET /list HTTP/2.0
func listPage(kclient kubernetes.Interface, cmclient cmversioned.Interface) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, fmt.Sprintf("Only the GET method is supported supported on the path %s.\n", r.URL.Path), http.StatusMethodNotAllowed)
			return
		}

		refreshStr := r.URL.Query().Get("refresh")
		if refreshStr == "" {
			http.Redirect(w, r, "/list?refresh=5", 301)
			return
		}

		refresh, err := strconv.Atoi(refreshStr)
		if err != nil {
			http.Error(w, "Invalid refresh parameter. It should be an integer greater or equal to 0.", 400)
			log.Printf("GET /list: 400: invalid refresh parameter %q, should be >=0", refreshStr)
			return
		}

		// Let's get the list of certificates.
		certs, err := cmclient.CertmanagerV1().Certificates(*namespace).List(r.Context(), metav1.ListOptions{})
		if err != nil {
			w.WriteHeader(500)
			err = tmpl.ExecuteTemplate(w, "list.html", listPageData{Error: "Internal error: cannot list the last certificates that were printed."})
			if err != nil {
				log.Printf("GET /list: 500: while executing the template: %v", err)
			}
			log.Printf("GET /list: 500: %v", err)
			return
		}

		// We want the newest certificates first.
		sort.Slice(certs.Items, func(i, j int) bool {
			return certs.Items[i].CreationTimestamp.Time.After(certs.Items[j].CreationTimestamp.Time)
		})

		var certsOut []certificateItem
		for _, cert := range certs.Items {
			personName, email, err := parseNameAndEmail(cert.Spec.CommonName)
			if err != nil {
				log.Printf("GET /list: while listing certificates, the certificate %s was skipped: %v", cert.Name, err)
				continue
			}
			certsOut = append(certsOut, certificateItem{
				Name:  personName,
				Email: email,
				State: stateOfCert(cert),
				Date:  cert.Status.NotBefore.Time,
			})
		}

		// We also want to display the count of printed certificates.
		var printed, pending int
		for _, c := range certs.Items {
			if isAlreadyPrinted(&c) {
				printed++
			}
			if isPendingPrint(&c) {
				pending++
			}
		}

		err = tmpl.ExecuteTemplate(w, "list.html", listPageData{Certificates: certsOut, Refresh: refresh, CountPrinted: printed, CountPending: pending})
		if err != nil {
			log.Printf("GET /list: 200: while executing the template: %v", err)
		}
	}
}

func markedToBePrinted(cert *certmanagerv1.Certificate) bool {
	return cert.Annotations[AnnotationPrint] == "true"
}

func isAlreadyPrinted(cert *certmanagerv1.Certificate) bool {
	cond := apiutil.GetCertificateCondition(cert, ConditionPrinted)
	alreadyPrinted := cond != nil && cond.Status == "True"
	return alreadyPrinted
}

func isReady(cert *certmanagerv1.Certificate) bool {
	cond := apiutil.GetCertificateCondition(cert, "Ready")
	isReady := cond != nil && cond.Status == "True"
	return isReady
}

func emailToCertName(email string) string {
	certName := strings.ReplaceAll(email, "@", "-")
	certName = strings.ReplaceAll(certName, "_", "-")
	certName = strings.ReplaceAll(certName, " ", "")
	certName = strings.ToLower(certName)
	return certName
}

func stateOfCert(cert certmanagerv1.Certificate) StateCert {
	switch {
	case isAlreadyPrinted(&cert):
		return StatePrinted
	case isReady(&cert):
		return StateReady
	default:
		return StateUnknown
	}
}

type landingPageData struct {
	Name              string                   // Optional.
	Email             string                   // Optional.
	Certificate       *certificateTemplateData // Optional.
	Error             string                   // Optional.
	Message           string                   // Optional.
	CanPrint          bool                     // Optional.
	AlreadyPrinted    bool                     // Optional.
	MarkedToBePrinted bool                     // Optional.
	Debug             string                   // Optional.
	Refresh           int                      // Optional. In seconds.
	CountPrinted      int                      // Mandatory.
	CountPending      int                      // Mandatory.
	DuplicateURL      string
}

type printPageData struct {
	CertName string // Mandatory.
	Error    string // Optional.
}

type StateCert string

var (
	StateUnknown      StateCert = "Unknown"
	StateCreated      StateCert = "CertificateCreated"
	StateReady        StateCert = "CertificateReady"
	StatePendingPrint StateCert = "PrintPending"
	StatePrinted      StateCert = "Printed"
)

type listPageData struct {
	Certificates []certificateItem // Optionnal.
	Error        string            // Optionnal.
	Refresh      int               // Optionnal. In seconds.
	CountPrinted int               // Mandatory.
	CountPending int               // Mandatory.
}

type certificateItem struct {
	Position int
	Name     string
	Email    string
	Date     time.Time
	State    StateCert
}

type certificateTemplateData struct {
	PublicKeyAlgorithm string
	Serial             string
	Subject            string
	Issuer             string
	NotBefore          string
	NotAfter           string
}

// For certificate.html.
type certificatePageData struct {
	Name              string                   // Optional.
	Email             string                   // Optional.
	CertName          string                   // Mandatory.
	Certificate       *certificateTemplateData // Optional.
	Error             string                   // Optional.
	Message           string                   // Optional.
	CanPrint          bool                     // Optional.
	AlreadyPrinted    bool                     // Optional.
	MarkedToBePrinted bool                     // Optional.
	Debug             string                   // Optional.
	Refresh           int                      // Optional. In seconds.
}

func certificateToHTML(cert *x509.Certificate) certificateTemplateData {
	data := certificateTemplateData{
		PublicKeyAlgorithm: getPublicKeyAlgorithm(cert.PublicKeyAlgorithm, cert.PublicKey),
		Serial:             cert.SerialNumber.String(),
		Subject:            cert.Subject.CommonName,
		Issuer:             cert.Issuer.CommonName,
		NotBefore:          cert.NotBefore.Format(time.RFC3339),
		NotAfter:           cert.NotAfter.Format(time.RFC3339),
	}

	return data
}

func addCachingHeaders(h http.Header) {
	h.Set("Vary", "Accept-Encoding")
	h.Set("Cache-Control", "public, max-age=7776000")
}

func main() {
	flag.Parse()

	if *issuer == "" {
		log.Fatal("Error: you must provide an issuer name with --issuer.")
	}

	cfg, err := Config(*inCluster, *kubeconfig)
	if err != nil {
		log.Fatal(err)
	}

	cmclient, err := cmversioned.NewForConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}

	kclient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", landingPage(kclient, cmclient))
	http.HandleFunc("/print", printPage(kclient, cmclient))
	http.HandleFunc("/download", downloadPage(kclient, cmclient))
	http.HandleFunc("/list", listPage(kclient, cmclient))
	http.HandleFunc("/certificate", certificatePage(kclient, cmclient))
	fileserver := http.FileServer(http.FS(static))
	fileserver = http.StripPrefix("/", fileserver)
	http.Handle("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addCachingHeaders(w.Header())
		fileserver.ServeHTTP(w, r)
	}))

	fmt.Printf("Listening on http://" + *listen + ".\n")
	if err := http.ListenAndServe(*listen, nil); err != nil {
		log.Fatal(err)
	}
}

func valid(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// Copied over from smallstep's certinfo package.
func getPublicKeyAlgorithm(algorithm x509.PublicKeyAlgorithm, key interface{}) string {
	var params string
	switch pk := key.(type) {
	case *ecdsa.PublicKey:
		params = pk.Curve.Params().Name
	case *rsa.PublicKey:
		params = strconv.Itoa(pk.Size() * 8)
	case *dsa.PublicKey:
		params = strconv.Itoa(pk.Q.BitLen())
	case ed25519.PublicKey:
		params = strconv.Itoa(len(pk) * 8)
	default:
		params = "unknown"
	}
	return fmt.Sprintf("%s %s", algorithm, params)
}
