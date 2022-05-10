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
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/mail"
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
	listen            = flag.String("listen", "127.0.0.1:8080", "Allows you to specify the address and port to listen on.")
	kubeconfigContext = flag.String("context", "", "Allows you to specify the context to use in the kubeconfig file.")
	kubeconfig        = flag.String("kubeconfig", "", "Allows you to specify the path to the kubeconfig file.")
	namespace         = flag.String("namespace", "default", "Allows you to specify the namespace to use when creating the certificates.")
	issuer            = flag.String("issuer", "", "Allows you to specify the issuer to use when creating the certificates. The issuer must be in the same namespace as the namespace given with --namespace.")
)

// Config attempts to load the in-cluster config and falls back to using
// the local kube config in order to run out-of-cluster.
//
// The context is only useful for the local kube config. If context is left
// empty, the default context of the local kube config is used.
//
// The kubeconfig argument lets you specify the path to a kubeconfig file.
func Config(kubeconfig, context string) (cfg *rest.Config, err error) {
	cfg, err = rest.InClusterConfig()
	if err != nil {
		log.Printf("Using the local kubeconfig since we are not in a pod")
		rule := clientcmd.NewDefaultClientConfigLoadingRules()
		if kubeconfig != "" {
			rule.ExplicitPath = kubeconfig
		}
		apiCfg, err := rule.Load()
		if err != nil {
			return nil, fmt.Errorf("error loading kubeconfig: %v", err)
		}
		cfg, err = clientcmd.NewDefaultClientConfig(*apiCfg, &clientcmd.ConfigOverrides{
			CurrentContext: context,
		}).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("error loading kube config for context: %v", err)
		}
	} else {
		log.Printf("In-cluster config found")
	}

	cfg.UserAgent = fmt.Sprintf("print-your-cert")
	return cfg, nil
}

//go:embed *.html
var content embed.FS
var tmpl = template.Must(template.ParseFS(content, "*.html"))

func hello() func(http.ResponseWriter, *http.Request) {
	cfg, err := Config(*kubeconfig, *kubeconfigContext)
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

	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.Error(w, "404 not found.", http.StatusNotFound)
			return
		}

		switch r.Method {
		case "GET":

			personName := r.URL.Query().Get("name")
			email := r.URL.Query().Get("email")

			// Happily return early if the name or email haven't been
			// provided yet.
			if personName == "" || email == "" {
				tmpl.ExecuteTemplate(w, "get_landing.html", getLandingHTMLData{Name: personName, Email: email, Error: "To get your certificate, fill in your name and email."})
				log.Printf("GET: the user has given an empty name %q or an empty email %q", personName, email)
				return
			}

			if !valid(email) {
				tmpl.ExecuteTemplate(w, "get_landing.html", getLandingHTMLData{Name: personName, Email: email, Error: "The email is invalid."})
				log.Printf("GET: the user %q has given an invalid email %q", personName, email)
				return
			}

			// The email mael@vls.dev is transformed to mael-vls.dev so
			// that we can use it as a "name" in Kubernetes. We don't
			// expect any clashes since this project is meant to be used
			// just for the duration of KubeCon EU 2022.
			certName := strings.ReplaceAll(email, "@", "-")
			cert, err := cmclient.CertmanagerV1().Certificates(*namespace).Get(r.Context(), certName, metav1.GetOptions{})
			switch {
			case k8serrors.IsNotFound(err):
				// Create the Certificate.
				cert, err = cmclient.CertmanagerV1().Certificates(*namespace).Create(r.Context(), &certmanagerv1.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name: certName,
					},
					Spec: certmanagerv1.CertificateSpec{
						CommonName: personName + " <" + email + ">",
						SecretName: certName,
						IssuerRef: cmmetav1.ObjectReference{
							Name: *issuer,
							Kind: "Issuer",
						},
					},
				}, metav1.CreateOptions{})
				if err != nil {
					tmpl.ExecuteTemplate(w, "get_landing.html", getLandingHTMLData{Name: personName, Email: email, Error: "There was an error creating your certificate."})
					log.Printf("GET: issue while creating the Certificate named %s in namespace %s for '%s <%s>' in Kubernetes: %v", certName, *namespace, personName, email, err)
					return
				}

				tmpl.ExecuteTemplate(w, "get_landing.html", getLandingHTMLData{Name: personName, Email: email, Message: "A certificate was successfully requested. Reload to see the progress."})
				log.Printf("GET: successfully created a certificate named %s in namespace %s for '%s <%s>' in Kubernetes", certName, *namespace, personName, email)
				return
			case err != nil:
				tmpl.ExecuteTemplate(w, "get_landing.html", getLandingHTMLData{Name: personName, Email: email, Error: "Failed getting the Certificate in Kubernetes."})
				log.Printf("GET: while getting the Certificate %s in namespace %s in Kubernetes: %v", certName, *namespace, err)
				return
			}

			// Success: we found the Certificate in Kubernetes. Let us see
			// if it is ready.

			cond := apiutil.GetCertificateCondition(cert, "Ready")
			if cond == nil || cond.Status != "True" {
				tmpl.ExecuteTemplate(w, "get_landing.html", getLandingHTMLData{Name: personName, Email: email, Message: "Your certificate is not ready yet. Reload to see the progress."})
				log.Printf("GET: the requested certificate %s in namespace %s is not ready yet", certName, *namespace)
				return
			}

			// Let's show the user the Certificate.
			secret, err := kclient.CoreV1().Secrets("default").Get(r.Context(), cert.Spec.SecretName, metav1.GetOptions{})
			if err != nil {
				tmpl.ExecuteTemplate(w, "get_landing.html", getLandingHTMLData{Name: personName, Email: email, Error: "A certificate already exists, but the Secret does not exist."})
				log.Printf("GET: the requested certificate %s in namespace %s exists, but the Secret %s does not", certName, *namespace, cert.Spec.SecretName)
				return
			}

			// Let's show the user the Certificate. First, parse the X.509
			// certificate from the Secret.
			certPem, ok := secret.Data["tls.crt"]
			if !ok {
				tmpl.ExecuteTemplate(w, "get_landing.html", getLandingHTMLData{Name: personName, Email: email, Error: "Internal issue with the stored certificate in Kubernetes."})
				log.Printf("GET: the requested certificate %s in namespace %s exists, but the Secret %s does not contain a key 'tls.crt'", certName, *namespace, cert.Spec.SecretName)
				return
			}

			// Parse the certificate.
			certBlock, _ := pem.Decode(certPem)
			x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
			if err != nil {
				tmpl.ExecuteTemplate(w, "get_landing.html", getLandingHTMLData{Name: personName, Email: email, Error: "Internal issue with parsing the issued certificate when parsing it."})
				log.Printf("GET: the requested certificate %s in namespace %s exists, but the Secret %s contains in its tls.crt field an invalid PEM certificate", certName, *namespace, cert.Spec.SecretName)
				return
			}

			// Let's show the user the Certificate.
			certificateHTMLData := certificateToHTML(x509Cert)
			err = tmpl.ExecuteTemplate(w, "get_landing.html", getLandingHTMLData{Name: personName, Email: email, Certificate: certificateHTMLData})
			if err != nil {
				tmpl.ExecuteTemplate(w, "get_landing.html", getLandingHTMLData{Name: personName, Email: email, Error: "An unexpected error happened."})
				log.Printf("GET: failure while executing the template for get_landing.html: %v", err)
				return
			}
		case "POST":
			// Let's mark the certificate as "printable" in Kubernetes.
			err := r.ParseForm()
			if err != nil {
				tmpl.ExecuteTemplate(w, "post_printing.html", postPrintingHTMLData{Error: "Failed parsing the POST form."})
				log.Printf("POST: while parsing the form: %v", err)
				return
			}

			email := r.Form.Get("email")
			personName := r.Form.Get("name")

			if email == "" || personName == "" {
				tmpl.ExecuteTemplate(w, "post_printing.html", postPrintingHTMLData{Name: personName, Email: email, Error: "No email address provided."})
				log.Printf("POST: no email address provided")
				return
			}

			if !valid(email) {
				tmpl.ExecuteTemplate(w, "post_printing.html", postPrintingHTMLData{Name: personName, Email: email, Error: "The email is invalid."})
				log.Printf("GET: the user %q has given an invalid email %q", personName, email)
				return
			}

			certName := strings.ReplaceAll(email, "@", "-")

			// Add the annotation "print: true" to the certificate.
			cert, err := cmclient.CertmanagerV1().Certificates(*namespace).Get(r.Context(), certName, metav1.GetOptions{})
			if err != nil {
				tmpl.ExecuteTemplate(w, "post_printing.html", postPrintingHTMLData{Name: personName, Email: email, Error: "This email has not been used to create a certificate previously."})
				log.Printf("POST: the email %q has not been used to create a certificate previously", email)
				return
			}

			if cert.ObjectMeta.Annotations == nil {
				cert.ObjectMeta.Annotations = make(map[string]string)
			}
			cert.ObjectMeta.Annotations["print"] = "true"
			_, err = cmclient.CertmanagerV1().Certificates(*namespace).Update(r.Context(), cert, metav1.UpdateOptions{})
			if err != nil {
				tmpl.ExecuteTemplate(w, "post_printing.html", postPrintingHTMLData{Name: personName, Email: email, Error: "Could not trigger the print of the certificate."})
				log.Printf("POST: could not trigger the print of the certificate %s in namespace %s: %v", certName, *namespace, err)
				return
			}

			// Done!
			tmpl.ExecuteTemplate(w, "post_printing.html", postPrintingHTMLData{Name: personName, Email: email})
			log.Printf("POST: the certificate %s in namespace %s was added the annotation print:true", certName, *namespace)

		default:
			fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
		}
	}
}

type getLandingHTMLData struct {
	Name        string
	Email       string
	Certificate certificateHTMLData
	Error       string
	Message     string
}

type postPrintingHTMLData struct {
	Name  string
	Email string
	Error string
}

type certificateHTMLData struct {
	PublicKeyAlgorithm string
	Serial             string
	Subject            string
	Issuer             string
	NotBefore          string
	NotAfter           string
}

func certificateToHTML(cert *x509.Certificate) certificateHTMLData {
	data := certificateHTMLData{
		PublicKeyAlgorithm: getPublicKeyAlgorithm(cert.PublicKeyAlgorithm, cert.PublicKey),
		Serial:             cert.SerialNumber.String(),
		Subject:            cert.Subject.CommonName,
		Issuer:             cert.Issuer.CommonName,
		NotBefore:          cert.NotBefore.Format(time.RFC3339),
		NotAfter:           cert.NotAfter.Format(time.RFC3339),
	}

	return data
}

func main() {
	flag.Parse()

	if *issuer == "" {
		log.Fatal("Error: you must provide an issuer name with --issuer.")
	}

	http.HandleFunc("/", hello())

	fmt.Printf("Listening on http://" + *listen + "\n")
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
