const params = new Proxy(new URLSearchParams(window.location.search), {
  get: (searchParams, prop) => searchParams.get(prop),
});

// A PEM certificate looks like this:
//
//   -----BEGIN CERTIFICATE-----
//   MIIDBzCCAe+gAwIBAgIJAOjyPj/8QWbTMBQUAMIGLMQswCQYD
//   ...
//   -----END CERTIFICATE-----
//
// Since the certificate has to be encoded in base64, we need to remove the
// -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- lines to reduce the
// size.
//
// We use the query parameter "asn1" and give it the base64 and URL encoded PEM
// content. For example, given the PEM above, we remove the headers, and since
// it is already base64, we just need to URL encode it. It looks like this:
//
//   ?asn1=MIIDBzCCAe%2BgAwIBAgIJAOjyPj%2F8QWbTMBQUAMIGLMQswCQYD%0A
//
// Example of an actual URL:
//
//   https://cert-manager.github.io/print-your-cert/?asn1=MIICXDCCAgOgAwIBAgIQdPaTuGSUDeosii4dbdLBgTAKBggqhkjOPQQDAjAnMSUwIwYDVQQDExxUaGUgY2VydC1tYW5hZ2VyIG1haW50YWluZXJzMB4XDTIyMDUxNjEzMDkwMFoXDTIyMDgxNDEzMDkwMFowLDEqMCgGA1UEAwwhZm9vIGJhciBmb28gYmFyIDxmb28uYmFyQGJhci5mb28%2BMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtmGM5lil9Vw%2Fy5LhpgO8t5gSb5oUo%2BDp5vWw0Z5C7rjvifi0%2FeD9MbVFkxb%2B%2BhmOaaNCVgqDUio1OBOZyL90KzdnGW7nz1fRM2KCNrDF5Y1mO7uv1ZTZa8cVBjF67KjFuNkvvHp74m65bKwXeCHXJBmO3Z1FH8hudICU74%2BNl6tyjlMOsTHv%2BLY0jPfmAtO6eR%2BEf%2FHvgzwsjKds12vdlRCdHSS6u5zlrZZxF3zTO7YuAM7mN8Wbjq94YcpgsJ5ssNOtMu9FwZtPGQDHPaQyVQ86FfjhmMi1IUOUAAGwh%2FQRv8ksX%2BOupHTNdH06WmIDCaGBjWFgPkwicavMZgZG3QIDAQABo0EwPzAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH%2FBAIwADAfBgNVHSMEGDAWgBQG5XQnDhOUa748L9H7TWZN2avluTAKBggqhkjOPQQDAgNHADBEAiBXmyJ24PTG76pEyq6AQtCo6TXEidqJhsmK9O5WjGBw7wIgaPbcFI5iMMgfPGEATH2AGGutZ6MlxBmwhEO7pAkqhQc%3D
//
// To check that a given ?asn1= query value works:
//
//   echo "MIIDBzCCA...LMQswCQYD%0A" | urldecode | base64 -d | openssl asn1parse -inform DER

// The func getAsn1 gets the value of the query parameter "asn1" in
// "https://example.com/?asn1=some_value".
function getAsn1() {
  var base64der = params.asn1; // Example: "MIIDBzCCAe%2Bg...GLMQswCQYD%0A"
  if (!base64der) {
    throw new Error("the query parameter 'asn1' is missing");
  }

  try {
    // x509.X509Certificate can accept a base64 URL-encoded DER-encoded
    // certificate, so we don't need to do any decoding.
    cert = new x509.X509Certificate(base64der);
    return cert;
  } catch (e) {
    throw new Error(
      "the query parameter 'asn1' doesn't contain the Base64URL of the DER-encoded certificate: " +
        e
    );
  }
}

// Copied from https://stackoverflow.com/a/14487422
function wordWrap(str, maxWidth) {
  var newLineStr = "\n";
  done = false;
  res = "";
  while (str.length > maxWidth) {
    found = false;
    // Inserts new line at first whitespace of the line
    for (i = maxWidth - 1; i >= 0; i--) {
      if (testWhite(str.charAt(i))) {
        res = res + [str.slice(0, i), newLineStr].join("");
        str = str.slice(i + 1);
        found = true;
        break;
      }
    }
    // Inserts new line at maxWidth position, the word is too long to wrap
    if (!found) {
      res += [str.slice(0, maxWidth), newLineStr].join("");
      str = str.slice(maxWidth);
    }
  }

  return res + str;
}

function testWhite(x) {
  var white = new RegExp(/^\s$/);
  return white.test(x.charAt(0));
}

async function validate(cert, urlRootCAPEM) {
  if (!cert) {
    throw new Error("the certificate is null");
  }

  var pem = await fetch(urlRootCAPEM)
    .then((resp) => resp.text())
    .catch((err) => {
      throw new Error("failed to fetch the root certificate: " + err);
    });

  var root = new x509.X509Certificate(pem);

  console.log("root=", root);
  console.log("cert=", cert);

  return await cert.verify(
    { publicKey: await root.publicKey.export(crypto), signatureOnly: false },
    crypto
  );
}
