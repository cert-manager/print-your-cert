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

// Get the value of "asn1" in eg "https://example.com/?asn1=some_value". Note
// that it is already URL decoded. We just have to re-add the headers.

function getAsn1() {
  var asn1 = params.asn1; // Example: "MIIDBzCCAe%2Bg...GLMQswCQYD%0A"
  if (!asn1) {
    throw new Error("the query parameter 'asn1' is missing");
  }

  // Since the base64 part of the PEM-encoded certificate is expected by
  // everyone to be wrapped at 76 chars (instead of a long line), let's re-wrap
  // it to 76 chars. Solution copied from
  // https://stackoverflow.com/questions/14484787.
  asn1 = wordWrap(asn1, 76);

  const pem =
    "-----BEGIN CERTIFICATE-----\n" + asn1 + "-----END CERTIFICATE-----\n";

  var cert;
  try {
    cert = new x509.X509Certificate(pem);
  } catch (e) {
    throw new Error(
      "the query parameter 'asn1' doesn't contain the base64 part of the PEM-encoded certificate"
    );
  }

  console.log(cert);

  return cert;
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
