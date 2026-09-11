# HTTP Message Signer (RFC 9421)

A PHP 8.1+ library for signing and verifying HTTP messages (requests or responses) per [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421).

At the time of writing, this was the closest thing to a reference implementation of RFC9421 that could be found for the PHP platform and one of only a handful of implementations with the full range of support for Structured-Fields and signing algorithms specified in that document.

This is a fork of https://github.com/arduent/HTTP-Message-Signer (aka composer package quantificant/http-message-signer).

Supports:
- PSR-7 HTTP message requests/responses
- Automatically verify body digest (content-digest header) -- if present
- Algorithm support:
    - RFC-9421
        - 'rsa-v1_5-sha256'
        - 'rsa-v1_5-sha512'
        - 'rsa-pss-sha512'
        - 'ed25519'
        - 'hmac-sha256'
        - 'ecdsa-p256-sha256'
        - 'ecdsa-p384-sha384'
    - JWT
        - 'RS256'
        - 'RS384'
        - 'RS512'
        - 'EdDSA'
        - 'HS256'
        - 'HS384'
        - 'HS512'
        - 'ES256'
        - 'ES384'
        - 'ES512'
    - OpenSSL
        - 'Ed25519'
    - Other
        - 'rsa-v1_5-sha384'
        - 'ecdsa-p512-sha512'
        - 'hmac-sha384'
        - 'hmac-sha512'
  
## Note

Please report issues. Thanks. Tested on PHP 8.4, should run fine on 8.1+

## Installation

```bash
composer require macgirvin/http-message-signer
```

## Notes

An instance of a PSR-7 MessageInterface is passed to the sign and verify functions. This can be a RequestInterface or a ResponseInterface. Typically, this will be a RequestInterface. If your web framework does not supply a pre-populated PSR7-compatible request interface, you can quickly generate one using 

```php
use GuzzleHttp\Psr7\ServerRequest;

$request = ServerRequest::fromGlobals();
```

This would typically be used to verify a message.

If your project uses URL rewriting (such as Apache's 'mod_rewrite'), you may have difficulties verifying some request parameters using a PSR7 request generated using ServerRequest::fromGlobals() as shown here. In that case, you might wish instead to generate a minimal PSR7 Request Message which is populated from the original request URI and which is not affected by URL re-writing:

```php
use GuzzleHttp\Psr7\Request;

// Generate PSR7 request from current HTTP request, which is NOT
// affected by the use of Apache mod-rewrite or equivalent.
 
function createRequest(string $baseurl)
{
    /**
    * $baseurl for your site e.g. 'https://example.com'
    */
    
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $input = file_get_contents('php://input');
    }
    
    $headers = [];
    if (isset($_SERVER['CONTENT_TYPE'])) {
      $headers['content-type'] = $_SERVER['CONTENT_TYPE'];
    }
    if (isset($_SERVER['CONTENT_LENGTH'])) {
      $headers['content-length'] = $_SERVER['CONTENT_LENGTH'];
    }
    foreach ($_SERVER as $k => $v) {
      if (str_starts_with($k, 'HTTP_')) {
          $field = str_replace('_', '-', strtolower(substr($k, 5)));
          $headers[$field] = $v;
      }
    }
    
    return new Request(
      $_SERVER['REQUEST_METHOD'],
        $baseurl . $_SERVER['REQUEST_URI']),
        $headers,
        $input ?? null
      );
 }
```

To sign a message, install the composer package guzzlehttp/psr7 (or any other PSR7 compliant interface) and create an instance of `Request` or `Response` as appropriate.

## Usage

```php
use HttpSignature\HttpMessageSigner;
use HttpSignature\UnProcessableSignatureException;
use GuzzleHttp\Psr7\Request;

$request = new Request(
    'GET',
    'https://api.example.com/resource?bat&baz=3',
    [
        'Host' => 'api.example.com',
        'Date' => gmdate('D, d M Y H:i:s T'),
        ...additional headers
    ]
);

$signer = (new HttpMessageSigner())
    ->setPrivateKey($privateKey) // only needed for signing
    ->setPublicKey($publicKey)   // only needed for verifying
    ->setKeyId('https://example.com/dave#rsaKey')  // required when signing
    ->setAlgorithm('rsa-v1_5-sha256')    // typically required when signing
    ->setCreated(time())            // recommended
    ->setExpires(time() + 300)      // optional, enforced
    ->setNonce('xJJ9;ro.3*kidney`') // optional one-time token, uniqueness SHOULD be checked/enforced by the calling application
    ->setTag('fediverse')           // optional app profile name
    ->setSignatureId('sig1')        // optional, default is sig1
    
try {   
    $request = $signer->signRequest('("@method" "@path" "host" "date")', $request);
}
catch (UnProcessableSignatureException $exception) {
    $whatHappened = $exception->getMessage();
}
try {    
    $isValid = $signer->verifyRequest($request);
} catch (UnProcessableSignatureException $exception) {
    $isValid = false;
    $whatHappened = $exception->getMessage();
}
```

See full examples in `/tests`.

## Structured Fields

RFC9421 makes heavy use of HTTP Structured Fields (RFC8941/RFC9651). 

The signRequest() method takes a structured InnerList of components to sign. These may be headers or derived fields.
The string will look something like the following (where `...` represents additional components):

```
'("header1" "header2" "@method" ...)'
```

and may include modifier parameters. These are represented as

```
'("@query-param";name="foo" "header2";sf "header3" ...)'
```

Field names beginning with '@' are components derived from the HTTP request but may not be represented in the headers. Please review RFC9421 for precise definitions. 

Using the 'sf' parameter on a component will treat a signature component as a Structured Field when normalising the string. 

However, parsing arbitrary Structured Fields by adding the 'sf' parameter is likely to fail unless you know what `type` it is. A built-in table contains the type definition for a number of known stuctured header types. This list is probably incomplete. A method `addStructuredFieldTypes()` is available to add the type information so it can be successfully parsed. This takes an array with key of the lowercase header name and a value; which is one of 'list', 'innerlist', 'parameters, 'dictionary', 'item'. If the header name is in the list and the 'sf' modifier is used, the header will be parsed as the Structured Field type indicated.

If a Structured Field is declared as type 'dictionary'; it is suitable for use with the RFC9421 `key` parameter. Using this parameter will fail if the Structured Field type is unknown or has not been registered.

The signRequest() and verifyRequest() methods both use an instance of MessageInterface. In nearly all cases, this will be the RequestInterface. However, when signing responses, the default will be the ResponseInterface, and if components are required from the RequestInterface, the :req parameter must be added to the field definition. 

To sign or verify an HTTP Response, use a ResponseInterface as the provided `$interface`, and provide the RequestInterface in `$originalRequest`. This is optional but will allow the `req` modifier to work correctly when signing Responses.

## Known issues
Currently not implemented is the special handling of the `cookie` and `set-cookie` headers when using the `sf` modifier. For further information please see https://httpwg.org/http-extensions/draft-ietf-httpbis-retrofit.html and https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-22 (or later). It is planned to implement this once RFC6265bis is finalised as a new RFC.

There is currently no handling of Accept-Signature, as conflict negotiation depends largely on the requirements of the application. These can be parsed using functions in this library and its dependencies, but any conflict resolution is left to the calling application, which would need to perform the steps in RFC-9421:section 5.2 'Processing an Accept-Signature'. 

Currently, PEM keys are supported as per the RFC examples. JWT/JWK keys are not yet fully supported. A number of encryption libraries are being used to obtain coverage of the entire suite of supported algorithms under PHP, and their key format support varies dramatically.  

JWT/JWK algorithm identifiers are permitted for any of the supported algorithms. For instance, 'RS256' and 'rsa-v1_5-sha256' are inter-changeable, depending on your application requirements. 

Pull requests welcome. 

## License

BSD 3-Clause
