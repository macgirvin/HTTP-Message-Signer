<?php

namespace HttpSignature;

use Bakame\Http\StructuredFields\Dictionary;
use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\OuterList;
use Bakame\Http\StructuredFields\Parameters;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use phpseclib\Crypt\RSA;
use phpseclib3\Crypt\PublicKeyLoader;
use ParagonIE\EasyECC\EasyECC;
use ParagonIE\EasyECC\ECDSA\{PublicKey, SecretKey};


class HttpMessageSigner
{
    private string $keyId;
    private string $privateKey;
    private string $publicKey;
    private string $algorithm;
    private string $signatureId = 'sig1';
    private string $created = '';
    private string $expires = '';
    private string $nonce = '';
    private string $tag = '';

    private array $structuredFieldTypes = [];

    private $originalRequest;


    public function __construct()
    {
        $this->setStructuredFieldTypes((new StructuredFieldTypes())->getFields());
        return $this;
    }

    public function getHeaders($interface): array
    {
        $headers = [];
        foreach ($interface->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', $values);
        }
        return $headers;
    }


    /* PSR-7 interface to signing function */
    /**
     * @param string $coveredFields
     * @param MessageInterface $interface
     * @param RequestInterface|null $originalRequest
     * @return MessageInterface
     * @throws UnProcessableSignatureException
     */

    public function signRequest(string $coveredFields, MessageInterface $interface, ?RequestInterface $originalRequest = null): MessageInterface
    {
        $headers = $this->getHeaders($interface);
        if ($originalRequest) {
            $this->setOriginalRequest($originalRequest);
        }

        $signedHeaders = $this->sign(
            $headers,
            $coveredFields,
            $interface
        );

        foreach (['signature-input', 'signature'] as $header) {
            $interface = $interface->withHeader($header, $signedHeaders[$header]);
        }
        return $interface;
    }

    /* PSR-7 verify interface and also check body digest if included */
    /**
     * @param MessageInterface $interface
     * @param RequestInterface|null $originalRequest
     * @return bool
     *
     * @throws UnProcessableSignatureException
     */

    public function verifyRequest(MessageInterface $interface, ?RequestInterface $originalRequest = null): bool
    {
        $headers = [];
        if ($originalRequest) {
            $this->setOriginalRequest($originalRequest);
        }
        foreach ($interface->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', $values);
        }

        /* check the body digest if it's present */

        if (isset($headers['content-digest'])) {
            $body = (string)$interface->getBody();
            if (!$this->isBodyDigestValid($body, $headers['content-digest'])) {
                return false;
            }
        }

        return $this->verify($headers, $interface);
    }

    /**
     * check body digest
     *
     * From https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Digest
     * The algorithm used to create a digest of the message content. Only two registered digest algorithms are
     * considered secure: sha-512 and sha-256. The insecure (legacy) registered digest algorithms
     * are: md5, sha (SHA-1), unixsum, unixcksum, adler (ADLER32) and crc32c.
     */

    private function isBodyDigestValid(string $body, string $headerValue): bool
    {
        if (!preg_match('/sha-(.*?)=:(.*?):/', $headerValue, $matches)) {
            return false;
        }
        if (!in_array($matches[1], ['256', '512'], true)) {
            return false;
        }

        $algorithm = 'sha' . $matches[1];

        $expectedDigest = base64_decode($matches[2]);
        $actualDigest = hash($algorithm, $body, true);

        return hash_equals($expectedDigest, $actualDigest);
    }

    /**
     * @param array $headers
     * @param string $coveredFields
     *
     * Calculate the signature base from supplied components.
     * Declared public so it can also be used as a development function to peek into the internals of the exact things
     * that were signed and/or to test the internal results of data normalisation.
     */
    public function calculateSignatureBase(array $headers, string $coveredFields, $interface): array
    {
        $signatureComponents = [];
        $processedComponents = [];
        $dict = $this->parseStructuredDict($coveredFields);

        if ($dict->isNotEmpty()) {
            $coveredStructuredFields = $dict->__toString();
            $indices = $dict->indices();
            foreach ($indices as $index) {
                $member = $dict->getByIndex($index);
                if (!$member) {
                    throw new UnProcessableSignatureException('Index ' . $index . ' not found');
                }
                if (in_array($member, $processedComponents, true)) {
                    throw new UnProcessableSignatureException('Duplicate member found');
                }
                $processedComponents[] = $member;
                $signatureComponents[] = $this->canonicalizeComponent($member, $headers, $interface);
            }
        }

        $signatureInput = $coveredStructuredFields
            . ';keyid="' . $this->getkeyId()
            . '";alg="' . $this->getAlgorithm() . '"'
            . (($this->getCreated()) ? ';created=' . $this->getCreated() : '')
            . (($this->getExpires()) ? ';expires=' . $this->getExpires() : '')
            . (($this->getNonce()) ? ';nonce="' . $this->getNonce() . '"' : '')
            . (($this->getTag()) ? ';tag="' . $this->getTag() . '"' : '');

        /**
         * Always include @signature-params in the result.
         */
        $signatureComponents[] = '"@signature-params": ' . $signatureInput;

        $signatureBase = implode("\n", $signatureComponents);
        return [$signatureInput, $signatureBase];

    }

    public function sign(array $headers, string $coveredFields, MessageInterface $interface): array
    {
        [$signatureInput, $signatureBase] = $this->calculateSignatureBase($headers, $coveredFields, $interface);
        $signature = $this->createSignature($signatureBase);

        $headers['signature-input'] = $this->getSignatureId() . '=' . $signatureInput;
        $headers['signature'] = $this->getSignatureId() . '=:' . $signature . ':';

        return $headers;
    }

    public function verify(array $headers, $interface): bool
    {
        if (!isset($headers['signature-input'], $headers['signature'])) {
            return false;
        }
        $headers[] = 'signature-params';

        $sigInputDict = $this->parseStructuredDict($headers['signature-input']);

        $signatureComponents = [];

        if ($sigInputDict->isNotEmpty()) {
            $indices = $sigInputDict->indices();
            foreach ($indices as $index) {
                [$dictName, $members] = $sigInputDict->getByIndex($index);
                if ($members instanceof InnerList) {
                    $innerIndices = $members->indices();
                    foreach ($innerIndices as $innerIndex) {
                       $member = $members->getByIndex($innerIndex);
                       $signatureComponents[$dictName][] = $this->canonicalizeComponent($member, $headers, $interface);
                    }
                    $parameters = $this->extractParameters($members);
                    if ($parameters) {
                        foreach ($parameters as $key => $value) {
                            if (!in_array($key, ['created', 'expires', 'nonce', 'alg', 'keyid', 'tag'])) {
                                return false;
                            }
                        }
                    }
                    if (isset($parameters['expires'])) {
                        $expires = (int) $parameters['expires'];
                        if ($expires < time()) {
                            return false;
                        }
                        if (isset($parameters['created'])) {
                            $created = (int) $parameters['created'];
                            if ($created >= $expires) {
                                return false;
                            }
                        }
                    }
                }
            }
        }

        $sigDict = $this->parseStructuredDict($headers['signature']);

        foreach ($signatureComponents as $dictName => $dictComponents) {
            $namedSignatureComponents = $signatureComponents[$dictName];
            $signatureParamsStr = $sigInputDict[$dictName]->toHttpValue();
            $namedSignatureComponents[] = '"@signature-params": ' . $signatureParamsStr;
            $signatureBase = implode("\n", $namedSignatureComponents);
            if (!isset($sigDict[$dictName])) {
                return false;
            }

            $decodedSig = base64_decode(trim($sigDict[$dictName]->__toString(), ':'));
            return $this->verifySignature($signatureBase, $decodedSig, $parameters['alg'] ?? $this->getAlgorithm());
        }
        return false;
    }

    protected function extractParameters($field): array
    {
        $parameters = [];
        $fieldParams = $field->parameters();

        if ($fieldParams->isNotEmpty()) {
            $indices = $fieldParams->indices();
            foreach ($indices as $index) {
                [$name, $item] = $fieldParams->getByIndex($index);
                $parameters[$name] = $item->value();
            }
        }
        return $parameters;
    }

    private function canonicalizeComponent($field, array $headers, MessageInterface $interface): string
    {
        $fieldName = $field->value();
        $parameters = $this->extractParameters($field);
        if (isset($parameters['bs']) && isset($parameters['sf'])) {
            throw new UnProcessableSignatureException('Cannot use both bs and sf');
        }

        $whichRequest = $interface;
        $whichHeaders = $headers;
        if (isset($parameters['req'])) {
            if ($interface instanceof ResponseInterface) {
                $whichRequest = $this->getOriginalRequest();
                $whichHeaders = $this->getHeaders($whichRequest);
            } else {
                throw new UnProcessableSignatureException('missing request for req parameter');
            }
        }

        if (isset($parameters['tr'])) {
            $whichHeaders = $whichRequest->getTrailers();
        }

        [$name, $value] = $this->getFieldValue($fieldName, $whichRequest, $whichHeaders, $parameters);

        if (isset($parameters['bs'])) {
            $result = $name . ';bs: ';
            $values = $whichRequest->getHeader($fieldName);
            if (!$values) {
                return '';
            }
            if (!is_array($values)) {
                $values = [$values];
            }
            foreach ($values as $value) {
                $value = trim($value);
                $result .= ':' . base64_encode($value) . ':' . ', ';
            }
            return $values ? rtrim($result, ', ') : $result;
        }

        if (isset($parameters['sf'])) {
            $value = $this->applyStructuredField($name, $value);
            return $name . ';sf: ' . $value;
        }
        if (isset($parameters['key'])) {
            $childName = $parameters['key'];
            $value = $this->applySingleKeyValue($name, $childName, $value);
            return $name . ';key="' . $childName . '": ' . $value;
        }
        return $name . ': ' . $value;
    }

    private function getFieldValue($fieldName, MessageInterface $interface, $headers, $parameters ): array
    {
        if ($interface instanceof RequestInterface) {
            $value = match ($fieldName) {
                '@signature-params' => ['', ''],
                '@method' => ['"@method"', strtoupper($interface->getMethod())],
                '@authority' => ['"@authority"', $this->getNormalisedAuthority($interface)],
                '@scheme' => ['"@scheme"', strtolower($interface->getUri()->getScheme())],
                '@target-uri' => ['"@target-uri"', $interface->getUri()->getScheme() . '://' . $this->getNormalisedAuthority($interface)
                    . $interface->getUri()->getPath() . (($interface->getUri()->getQuery()) ? '?' . $interface->getUri()->getQuery() : '')],
                '@request-target' => ['"@request-target"', $interface->getRequestTarget()],
                '@path' => ['"@path"', $interface->getUri()->getPath()],
                '@query' => ['"@query"', $interface->getUri()->getQuery()],
                '@query-param' => $this->getQueryParam($interface, $parameters) ?? ['', ''],
                default => ['"' . $fieldName . '"', trim($headers[$fieldName] ?? '')],
            };
        }
        else {
            $value = match ($fieldName) {
                '@signature-params' => ['', ''],
                '@status' => ['"@status"', $interface->getStatusCode()],
                default => ['"' . $fieldName . '"', trim($headers[$fieldName] ?? '')],
            };
        }

        if(isset($parameters['req']))
            $value[0] .= ';req';

        return $value;
    }

    /**
     * $interface->getUri()->getAuthority() requires additional filtering for RFC-9421.
     * It must be lowercase and must not contain a port value.
     * @param MessageInterface $interface
     * @return string
     * @throws UnprocessableSignatureException
     */
    protected function getNormalisedAuthority(MessageInterface $interface): string
    {
        if (method_exists($interface, 'getUri')) {
            $authority = strtolower($interface->getUri()->getAuthority());
            $authority = explode(':', $authority);
            return $authority[0];
        }
        throw new UnprocessableSignatureException('Unable to extract authority from MessageInterface');
    }

    /**
     * @param string $query
     * @return array|null
     *
     * Should not use PHP's parse_str function here, as it has some issues with
     * spaces and dots in parameter names. The following function treats them as
     * opaque strings rather than as variable names.
     */
    private function parseQueryString(string $query): array|null
    {
        $result = [];

        if (!isset($query)) {
            return null;
        }

        $queryParams = explode('&', $query);
        foreach ($queryParams as $param) {
            // The '=' character is not required and indicates a boolean true value if unset.
            $element = explode('=', $param, 2);
            $result[urldecode($element[0])] = isset($element[1]) ? urldecode($element[1]) : '';
        }
        return $result;
    }

    /**
     * @param $parameters
     * @param $name
     * @return string|null
     *
     * Find one query parameter by name (which must be supplied as parameters in the covered field list).
     */
    private function getQueryParam($whichRequest, array $parameters): array
    {
        $queryString = $whichRequest->getUri()->getQuery();
        if ($queryString) {
            $queryParams = $this->parseQueryString($queryString);
            $fieldName = $parameters['name'];
            if ($fieldName) {
                return ['"_' . $fieldName . '_"', $queryParams[$fieldName] ? '"' . $queryParams[$fieldName] . '"' : ''];
            }
        }
        throw new UnProcessableSignatureException('Query string named parameter not set');
    }

    private function applyStructuredField(string $name, string $fieldValue): string
    {
        $type = $this->structuredFieldTypes[trim($name, '"')];
        switch ($type) {
            case 'list':
                $field = OuterList::fromHttpValue($fieldValue);
                break;
            case 'innerlist':
                $field = InnerList::fromHttpValue($fieldValue);
                break;
            case 'parameters':
                $field = Parameters::fromHttpValue($fieldValue);
                break;
            case 'dictionary':
                $field = Dictionary::fromHttpValue($fieldValue);
                break;
            case 'item':
                $field = Item::fromHttpValue($fieldValue);
                break;
            case 'url':
                return '"' . $fieldValue . '"';
            case 'date':
                return '@' . strtotime($fieldValue);
            case 'etag':
                $result = '';
                $list = explode(',', $fieldValue);
                foreach ($list as $item) {
                    if (str_starts_with(trim($item), 'W/')) {
                        $result .= substr(trim($item), 2) . '; w' . ', ';
                    } else {
                        $result .= trim($item) . ', ';
                    }
                }
                return rtrim($result, ', ');
            case 'cookie':
                // @TODO
            default:
                break;
        }
        if (!$field) {
            throw new UnProcessableSignatureException('Unknown or unregistered structured field type');
        }
        return $field->toHttpValue();
    }

    private function applySingleKeyValue(string $name, string $key, string $fieldValue): string
    {
        $type = $this->structuredFieldTypes[trim($name, '"')];
        if (empty($type) || $type === 'dictionary') {
            $dictionary = Dictionary::fromHttpValue($fieldValue);
            if ($dictionary->isNotEmpty() && isset($dictionary[$key])) {
                return $dictionary[$key]->toHttpValue();
            }
        }
        return '';
    }

    private function createSignature(string $data): string
    {
        $algorithm = $this->getAlgorithm();

        switch ($algorithm) {
            case 'RS256':
            case 'rsa-v1_5-sha256':
                return $this->rsa256Sign($data);
            case 'RS384':
            case 'rsa-v1_5-sha384':
                return $this->rsa384Sign($data);
            case 'RS512':
            case 'rsa-v1_5-sha512':
                return $this->rsa512Sign($data);
            case 'EdDSA':
            case 'Ed25519':
            case 'ed25519':
                return $this->ed25519Sign($data);
            case 'ES256':
            case 'ecdsa-p256-sha256':
                return $this->ecdsa256Sign($data);
            case 'ES384':
            case 'ecdsa-p384-sha384':
                return $this->ecdsa384Sign($data);
            case 'ES512':
            case 'ecdsa-p512-sha512':
                return $this->ecdsa512Sign($data);
            case 'HS256':
            case 'hmac-sha256':
                return base64_encode(hash_hmac('sha256', $data, $this->getPrivateKey(), true));
            case 'HS384':
            case 'hmac-sha384':
                return base64_encode(hash_hmac('sha384', $data, $this->getPrivateKey(), true));
            case 'HS512':
            case 'hmac-sha512':
                return base64_encode(hash_hmac('sha512', $data, $this->getPrivateKey(), true));
            case 'rsa-pss-sha512':
                return $this->pss512Sign($data);
            default:
                throw new UnProcessableSignatureException("Unsupported algorithm: $algorithm");
        };
    }

    private function verifySignature(string $data, string $signature, string $algorithm): bool
    {
        switch ($algorithm) {
            case 'RS256':
            case 'rsa-v1_5-sha256':
                return openssl_verify($data, $signature, $this->getPublicKey(), OPENSSL_ALGO_SHA256) === 1;
            case 'RS384':
            case 'rsa-v1_5-sha384':
                return openssl_verify($data, $signature, $this->getPublicKey(), OPENSSL_ALGO_SHA384) === 1;
            case 'RS512':
            case 'rsa-v1_5-sha512':
                return openssl_verify($data, $signature, $this->getPublicKey(), OPENSSL_ALGO_SHA512) === 1;
            case 'EdDSA':
            case 'Ed25519':
            case 'ed25519':
                return $this->ed25519Verify($data, $signature);
            case 'ES256':
            case 'ecdsa-p256-sha256':
                return $this->ecdsa256Verify($data, $signature);
            case 'ES384':
            case 'ecdsa-p384-sha384':
                return $this->ecdsa384Verify($data, $signature);
            case 'ES512':
            case 'ecdsa-p512-sha512':
                return $this->ecdsa512Verify($data, $signature);
            case 'HS256':
            case 'hmac-sha256':
               return hash_equals(base64_encode(hash_hmac('sha256', $data, $this->getPrivateKey(), true)),
                base64_encode($signature)
            );
            case 'HS384':
            case 'hmac-sha384':
                return hash_equals(base64_encode(hash_hmac('sha384', $data, $this->getPrivateKey(), true)),
                    base64_encode($signature)
                );
            case 'HS512':
            case 'hmac-sha512':
                return hash_equals(base64_encode(hash_hmac('sha512', $data, $this->getPrivateKey(), true)),
                    base64_encode($signature)
                );
            case 'rsa-pss-sha512':
                return $this->pss512Verify($data, $signature);
            default:
                return false;
        }
    }


    private function rsa256Sign(string $data): string
    {
        if (!openssl_sign($data, $signature, $this->getPrivateKey(), OPENSSL_ALGO_SHA256)) {
            throw new UnProcessableSignatureException("RSA signing failed");
        }
        return base64_encode($signature);
    }

    private function rsa384Sign(string $data): string
    {
        if (!openssl_sign($data, $signature, $this->getPrivateKey(), OPENSSL_ALGO_SHA384)) {
            throw new UnProcessableSignatureException("RSA signing failed");
        }
        return base64_encode($signature);
    }

    private function rsa512Sign(string $data): string
    {
        if (!openssl_sign($data, $signature, $this->getPrivateKey(), OPENSSL_ALGO_SHA512)) {
            throw new UnProcessableSignatureException("RSA signing failed");
        }
        return base64_encode($signature);
    }

    private function ecdsa256Sign(string $data): string
    {
        $ecc = new EasyECC('P256');
        $signature = $ecc->sign($data, SecretKey::importPem($this->getPrivateKey()), false);
        if (!$signature) {
            throw new UnprocessableSignatureException("ECDSA signing failed");
        }
        return base64_encode($signature);
    }

    private function ecdsa384Sign(string $data): string
    {
        $ecc = new EasyECC('P384');
        $signature = $ecc->sign($data, SecretKey::importPem($this->getPrivateKey()), false);
        if (!$signature) {
            throw new UnprocessableSignatureException("ECDSA signing failed");
        }
        return base64_encode($signature);
    }

    private function ecdsa512Sign(string $data): string
    {
        $ecc = new EasyECC('P512');
        $signature = $ecc->sign($data, SecretKey::importPem($this->getPrivateKey()), false);
        if (!$signature) {
            throw new UnprocessableSignatureException("ECDSA signing failed");
        }
        return base64_encode($signature);
    }

    private function pss512Sign(string $data): string
    {
        $rsa = new RSA();
        if ($rsa->loadKey($this->getPrivateKey()) !== true) {
            throw new UnprocessableSignatureException("PSS loadkey failure");
        };
        $rsa->setHash('sha512');
        $rsa->setMGFHash('sha512');
        $rsa->setSignatureMode(RSA::SIGNATURE_PSS);
        try {
            $signatureBytes = $rsa->sign($data);
        } catch (\Exception $exception) {
            throw new UnprocessableSignatureException($exception->getMessage());
        }
        return base64_encode($signatureBytes);
    }

    private function ed25519Sign(string $data): string
    {
        try {
            $private_key = PublicKeyLoader::loadPrivateKey($this->getPrivateKey());
            $signature = $private_key->sign($data);

        } catch (\Exception $e) {
            $signature = '';
            throw new UnprocessableSignatureException($e->getMessage());
        }
        return base64_encode($signature);
    }

    private function ed25519Verify(string $data, $signature): bool
    {
        try {
            $public_key = PublicKeyLoader::loadPublicKey($this->getPublicKey());
            $verified = $public_key->verify($data, $signature);
        }
        catch (\Exception $e) {
            $verified = false;
            throw new UnProcessableSignatureException($e->getMessage());
        }
        return $verified;
    }

    private function ecdsa256Verify(string $data, string $signature): bool
    {
        $ecc = new EasyECC('P256');
        try {
            $verified = $ecc->verify($data, PublicKey::importPem($this->getPublicKey()), $signature, false);
        }
        catch (UnprocessableSignatureException $e) {
            $verified = false;
        }
        return $verified;
    }

    private function ecdsa384Verify(string $data, string $signature): bool
    {
        $ecc = new EasyECC('P384');
        try {
            $verified = $ecc->verify($data, PublicKey::importPem($this->getPublicKey()), $signature, false);
        }
        catch (UnprocessableSignatureException $e) {
            $verified = false;
        }
        return $verified;
    }

    private function ecdsa512Verify(string $data, string $signature): bool
    {
        $ecc = new EasyECC('P512');
        try {
            $verified = $ecc->verify($data, PublicKey::importPem($this->getPublicKey()), $signature, false);
        }
        catch (UnprocessableSignatureException $e) {
            $verified = false;
        }
        return $verified;
    }


    private function pss512Verify(string $data, $signature): bool
    {
        $rsa = new RSA();
        if (!$rsa->loadKey($this->getPublicKey())) {
            throw new UnprocessableSignatureException("PSS loadkey failure");
        };
        $rsa->setHash('sha512');
        $rsa->setMGFHash('sha512');
        $rsa->setSignatureMode(RSA::SIGNATURE_PSS);
        try {
            $verified = $rsa->verify($data, $signature);
        } catch (\Exception $exception) {
            $verified = false;
        }
        return $verified;
    }


    /* parse a structed dict */

    private function parseStructuredDict(string $headerValue)
    {
        if (str_starts_with(trim($headerValue), '(')) {
            return InnerList::fromHttpValue($headerValue);
        }
        else {
            return Dictionary::fromHttpValue($headerValue);
        }
    }

    /* Recommended to calculate the digest of the body and add it to 
        covered headers and sign, but not required. Convenience function
        to calculate the digest.

        ex:

        $digest = $signer->createContentDigestHeader($body);
        $request = $request->withHeader('Content-Digest', $digest);
    */

    /**
     * @param string $body
     * @param $algorithm ('sha256' || 'sha512')
     * @return string
     *
     * From https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Digest
     * The algorithm used to create a digest of the message content. Only two registered digest algorithms are
     * considered secure: sha-512 and sha-256. The insecure (legacy) registered digest algorithms
     * are: md5, sha (SHA-1), unixsum, unixcksum, adler (ADLER32) and crc32c.
     */

    public function createContentDigestHeader(string $body, $algorithm = 'sha256'): string
    {
        $supportedAlgorithms = ['sha256' => 'sha-256', 'sha512' => 'sha-512'];
        foreach ($supportedAlgorithms as $alg => $value) {
            if ($alg === $algorithm) {
                $algorithmHeaderString = $value;
                break;
            }
        }
        if (!isset($algorithmHeaderString)) {
            throw new UnProcessableSignatureException("Unsupported digest algorithm: $algorithm");
        }
        $digest = hash($algorithm, $body, true);
        /**
         * Output as structured field.
         */
        return $algorithmHeaderString . '=:' . base64_encode($digest) . ':';
    }

    /* Convenience function, probably want to use a robust PSR7 solution instead */

    public static function parseHttpMessage(string $raw): array
    {
        [$headerPart, $body] = explode("\r\n\r\n", $raw, 2);
        $lines = explode("\r\n", $headerPart);
        $requestLine = array_shift($lines);
        [$method, $path] = explode(' ', $requestLine);

        $headers = [];
        foreach ($lines as $line) {
            [$name, $value] = explode(':', $line, 2);
            $headers[strtolower(trim($name))] = trim($value);
        }

        return [
            'method' => $method,
            'path' => $path,
            'headers' => $headers,
            'body' => $body
        ];
    }

    /**
     * @return array
     */
    public function getStructuredFieldTypes(): array
    {
        return $this->structuredFieldTypes;
    }

    /**
     * @param array $structuredFieldTypes
     * @return HttpMessageSigner
     */
    public function setStructuredFieldTypes(array $structuredFieldTypes): HttpMessageSigner
    {
        $this->structuredFieldTypes = $structuredFieldTypes;
        return $this;
    }

    /**
     * $structuredFieldType consists of a key named after a specific header field, and a value
     * which is one of 'list', 'innerlist', 'parameters, 'dictionary', 'item'.
     *
     * Example:
     *  ['example-dict' => 'dictionary']
     *
     * The 'sf' flag will not be honoured unless the structured type of the header is registered/known.
     *
     * @param array $structuredFieldType
     * @return $this
     */

    public function addStructuredFieldType(array $structuredFieldType): HttpMessageSigner
    {
        foreach ($structuredFieldType as $key => $value) {
            $this->structuredFieldTypes[$key] = $value;
        }
        return $this;
    }

    /**
     * @return mixed
     */
    public function getOriginalRequest()
    {
        return $this->originalRequest;
    }

    /**
     * @param mixed $originalRequest
     * @return HttpMessageSigner
     */
    public function setOriginalRequest($originalRequest)
    {
        $this->originalRequest = $originalRequest;
        return $this;
    }

    /**
     * @return string
     */
    public function getKeyId(): string
    {
        return $this->keyId;
    }

    /**
     * @param string $keyId
     * @return HttpMessageSigner
     */
    public function setKeyId(string $keyId): HttpMessageSigner
    {
        $this->keyId = $keyId;
        return $this;
    }

    /**
     * @return string
     */
    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    /**
     * @param string $privateKey
     * @return HttpMessageSigner
     */
    public function setPrivateKey(string $privateKey): HttpMessageSigner
    {
        $this->privateKey = $privateKey;
        return $this;
    }

    /**
     * @return string
     */
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * @param string $publicKey
     * @return HttpMessageSigner
     */
    public function setPublicKey(string $publicKey): HttpMessageSigner
    {
        $this->publicKey = $publicKey;
        return $this;
    }

    /**
     * @return string
     */
    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * @param string $algorithm
     * @return HttpMessageSigner
     */
    public function setAlgorithm(string $algorithm): HttpMessageSigner
    {
        $this->algorithm = $algorithm;
        return $this;
    }

    /**
     * @return string
     */
    public function getSignatureId(): string
    {
        return $this->signatureId;
    }

    /**
     * @param string $signatureId
     * @return HttpMessageSigner
     */
    public function setSignatureId(string $signatureId): HttpMessageSigner
    {
        $this->signatureId = $signatureId;
        return $this;
    }

    /**
     * @return string
     */
    public function getCreated(): string
    {
        return $this->created;
    }

    /**
     * @param string $created
     * @return HttpMessageSigner
     */
    public function setCreated(string $created): HttpMessageSigner
    {
        $this->created = $created;
        return $this;
    }

    /**
     * @return string
     */
    public function getExpires(): string
    {
        return $this->expires;
    }

    /**
     * @param string $expires
     * @return HttpMessageSigner
     */
    public function setExpires(string $expires): HttpMessageSigner
    {
        $this->expires = $expires;
        return $this;
    }

    /**
     * @return string
     */
    public function getNonce(): string
    {
        return $this->nonce;
    }

    /**
     * @param string $nonce
     * @return HttpMessageSigner
     */
    public function setNonce(string $nonce): HttpMessageSigner
    {
        $this->nonce = $nonce;
        return $this;
    }

    /**
     * @return string
     */
    public function getTag(): string
    {
        return $this->tag;
    }

    /**
     * @param string $tag
     * @return HttpMessageSigner
     */
    public function setTag(string $tag): HttpMessageSigner
    {
        $this->tag = $tag;
        return $this;
    }
}

