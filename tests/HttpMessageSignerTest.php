<?php
namespace HttpSignature\Tests;

use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use HttpSignature\HttpMessageSigner;
use HttpSignature\Tests\Helpers\RawHttpBuilder;

final class HttpMessageSignerTest extends TestCase
{
    private string $privateKey;
    private string $publicKey;
    private HttpMessageSigner $signer;

    protected function setUp(): void
    {
        $this->privateKey = file_get_contents(__DIR__ . '/keys/private.pem');
        $this->publicKey = file_get_contents(__DIR__ . '/keys/public.pem');

        $this->signer = (new HttpMessageSigner())
            ->setPrivateKey($this->privateKey)
            ->setPublicKey($this->publicKey)
            ->setKeyId('test-key')
            ->setAlgorithm('rsa-v1_5-sha256')
            ->setCreated(time()
        );
    }

    public function testSignsAndVerifiesValidRequest(): void
    {
        $date = gmdate('D, d M Y H:i:s T');
        $request = new Request(
            'POST',
            'https://api.example.com/resource?bat&baz=3',
            [
                'Host' => 'api.example.com',
                'Date' => $date,
                'x-test' => '',
                'Example-Dict' => '  a=1,    b=2;x=1;y=2,   c=(a   b   c), d ',
                'Empty-List' => '',
                'Another-Empty-List' => '',
            ]
        );
        /**
         * Use $request->withAddedHeader() method to provide an additional header with same name as an existing header.
         */
        $request = $request->withHeader('Example-Header', 'value, with, lots');
        $request = $request->withAddedHeader('Example-Header', 'of, commas');
        $request = $request->withHeader('If-None-Match', 'W/"abcdef", "ghijkl", *');

        $coveredFields = '("example-header";bs "@method" "@path" "host" "if-none-match";sf "date" "date";sf "@request-target" "@target-uri" "@query-param";name="baz" "@query-param";name="bat" "example-dict" "example-dict";sf "example-dict";key="a" "example-dict";key="b" "example-dict";key="c" "example-dict";key="d" "empty-list";sf "another-empty-list")';
        $this->signer->addStructuredFieldType(['example-dict' => 'dictionary']);
        $this->signer->addStructuredFieldType(['empty-list' => 'list']);
        $this->signer->addStructuredFieldType(['another-empty-list' => 'list']);
        $request = $this->signer->signRequest($coveredFields, $request);

        $this->assertTrue($request->hasHeader('signature'));
        $this->assertTrue($request->hasHeader('signature-input'));

        [$signatureInput, $signatureBase] = $this->signer->calculateSignatureBase($this->signer->getHeaders($request), $coveredFields, $request);
        $normalised = explode("\n", $signatureBase);

        $this->assertContains('"example-header";bs: :dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:', $normalised);
        $this->assertContains('"@method": POST', $normalised);
        $this->assertContains('"@path": /resource', $normalised);
        $this->assertContains('"host": api.example.com', $normalised);
        $this->assertContains('"if-none-match";sf: "abcdef"; w, "ghijkl", *', $normalised);
        $this->assertContains('"date": ' . $date, $normalised);
        $this->assertContains('"date";sf: @' . strtotime($date), $normalised);
        $this->assertContains('"@request-target": /resource?bat&baz=3', $normalised);
        $this->assertContains('"@target-uri": https://api.example.com/resource?bat&baz=3', $normalised);
        $this->assertContains('"_baz_": "3"', $normalised);
        $this->assertContains('"_bat_": ', $normalised);
        $this->assertContains('"example-dict": a=1,    b=2;x=1;y=2,   c=(a   b   c), d', $normalised);
        $this->assertContains('"example-dict";sf: a=1, b=2;x=1;y=2, c=(a b c), d', $normalised);
        $this->assertContains('"example-dict";key="a": 1', $normalised);
        $this->assertContains('"example-dict";key="b": 2;x=1;y=2', $normalised);
        $this->assertContains('"example-dict";key="c": (a b c)', $normalised);
        $this->assertContains('"example-dict";key="d": ?1', $normalised);
        $this->assertNotContains('"empty-list":', $normalised, 'empty structured field lists parsed as structured fields should be ignored');
        $this->assertContains('"another-empty-list": ', $normalised, 'empty structured field lists which are not parsed as structured fields should be included');
        $this->assertEquals($request->getRequestTarget(), '/resource?bat&baz=3');

        $isValid = $this->signer->verifyRequest($request);
        $this->assertTrue($isValid, 'Signed request should be valid');
    }

    public function testSignsAndVerifiesValidResponse(): void
    {
        $date = gmdate('D, d M Y H:i:s T');
        $originalRequest = new Request(
            'POST',
            'https://api.example.com/resource?bat&baz=3',
            [
                'Host' => 'api.example.com',
                'Date' => $date,
                'x-test' => '',
                'Example-Dict' => '  a=1,    b=2;x=1;y=2,   c=(a   b   c), d ',
            ]
        );

        $response = new Response(
            200,
            [
                'content-type' => 'text/json; charset=utf-8',
                'Date' => $date,
            ],
            '{"foo":"bar"}'
        );

        $coveredFields = '("date" "content-type" "@status" "host";req)';

        $response = $this->signer->signRequest($coveredFields, $response, $originalRequest);

        $this->assertTrue($response->hasHeader('signature'));
        $this->assertTrue($response->hasHeader('signature-input'));

        [$signatureInput, $signatureBase] = $this->signer->calculateSignatureBase($this->signer->getHeaders($response), $coveredFields, $response);
        $normalised = explode("\n", $signatureBase);
        print_r($normalised);

        $isValid = $this->signer->verifyRequest($response, $originalRequest);
        $this->assertTrue($isValid, 'Signed request should be valid');
    }


    public function testPssSignatures(): void
    {
        $this->privateKey = file_get_contents(__DIR__ . '/keys/pss-private.pem');
        $this->publicKey = file_get_contents(__DIR__ . '/keys/pss-public.pem');

        $this->signer = (new HttpMessageSigner())
            ->setPrivateKey($this->privateKey)
            ->setPublicKey($this->publicKey)
            ->setKeyId('test-key')
            ->setAlgorithm('rsa-pss-sha512')
            ->setCreated(time());

        $body = '{"hello": "world"}';
        $digest = $this->signer->createContentDigestHeader($body);

        $request = new Request(
            'POST',
            'https://example.com/api',
            [
                'Host' => 'example.com',
                'Content-Digest' => $digest
            ],
            $body
        );

        $signed = $this->signer->signRequest('("@method" "@target-uri" "host" "content-digest")', $request);
        $this->assertTrue($this->signer->verifyRequest($signed));
    }

    public function testEdSignatures(): void
    {
        $this->privateKey = file_get_contents(__DIR__ . '/keys/ed25519-private.pem');
        $this->publicKey = file_get_contents(__DIR__ . '/keys/ed25519-public.pem');

        $this->signer = (new HttpMessageSigner())
            ->setPrivateKey($this->privateKey)
            ->setPublicKey($this->publicKey)
            ->setKeyId('test-key')
            ->setAlgorithm('ed25519')
            ->setCreated(time());

        $body = '{"hello": "world"}';
        $digest = $this->signer->createContentDigestHeader($body);

        $request = new Request(
            'POST',
            'https://example.com/api',
            [
                'Host' => 'example.com',
                'Content-Digest' => $digest
            ],
            $body
        );

        $signed = $this->signer->signRequest('("@method" "@target-uri" "host" "content-digest")', $request);
        $this->assertTrue($this->signer->verifyRequest($signed));
    }

    public function testEccSignatures(): void
    {
        $this->privateKey = file_get_contents(__DIR__ . '/keys/ecc-private.pem');
        $this->publicKey = file_get_contents(__DIR__ . '/keys/ecc-public.pem');

        $this->signer = (new HttpMessageSigner())
            ->setPrivateKey($this->privateKey)
            ->setPublicKey($this->publicKey)
            ->setKeyId('test-key')
            ->setAlgorithm('ecdsa-p256-sha256')
            ->setCreated(time());

        $body = '{"hello": "world"}';
        $digest = $this->signer->createContentDigestHeader($body);

        $request = new Request(
            'POST',
            'https://example.com/api',
            [
                'Host' => 'example.com',
                'Content-Digest' => $digest
            ],
            $body
        );

        $signed = $this->signer->signRequest('("@method" "@target-uri" "host" "content-digest")', $request);
        $this->assertTrue($this->signer->verifyRequest($signed));
    }

    public function testSignsAndVerifiesWithBodyDigest(): void
    {
        $body = '{"message":"hello"}';
        $digest = $this->signer->createContentDigestHeader($body);

        $request = new Request(
            'POST',
            'https://example.com/api',
            [
                'Host' => 'example.com',
                'Content-Digest' => $digest
            ],
            $body
        );

        $signed = $this->signer->signRequest('("@method" "@path" "host" "content-digest")', $request);
        $this->assertTrue($this->signer->verifyRequest($signed));
    }

    public function testFailsIfBodyDigestDoesNotMatch(): void
    {
        $originalBody = '{"message":"hello"}';
        $digest = $this->signer->createContentDigestHeader($originalBody);

        // Use a different body (tampered)
        $tamperedBody = '{"message":"goodbye"}';

        $request = new Request(
            'POST',
            'https://example.com/api',
            [
                'Host' => 'example.com',
                'Content-Digest' => $digest
            ],
            $tamperedBody
        );

        $signed = $this->signer->signRequest('("@method" "@path" "host" "content-digest")', $request);
        $this->assertFalse($this->signer->verifyRequest($signed),
                'Digest mismatch should cause verification to fail');
    }


    public function testVerificationFailsWhenHeaderIsModified(): void
    {
        $request = new Request(
            'POST',
            'https://api.example.com/resource',
            [
                'Host' => 'api.example.com',
                'Date' => gmdate('D, d M Y H:i:s T'),
            ]
        );

        $signed = $this->signer->signRequest('("@method" "@path" "host" "date")', $request);

        $tampered = $signed->withHeader('Host', 'attacker.com');
        $this->assertFalse($this->signer->verifyRequest($tampered), 
                                'Tampered request should be invalid');
    }

    public function testVerificationFailsWithoutSignature(): void
    {
        $request = new Request(
            'POST',
            'https://api.example.com/resource',
            [
                'Host' => 'api.example.com',
                'Date' => gmdate('D, d M Y H:i:s T'),
            ]
        );

        $this->assertFalse($this->signer->verifyRequest($request), 'Unsigned request should be invalid');
    }

    public function testParsesRawHttpMessageCorrectly(): void
    {

        $raw = RawHttpBuilder::fromParts(
            'POST',
            '/foo',
            [
                'Host'=>'example.com',
                'Date'=>'Tue, 13 May 2025 00:00:01 GMT',
                'Content-Type' => 'application/json',
                'Content-Digest' => 'sha-256=:abcd1234=:'
            ],
            '{"message":"hello"}'
        );

        $parsed = HttpMessageSigner::parseHttpMessage($raw);

        $this->assertEquals('POST', $parsed['method']);
        $this->assertEquals('/foo', $parsed['path']);
        $this->assertEquals('example.com', $parsed['headers']['host']);
        $this->assertEquals('Tue, 13 May 2025 00:00:01 GMT', $parsed['headers']['date']);
        $this->assertEquals('application/json', $parsed['headers']['content-type']);
        $this->assertEquals('{"message":"hello"}', $parsed['body']);
    }

    public function testManualInspectSignature(): void
    {
        $request = new Request(
            'POST',
            'https://api.example.com/resource?bat&baz=3',
            [
                'Host' => 'api.example.com',
                'Date' => gmdate('D, d M Y H:i:s T'),
                'Example-Dict' => '  a=1,    b=2;x=1;y=2,   c=(a   b   c), d ',
                'If-None-Match' => 'W/"abcdef", "ghijkl", *',
                'Empty-List' => '',
            ],
            '{"message":"hello"}'
        );
        // Use this method to provide an additional header with the same name as an existing header.
        $request = $request->withHeader('Example-Header', 'value, with, lots');
        $request = $request->withAddedHeader('Example-Header', 'of, commas');

        $coveredFields = '("@method" "@path" "if-none-match";sf "host" "date" "date";sf "@request-target" "@target-uri" "@query-param";name="baz" "@query-param";name="bat" "content-digest" "example-dict" "example-dict";sf "example-dict";key="a" "example-dict";key="b" "example-dict";key="c" "example-dict";key="d" "example-header";bs "empty-list";sf)';
        $this->signer->addStructuredFieldType(['example-dict' => 'dictionary']);
        $this->signer->addStructuredFieldType(['empty-list' => 'list']);
        $digest = $this->signer->createContentDigestHeader((string) $request->getBody());
        $request = $request->withHeader('Content-Digest', $digest);
        $request = $this->signer->signRequest($coveredFields, $request);

        echo "\n\nManual Inspection\n\n";

        foreach ($request->getHeaders() as $name => $values) {
            echo $name . ": " . implode(', ', $values) . PHP_EOL;
        }

        [$signatureInput, $signatureBase] = $this->signer->calculateSignatureBase($this->signer->getHeaders($request), $coveredFields, $request);
        $normalised = explode("\n", $signatureBase);

        echo "\n\nNormalised signature components\n\n";

        foreach ($normalised as $component) {
            echo $component . PHP_EOL;
        }
        // Optional assertion to keep PHPUnit happy
        $this->assertTrue($request->hasHeader('signature'), 'Signature header should exist');
    }
}

