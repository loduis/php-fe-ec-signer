<?php

// https://es.stackoverflow.com/questions/377199/error-al-firmar-xml-con-php-para-el-sri
// https://github.com/jybaro/xades-bes-sri/blob/master/xades_factura_electronica_sri.js
namespace FEEC\Tests;

use FEEC\Signer;
use DOMDocument;
use XML\Tests\Cert;
use XML\Signature\X509;
use XML\Tests\TestCase;
use Dotenv\Dotenv;

class SignerTest extends TestCase
{
    public function testShouldCreateXml()
    {
        $doc = new DOMDocument();
        $doc->loadXML('<test id="comprobante"></test>');

        $certificate = X509::fromFile(Cert::file('pem'));
        $signature = new Signer([
            'certificate' => $certificate,
            'id' => 'Signature620397',
            'reference_id' => 'Reference-ID-363558',
            'object_id' => 'Signature620397-Object231987',
            'key_info_id' => 'Certificate1562780',
            'signature_value_id' => 'SignatureValue398963',
            'signed_properties_id' => 'Signature620397-SignedProperties24123',
            'time' => '2012-03-05T16:57:32-05:00',
            'certs' => [
                [
                    'raw' => 'prueba1',
                    'digest_value' => 'xUQewsj7MrjSfyMnhWz5DhQnWJM=',
                    'issuer_name' => 'CN=AC BANCO CENTRAL DEL ECUADOR,L=QUITO,OU=ENTIDAD DE CERTIFICACION DE INFORMACION-ECIBCE,O=BANCO CENTRAL DEL ECUADOR,C=EC',
                    'serial_number' => '1312833444'
                ],
            ]
        ]);
        $signature->sign($doc);
        $this->assertTrue($signature->verify());
        $this->assertMatchesXmlSnapshot((string) $signature);
    }

    /*
    public function testShouldCreateXml2()
    {
        $certificate = X509::fromFile(__DIR__ . '/resources/cert.p12', $_ENV['CERT_PASS']);

        $doc = new DOMDocument();
        $doc->load(__DIR__ . '/resources/test.xml');

        $signature = new Signer([
            'certificate' => $certificate,
            'id' => 'Signature1645664475',
            'reference_id' => 'Reference-ID-2010957418',
            'object_id' => 'Signature1645664475-Object1007621934',
            'key_info_id' => 'Certificate2061127488',
            'signature_value_id' => 'SignatureValue398963',
            'signed_properties_id' => 'Signature1645664475-SignedProperties955375121',
            'time' => '2024-02-05T08:30:27-05:00',
        ]);
        $signature->sign($doc);
        $this->assertTrue($signature->verify());
        $this->assertMatchesXmlSnapshot((string) $signature);
    }
    */
}
