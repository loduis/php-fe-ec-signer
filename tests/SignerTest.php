<?php

namespace FEEC\Tests;

use FEEC\Signer;
use DOMDocument;
use FEEC\Signature\Validator;
use XML\Tests\Cert;
use XML\Signature\X509;
use XML\Tests\TestCase;

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

    public function testVerify()
    {
        $test = Validator::verify(file_get_contents(__DIR__ . '/resources/FE-001-003-000000021.xml'));

        $this->assertTrue($test);
    }
}
