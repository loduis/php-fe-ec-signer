<?php

namespace FEEC;

use XML\Signature;
use XML\Signature\Key;
use XML\Signature\Digest;
use XML\Signature\Xades;

class Signer extends Signature
{
    protected  $keyAlgorithm = Key::RSA_SHA1;

    protected $digestAlgorithm = Digest::SHA1;

    protected string $prefix;

    protected $namespaces = [];

    public function __construct(array $options = [])
    {
        $options = $this->prepareOptions($options);

        parent::__construct($options);

        $this->namespaces = implode(' ', $this->namespaces);
    }

    protected function uuid($posfix): string
    {
        return  $posfix ? $this->prefix . '-' . $posfix : $this->prefix;
    }

    protected function prepareOptions(array $options): array
    {
        static $defaults = [
            'id' => '',
            'key_info_id' => 'keyinfo',
            'reference_id' => 'ref0',
            'signed_properties_id' => 'signedprops',
            'signature_value_id' => 'sigvalue'
        ];

        $this->prefix = $options['prefix'] ?? 'xmldsig-' . $this->randomId();

        foreach ($defaults as $key => $posfix) {
            if (!($options[$key] ?? false)) {
                $options[$key] = $this->uuid($posfix);
            }
        }
        $options['reference_uri'] = '#comprobante';
        $options['namespaces'] = ['etsi' => Xades::NS];
        $options['modulus'] = true;
        $options['xades'] = new Xades([
            'id' => $options['signed_properties_id'],
            'reference_id' => $options['reference_id'],
            'certs' => $options['certs'] ?? [],
            'time' => $options['time'] ?? null,
            'prefix' => 'etsi',
            'format' => [
                'description' => 'contenido comprobante',
                'type' => 'text/xml'
            ]
        ]);

        return $options;
    }

    protected function randomId(): string
    {
        return bin2hex(random_bytes(6));
    }
}
