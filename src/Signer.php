<?php

namespace FEEC;

use DOMNode;
use XML\Element;
use XML\Signature;
use XML\Signature\Key;
use XML\Signature\Digest;
use XML\Signature\Xades;

class Signer extends Signature
{
    protected  $keyAlgorithm = Key::RSA_SHA1;

    protected $digestAlgorithm = Digest::SHA1;

    protected string $prefix;

    protected int $chunks = 76;

    protected $namespaces = [
        'xmlns:ds="' . Signature::NS. '"',
        'xmlns:etsi="' . Xades::NS . '"'
    ];

    public function __construct(array $options = [])
    {
        $options = $this->prepareOptions($options);

        parent::__construct($options);

        $this->namespaces = implode(' ', $this->namespaces);

        if (count($this->xades['certs']) > 1) {
            $this->xades['certs'] = [
                $this->xades['certs'][0]
            ];
        }
    }

    public function sign(DOMNode $node, $appendTo = null): string
    {
        parent::sign($node, $appendTo);

        return Element::stripXmlns($node->saveXML());
    }

    protected function uuid($postfix): string
    {
        return  $postfix ? $this->prefix . '-' . $postfix : $this->prefix;
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

        foreach ($defaults as $key => $postfix) {
            if (!($options[$key] ?? false)) {
                $options[$key] = $this->uuid($postfix);
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
    protected function canonicalize($node): string
    {
        $xml = parent::canonicalize($node);

        foreach (['ds:KeyInfo', 'xades:SignedProperties', 'ds:SignedInfo'] as $tagname) {
            if ($this->injectNamespaces($tagname, $xml)) {
                break;
            }
        }

        return $xml;
    }

    protected function injectNamespaces($tagname, & $xml): bool
    {
        $regex = "!<$tagname([^>]*)>.+?</$tagname>!is";
        if (!preg_match($regex, $xml, $matches)) {
            return false;
        }
        $attributes = [];
        $search = trim($matches[1]);
        foreach (explode(' ', $search) as $attribute) {
            if (strpos($attribute, ':') === false) {
                $attributes[] = $attribute;
            }
        }
        $replace = trim($this->namespaces . ' ' .implode(' ', $attributes));
        $xml = str_replace(' ' . $search, ' ' . $replace, $xml);

        return true;
    }

    protected function randomId(): string
    {
        return bin2hex(random_bytes(6));
    }
}
