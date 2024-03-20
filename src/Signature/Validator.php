<?php

declare(strict_types=1);

namespace FEEC\Signature;

use XML\Signature\Validator as BaseValidator;

class Validator extends BaseValidator
{
    public static function verify(string $xml): bool
    {
        $doc = static::toDocument($xml);

        $node = static::findElement($doc, 'comprobante', null);
        if (!$node) {
            return false;
        }

        $node = static::toDocument($node->nodeValue)->firstChild;

        return ($info = static::verifySignature($node)) !== null &&
            static::verifyKeyInfo($node, $info) &&
            static::verifySignedProperties($node, $info);
    }
}