<?php

declare(strict_types=1);

namespace Inane\Crypt\Tests;

use Inane\Crypt\Secret;
use Inane\Stdlib\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Secret::class)]
final class SecretTest extends TestCase {
    private const PASSPHRASE = 'this-is-a-secure-passphrase-32';

    public function testEncryptDecryptRoundTrip(): void {
        $secret = new Secret(self::PASSPHRASE);

        $plain = 'The quick brown fox jumps over 13 lazy dogs 🦊';
        $encrypted = $secret->encrypt($plain);
        self::assertIsString($encrypted);
        self::assertNotSame($plain, $encrypted, 'Encrypted text should differ from plain');

        $decrypted = $secret->decrypt($encrypted);
        self::assertSame($plain, $decrypted);
    }

    public function testEncodeDecodeMapping(): void {
        $secret = new Secret(self::PASSPHRASE);

        // Craft a string that base64-encodes to + / = characters
        $encrypted = "\xFA\xFB\xFC"; // base64: +vv8
        $encoded = $secret->encode($encrypted);

        // Expect replacements according to Secret::$clean mapping
        self::assertStringNotContainsString('+', $encoded);
        self::assertStringNotContainsString('/', $encoded);
        self::assertStringNotContainsString('=', $encoded);

        $decoded = $secret->decode($encoded);
        self::assertSame($encrypted, $decoded);
    }

    public function testEncryptEncodeAndDecryptDecodeRoundTrip(): void {
        $secret = new Secret(self::PASSPHRASE);

        $plain = 'Sphinx of black quartz, judge my vow!';
        $token = $secret->encryptEncode($plain);

        // Should be URL-safe per mapping
        self::assertStringNotContainsString('+', $token);
        self::assertStringNotContainsString('/', $token);
        self::assertStringNotContainsString('=', $token);

        $out = $secret->decryptDecode($token);
        self::assertSame($plain, $out);
    }

    public function testConstructorRejectsShortKey(): void {
        $this->expectException(InvalidArgumentException::class);
        // 8 chars is too short (must be >= 16)
        new Secret('tooShort');
    }

    public function testConstructorRejectsInvalidCipher(): void {
        $this->expectException(InvalidArgumentException::class);
        new Secret(self::PASSPHRASE, 'definitely-not-a-cipher');
    }
}
