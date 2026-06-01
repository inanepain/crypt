<?php

/**
 * Inane: Crypt
 *
 * Encryption helpers and password hashers.
 *
 * $Id$
 * $Date$
 *
 * PHP version 8.5
 *
 * @author   Philip Michael Raab<philip@cathedral.co.za>
 * @package  inanepain\crypt
 * @category crypt
 *
 * @license  UNLICENSE
 * @license  https://unlicense.org/UNLICENSE UNLICENSE
 *
 * _version_ $version
 */

declare(strict_types = 1);

namespace Inane\Crypt\Tests;

use Inane\{
    Crypt\Secret,
    Stdlib\Exception\InvalidArgumentException};
use PHPUnit\Framework\{
    Attributes\CoversClass,
    TestCase};

/**
 * Tests for the {@see Secret} helper.
 *
 * Verifies that encryption/decryption work as a round‑trip, the custom
 * base64 mapping used by `encode`/`decode` is reversible and URL‑safe, and
 * constructor validation guards against weak keys and invalid ciphers.
 */
#[CoversClass(Secret::class)]
final class SecretTest extends TestCase {
    /**
     * 32‑character passphrase used for test vectors.
     *
     * @var string
     */
    private const PASSPHRASE = 'this-is-a-secure-passphrase-32';

    /**
     * Ensures that a plaintext encrypted with {@see Secret::encrypt()} can be
     * successfully recovered using {@see Secret::decrypt()} and that ciphertext
     * differs from plaintext.
     *
     * @return void
     */
    public function testEncryptDecryptRoundTrip(): void {
        $secret = new Secret(self::PASSPHRASE);

        $plain = 'The quick brown fox jumps over 13 lazy dogs 🦊';
        $encrypted = $secret->encrypt($plain);
        self::assertIsString($encrypted);
        self::assertNotSame($plain, $encrypted, 'Encrypted text should differ from plain');

        $decrypted = $secret->decrypt($encrypted);
        self::assertSame($plain, $decrypted);
    }

    /**
     * Validates that {@see Secret::encode()} performs the expected character
     * substitutions for '+', '/', and '=' and that {@see Secret::decode()}
     * cleanly reverses the process.
     *
     * @return void
     */
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

    /**
     * Asserts the combined helpers {@see Secret::encryptEncode()} and
     * {@see Secret::decryptDecode()} perform a full round‑trip and yield an
     * URL‑safe token without '+', '/', or '=' characters.
     *
     * @return void
     */
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

    /**
     * Ensures that too‑short passphrases (length < 16) are rejected.
     *
     * @return void
     */
    public function testConstructorRejectsShortKey(): void {
        $this->expectException(InvalidArgumentException::class);
        // 8 chars is too short (must be >= 16)
        new Secret('tooShort');
    }

    /**
     * Ensures that an invalid cipher name triggers an
     * {@see InvalidArgumentException} from the constructor.
     *
     * @return void
     */
    public function testConstructorRejectsInvalidCipher(): void {
        $this->expectException(InvalidArgumentException::class);
        new Secret(self::PASSPHRASE, 'definitely-not-a-cipher');
    }
}
