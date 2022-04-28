<?php

/**
 * Inane: Stdlib
 *
 * Inane Crypt
 *
 * PHP version 8.1
 *
 * @package Inane\Stdlib
 * @author Philip Michael Raab<peep@inane.co.za>
 *
 * @license UNLICENSE
 * @license https://github.com/inanepain/event/raw/develop/UNLICENSE UNLICENSE
 */
declare(strict_types=1);

namespace Inane\Crypt;

use Inane\Stdlib\Exception\InvalidArgumentException;

use function base64_decode;
use function base64_encode;
use function in_array;
use function is_null;
use function openssl_decrypt;
use function openssl_encrypt;
use function openssl_get_cipher_methods;
use function str_replace;
use function strlen;
use function substr;
use const null;

/**
 * Secret
 *
 * Encrypt and decrypt strings
 *
 * NOTE: Not all cipher methods are supported.
 *
 * @version 1.0.0
 *
 * @package Inane\Crypt
 */
class Secret {
    /**
     * Clean characters
     */
    private static array $clean = ['_P_', '_S_', '_E_'];

    /**
     * Dirty characters
     */
    private static array $dirty = ['+', '/', '='];

    /**
     * Secret
     *
     * @param string $passphrase The passphrase. If the passphrase is shorter than expected, it is silently padded with NUL characters; if the passphrase is longer than expected, it is silently truncated.
     * @param string $cipher The cipher method. For a list of available cipher methods, @see openssl_get_cipher_methods()
     * @param null|string $iv A non-NULL Initialization Vector. If not supplied it will be generated from key
     *
     * @return void
     *
     * @throws \Inane\Exception\InvalidArgumentException
     */
    public function __construct(
        /** The passphrase. If the passphrase is shorter than expected, it is silently padded with NUL characters; if the passphrase is longer than expected, it is silently truncated. */
        private readonly string $passphrase,
        /** The cipher method. For a list of available cipher methods, @see openssl_get_cipher_methods() */
        protected string $cipher = 'aes-256-ctr',
        /** A non-NULL Initialization Vector. If not supplied it will be generated from key */
        protected ?string $iv = null,
    ) {
        if (strlen($this->passphrase) < 16) throw new InvalidArgumentException("Invalid key, must be at least 16 char: '{$this->passphrase}' => " . strlen($this->passphrase));
        if (!in_array($this->cipher, openssl_get_cipher_methods())) throw new InvalidArgumentException("Invalid cipher method: '{$this->cipher}'");
    }

    /**
     * Get IV
     *
     * @return string IV value
     */
    protected function getIv(): string {
        if (is_null($this->iv)) $this->iv = substr($this->passphrase, 0, 16);
        return $this->iv;
    }

    /**
     * Encrypt string
     *
     * @param string $plainText
     *
     * @return string encrypted string
     */
    public function encrypt(string $plainText): string {
        return openssl_encrypt($plainText, $this->cipher, $this->passphrase, $options = 0, $this->getIv());
    }

    /**
     * Decrypt string
     *
     * @param string $encryptedText
     *
     * @return string decrypted string
     */
    public function decrypt(string $encryptedText): string {
        return openssl_decrypt($encryptedText, $this->cipher, $this->passphrase, $options = 0, $this->getIv());
    }

    /**
     * Encode for url
     *
     * @param string $encryptedText
     *
     * @return string encoded text
     */
    public function encode(string $encryptedText): string {
        $encryptedText = base64_encode($encryptedText);
        return str_replace(static::$dirty, static::$clean, $encryptedText);
    }

    /**
     * Decode from url
     *
     * @param string $encodedText
     *
     * @return string decoded text
     */
    public function decode(string $encodedText): string {
        return base64_decode(str_replace(static::$clean, static::$dirty, $encodedText));
    }

    /**
     * Encrypt and Encode
     *
     * @param string $plainText
     *
     * @return string encrypted and encoded text
     */
    public function encryptEncode(string $plainText): string {
        $encryptedText = $this->encrypt($plainText);
        $encryptedText = base64_encode($encryptedText);
        return str_replace(static::$dirty, static::$clean, $encryptedText);
    }

    /**
     * Decrypt and Decode
     *
     * @param string $encryptedEncodedText
     *
     * @return string plain text
     */
    public function decryptDecode(string $encryptedEncodedText): string {
        $encodedText = base64_decode(str_replace(static::$clean, static::$dirty, $encryptedEncodedText));
        return $this->decrypt($encodedText);
    }
}
