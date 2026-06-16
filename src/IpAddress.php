<?php

declare(strict_types=1);

namespace Componenta\Stdlib;

use InvalidArgumentException;
use JsonSerializable;
use Stringable;

final readonly class IpAddress implements Stringable, JsonSerializable
{
    private const array PRIVATE_RANGES = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        'fc00::/7',
    ];

    private const array LOOPBACK_RANGES = [
        '127.0.0.0/8',
        '::1/128',
    ];

    private const array LINK_LOCAL_RANGES = [
        '169.254.0.0/16',
        'fe80::/10',
    ];

    private const array MULTICAST_RANGES = [
        '224.0.0.0/4',
        'ff00::/8',
    ];

    public IpVersion $version;

    private function __construct(
        public string $value,
    ) {
        $this->version = str_contains($value, ':') ? IpVersion::V6 : IpVersion::V4;
    }


    /**
     * @throws InvalidArgumentException If the address is empty or invalid.
     */
    public static function fromString(string $ip): self
    {
        $ip = trim($ip);

        if ($ip === '') {
            throw new InvalidArgumentException('IP address cannot be empty');
        }

        $normalized = self::normalize($ip);

        if ($normalized === null) {
            throw new InvalidArgumentException("Invalid IP address: {$ip}");
        }

        return new self($normalized);
    }

    public static function tryFromString(string $ip): ?self
    {
        try {
            return self::fromString($ip);
        } catch (InvalidArgumentException) {
            return null;
        }
    }


    public static function isValid(string $ip): bool
    {
        return self::normalize(trim($ip)) !== null;
    }

    public static function isValidV4(string $ip): bool
    {
        return filter_var(trim($ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    public static function isValidV6(string $ip): bool
    {
        return filter_var(trim($ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }


    public function isV4(): bool
    {
        return $this->version === IpVersion::V4;
    }

    public function isV6(): bool
    {
        return $this->version === IpVersion::V6;
    }


    /**
     * Returns true for RFC 1918 private ranges:
     * 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 and IPv6 fc00::/7.
     *
     * Note: loopback, link-local, multicast and other reserved ranges are NOT
     * considered private by this method. Use isLoopback(), isLinkLocal(),
     * isMulticast() or isPublic() as needed; !isPublic() does not equal isPrivate().
     */
    public function isPrivate(): bool
    {
        return $this->isInAnyRange(self::PRIVATE_RANGES);
    }

    /**
     * Returns true for loopback: 127.0.0.0/8 or ::1
     */
    public function isLoopback(): bool
    {
        return $this->isInAnyRange(self::LOOPBACK_RANGES);
    }

    /**
     * Returns true for link-local: 169.254.0.0/16 or fe80::/10
     */
    public function isLinkLocal(): bool
    {
        return $this->isInAnyRange(self::LINK_LOCAL_RANGES);
    }

    /**
     * Returns true for multicast: 224.0.0.0/4 or ff00::/8
     */
    public function isMulticast(): bool
    {
        return $this->isInAnyRange(self::MULTICAST_RANGES);
    }

    /**
     * Returns true if the address is publicly routable.
     * Uses FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE to correctly
     * exclude carrier-grade NAT, documentation, benchmarking and future-use ranges
     * (100.64.0.0/10, 192.0.2.0/24, 198.18.0.0/15, 240.0.0.0/4, 2001:db8::/32, etc.)
     *
     * Note: isPublic() covers a broader set of exclusions than isPrivate().
     * Loopback (127.0.0.1) returns false for both; they are not symmetric opposites.
     */
    public function isPublic(): bool
    {
        return filter_var(
            $this->value,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        ) !== false;
    }


    /**
     * Checks whether the IP falls within a CIDR range.
     * Returns false on version mismatch, invalid range, or invalid prefix.
     *
     * Example: $ip->isInRange('192.168.1.0/24')
     *          $ip->isInRange('2001:db8::/32')
     */
    public function isInRange(string $cidr): bool
    {
        [$range, $prefixRaw] = explode('/', $cidr, 2) + [1 => null];

        $normalizedRange = self::normalize($range);

        if ($normalizedRange === null) {
            return false;
        }

        // Reject version mismatch (IPv4 IP vs IPv6 CIDR and vice versa)
        if ($this->isV6() !== str_contains($normalizedRange, ':')) {
            return false;
        }

        // No prefix means exact match.
        if ($prefixRaw === null) {
            return $this->value === $normalizedRange;
        }

        // Strict integer check: reject '/abc', '/1foo', '/-1', '/+12', '/00', '/01'
        if (!ctype_digit($prefixRaw) || (string)(int)$prefixRaw !== $prefixRaw) {
            return false;
        }

        $prefix = (int) $prefixRaw;

        if ($this->isV4() && $prefix > 32) {
            return false;
        }

        if ($this->isV6() && $prefix > 128) {
            return false;
        }

        return $this->isV4()
            ? $this->isInRangeV4($normalizedRange, $prefix)
            : $this->isInRangeV6($normalizedRange, $prefix);
    }

    /**
     * @param string[] $cidrs
     */
    public function isInAnyRange(array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if ($this->isInRange($cidr)) {
                return true;
            }
        }

        return false;
    }


    /**
     * Returns an IPv6 representation of this address for canonical comparison.
     * IPv4 is converted to its IPv6-mapped form (::ffff:x.x.x.x).
     * Native IPv6 addresses are returned as-is.
     *
     * Note: use equalsCanonical() if you need cross-version equality.
     */
    public function toMappedV6(): self
    {
        if ($this->isV6()) {
            return $this;
        }

        return self::fromString('::ffff:' . $this->value);
    }

    /**
     * Returns packed binary representation (suitable for storage and sorting).
     * IPv4 -> 4 bytes, IPv6 -> 16 bytes.
     *
     * @throws \RuntimeException If the normalized address cannot be packed.
     */
    public function toBinary(): string
    {
        $packed = inet_pton($this->value);

        if ($packed === false) {
            throw new \RuntimeException("Failed to pack IP: {$this->value}");
        }

        return $packed;
    }

    /**
     * Returns numeric string representation.
     * Uses GMP to correctly handle 128-bit IPv6 numbers.
     *
     * Requires the GMP extension (php-gmp).
     *
     * @throws \RuntimeException If the GMP extension is unavailable.
     */
    public function toLong(): string
    {
        if (!function_exists('gmp_init')) {
            throw new \RuntimeException(
                'The GMP extension is required for numeric IP conversion (php-gmp).'
            );
        }

        return gmp_strval(gmp_init(bin2hex($this->toBinary()), 16));
    }


    /**
     * Masks the IP for logs and UI.
     * IPv4: "192.168.1.100" -> "192.168.1.***"
     * IPv6: "2001:db8::1"   -> "2001:db8::****"
     */
    public function masked(): string
    {
        if ($this->isV4()) {
            $parts    = explode('.', $this->value);
            $parts[3] = '***';

            return implode('.', $parts);
        }

        $pos = strrpos($this->value, ':');

        return substr($this->value, 0, $pos + 1) . '****';
    }


    /**
     * Compares addresses by their normalized value.
     * IPv4 and its IPv6-mapped form are NOT considered equal.
     * Use equalsCanonical() for cross-version comparison.
     */
    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }

    /**
     * Compares addresses across versions.
     * "127.0.0.1" and "::ffff:127.0.0.1" are considered equal.
     */
    public function equalsCanonical(self $other): bool
    {
        return $this->toMappedV6()->value === $other->toMappedV6()->value;
    }


    public function jsonSerialize(): string
    {
        return $this->value;
    }

    public function __toString(): string
    {
        return $this->value;
    }


    private static function normalize(string $ip): ?string
    {
        $packed = inet_pton($ip);

        if ($packed === false) {
            return null;
        }

        $normalized = inet_ntop($packed);

        return $normalized !== false ? $normalized : null;
    }

    private function isInRangeV4(string $range, int $prefix): bool
    {
        $ipLong    = ip2long($this->value);
        $rangeLong = ip2long($range);

        if ($ipLong === false || $rangeLong === false) {
            return false;
        }

        $mask = $prefix === 0 ? 0 : (~0 << (32 - $prefix));

        return ($ipLong & $mask) === ($rangeLong & $mask);
    }

    private function isInRangeV6(string $range, int $prefix): bool
    {
        $ipPacked    = inet_pton($this->value);
        $rangePacked = inet_pton($range);

        if ($ipPacked === false || $rangePacked === false) {
            return false;
        }

        $fullBytes = (int) floor($prefix / 8);
        $remainder = $prefix % 8;

        if ($fullBytes > 0 && strncmp($ipPacked, $rangePacked, $fullBytes) !== 0) {
            return false;
        }

        if ($remainder !== 0) {
            $mask = 0xFF & (0xFF << (8 - $remainder));

            if ((ord($ipPacked[$fullBytes]) & $mask) !== (ord($rangePacked[$fullBytes]) & $mask)) {
                return false;
            }
        }

        return true;
    }
}
