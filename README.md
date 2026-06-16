# Componenta IP Address

IPv4/IPv6 value object with validation, normalization, classification, CIDR checks, masking, binary conversion, and JSON/string serialization.

Use it for request metadata, access rules, audit logs, and infrastructure code that should not pass raw IP strings around.

## Installation

```bash
composer require componenta/ip-address
```

## Related Packages

This package validates IP addresses without neighboring Componenta packages.

| Package | Why it may be used nearby |
|---|---|
| `componenta/http-trusted-proxy-middleware` | Trusted proxy middleware can expose client IP values on the request. |
| `componenta/policy` | Authorization policies can use IP/CIDR checks as context. |
| `componenta/validation` | Can validate raw user input before creating `IpAddress`. |

## Usage

```php
use Componenta\Stdlib\IpAddress;

$ip = IpAddress::fromString('192.168.1.10');

(string) $ip;              // "192.168.1.10"
$ip->version->name;        // "V4"
$ip->isPrivate();          // true
$ip->isPublic();           // false
$ip->isInRange('192.168.1.0/24'); // true
$ip->masked();             // "192.168.1.***"
```

## Constructors And Validation

- `fromString()` validates and normalizes or throws `InvalidArgumentException`
- `tryFromString()` returns `null` for invalid input
- `isValid()`, `isValidV4()`, and `isValidV6()` perform static checks

Normalization uses `inet_pton()`/`inet_ntop()`.

## Classification

The object can detect:

- IPv4 vs IPv6
- RFC 1918/private ranges and IPv6 unique local range
- loopback
- link-local
- multicast
- public routability

`isPublic()` is not the inverse of `isPrivate()`. Reserved, documentation, loopback, multicast, and link-local ranges may be neither public nor private.

## CIDR And Conversion

`isInRange()` returns `false` for invalid CIDR input, invalid prefix, or IP version mismatch.

`toBinary()` returns packed binary form. `toLong()` returns a numeric string and requires the GMP extension for IPv6-safe conversion.

## Equality

- `equals()` compares normalized values and does not treat IPv4 and IPv4-mapped IPv6 as equal
- `equalsCanonical()` maps IPv4 to IPv6 first and can compare across versions
