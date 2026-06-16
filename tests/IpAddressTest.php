<?php

declare(strict_types=1);

namespace Componenta\Stdlib\Tests;

use Componenta\Stdlib\IpAddress;
use Componenta\Stdlib\IpVersion;

it('normalizes and classifies IPv4 addresses', function (): void {
    $ip = IpAddress::fromString('192.168.1.10');

    expect((string) $ip)->toBe('192.168.1.10')
        ->and($ip->version)->toBe(IpVersion::V4)
        ->and($ip->isV4())->toBeTrue()
        ->and($ip->isPrivate())->toBeTrue()
        ->and($ip->isPublic())->toBeFalse()
        ->and($ip->isInRange('192.168.1.0/24'))->toBeTrue();
});

it('normalizes and compares IPv6 addresses canonically', function (): void {
    $ipv4 = IpAddress::fromString('127.0.0.1');
    $mapped = IpAddress::fromString('::ffff:127.0.0.1');

    expect($mapped->version)->toBe(IpVersion::V6)
        ->and($ipv4->equals($mapped))->toBeFalse()
        ->and($ipv4->equalsCanonical($mapped))->toBeTrue();
});

it('rejects invalid addresses and offers nullable construction', function (): void {
    expect(fn () => IpAddress::fromString('not-an-ip'))->toThrow(\InvalidArgumentException::class)
        ->and(IpAddress::tryFromString('not-an-ip'))->toBeNull()
        ->and(IpAddress::isValid('8.8.8.8'))->toBeTrue();
});
