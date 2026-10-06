<?php
/**
 * For the full copyright and license information, please view the
 * docs/licenses/LICENSE.txt file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Tests\Unit\PrestaShopBundle\Security\Admin;

use Configuration;
use PHPUnit\Framework\TestCase;
use PrestaShopBundle\Entity\Employee\Employee;
use ReflectionProperty;

abstract class TwoFactorSetupTestCase extends TestCase
{
    private array $configurationCache = [];

    protected function setUp(): void
    {
        parent::setUp();

        foreach (['_cache', '_new_cache_shop', '_new_cache_group', '_new_cache_global', '_initialized', 'types'] as $name) {
            $property = new ReflectionProperty(Configuration::class, $name);
            $property->setAccessible(true);
            $this->configurationCache[$name] = $property->getValue();
        }

        Configuration::resetStaticCache();
        $types = new ReflectionProperty(Configuration::class, 'types');
        $types->setAccessible(true);
        $types->setValue(null, []);
        // Keep temporary configuration in memory without loading the database in unit tests.
        $initialized = new ReflectionProperty(Configuration::class, '_initialized');
        $initialized->setAccessible(true);
        $initialized->setValue(null, true);
    }

    protected function tearDown(): void
    {
        foreach ($this->configurationCache as $name => $value) {
            $property = new ReflectionProperty(Configuration::class, $name);
            $property->setAccessible(true);
            $property->setValue(null, $value);
        }

        parent::tearDown();
    }

    protected function setGlobalTwoFactorEnabled(bool $enabled): void
    {
        Configuration::set('PS_BACKOFFICE_2FA', (int) $enabled, 0, 0);
        self::assertSame((int) $enabled, Configuration::getGlobalValue('PS_BACKOFFICE_2FA'));
    }

    protected function createEmployee(bool $required, bool $enabled, bool $email, bool $totp): Employee
    {
        $employee = new Employee();
        $employee->setEmail('employee@example.com');
        $employee->setTwoFactorRequired($required);
        $employee->setTwoFactorEnabled($enabled);
        $employee->setTwoFactorEmailEnabled($email);

        // The entity has no public setters for its ID or TOTP enabled flag.
        foreach (['id' => 42, 'twoFactorTotEnabled' => $totp] as $name => $value) {
            $property = new ReflectionProperty(Employee::class, $name);
            $property->setAccessible(true);
            $property->setValue($employee, $value);
        }

        return $employee;
    }

    public static function setupStates(): iterable
    {
        // global enabled, required, employee enabled, email enabled, TOTP enabled, setup redirect
        yield 'globally disabled with employee 2FA disabled' => [false, true, false, false, false, false];
        yield 'globally disabled with no provider' => [false, true, true, false, false, false];
        yield 'enabled with employee 2FA disabled' => [true, true, false, false, false, true];
        yield 'enabled with no provider' => [true, true, true, false, false, true];
        yield 'completed email setup' => [true, true, true, true, false, false];
        yield 'completed TOTP setup' => [true, true, true, false, true, false];
        yield 'no setup requirement' => [true, false, false, false, false, false];
    }
}
