<?php
/**
 * For the full copyright and license information, please view the
 * docs/licenses/LICENSE.txt file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Tests\Unit\PrestaShopBundle\Security\Admin;

use PrestaShopBundle\Entity\Repository\EmployeeRepository;
use PrestaShopBundle\Security\Admin\AdminAuthenticationSuccessHandler;
use PrestaShopBundle\Security\Admin\EmployeeHomepageProvider;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

final class AdminAuthenticationSuccessHandlerTest extends TwoFactorSetupTestCase
{
    /**
     * @dataProvider redirectStates
     */
    public function testSetupEnforcementPreservesNormalRedirects(
        bool $globalEnabled,
        bool $required,
        bool $enabled,
        bool $email,
        bool $totp,
        bool $redirectToSetup,
        ?string $targetPath,
        ?string $homepage,
        string $normalRedirect,
    ): void {
        $this->setGlobalTwoFactorEnabled($globalEnabled);
        $employee = $this->createEmployee($required, $enabled, $email, $totp);
        $repository = $this->createMock(EmployeeRepository::class);
        $repository->method('loadEmployeeByIdentifier')
            ->with('employee@example.com', true)
            ->willReturn($employee);
        $token = $this->createMock(TokenInterface::class);
        $token->method('getUserIdentifier')->willReturn('employee@example.com');
        $homepageProvider = $this->createMock(EmployeeHomepageProvider::class);
        $homepageProvider->expects(!$redirectToSetup && $targetPath === null ? self::once() : self::never())
            ->method('getHomepageUrl')->willReturn($homepage);
        $router = $this->createMock(RouterInterface::class);
        if ($redirectToSetup) {
            $router->expects(self::once())->method('generate')
                ->with('admin_employees_edit', ['employeeId' => 42])
                ->willReturn('/admin/employees/42/edit');
        } elseif ($targetPath === null && $homepage === null) {
            $router->expects(self::once())->method('generate')
                ->with('admin_homepage')->willReturn('/admin/');
        } else {
            $router->expects(self::never())->method('generate');
        }
        $request = Request::create('/admin/login', 'POST');
        if ($targetPath !== null) {
            $session = new Session(new MockArraySessionStorage());
            $session->set('_security.main.target_path', $targetPath);
            $request->setSession($session);
            $request->cookies->set($session->getName(), 'previous-session');
            self::assertTrue($request->hasPreviousSession());
        }

        $response = (new AdminAuthenticationSuccessHandler($homepageProvider, $repository, $router))
            ->onAuthenticationSuccess($request, $token);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame($redirectToSetup ? '/admin/employees/42/edit' : $normalRedirect, $response->getTargetUrl());
        if ($targetPath !== null) {
            self::assertSame($targetPath, $request->getSession()->get('_security.main.target_path'));
        }
    }

    public static function redirectStates(): iterable
    {
        foreach (parent::setupStates() as $setupName => $setup) {
            foreach ([
                'target path' => ['/saved-target', '/employee-homepage', '/saved-target'],
                'employee homepage' => [null, '/employee-homepage', '/employee-homepage'],
                'default homepage' => [null, null, '/admin/'],
            ] as $redirectName => $redirect) {
                yield $setupName . ' / ' . $redirectName => array_merge($setup, $redirect);
            }
        }
    }

    public function testTwoFactorInProgressRedirectsToVerification(): void
    {
        $this->setGlobalTwoFactorEnabled(true);
        $repository = $this->createMock(EmployeeRepository::class);
        $repository->expects(self::never())->method('loadEmployeeByIdentifier');
        $homepageProvider = $this->createMock(EmployeeHomepageProvider::class);
        $homepageProvider->expects(self::never())->method('getHomepageUrl');
        $router = $this->createMock(RouterInterface::class);
        $router->expects(self::once())->method('generate')->with('2fa_login')->willReturn('/admin/2fa');

        $response = (new AdminAuthenticationSuccessHandler($homepageProvider, $repository, $router))
            ->onAuthenticationSuccess(Request::create('/admin/login'), $this->createMock(TwoFactorTokenInterface::class));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/admin/2fa', $response->getTargetUrl());
    }
}
