<?php
/**
 * For the full copyright and license information, please view the
 * docs/licenses/LICENSE.txt file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Tests\Unit\PrestaShopBundle\EventListener\Admin;

use PrestaShopBundle\Entity\Repository\EmployeeRepository;
use PrestaShopBundle\EventListener\Admin\RequiredTwoFactorSetupListener;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Routing\RouterInterface;
use Tests\Unit\PrestaShopBundle\Security\Admin\TwoFactorSetupTestCase;

final class RequiredTwoFactorSetupListenerTest extends TwoFactorSetupTestCase
{
    /**
     * @dataProvider setupStates
     */
    public function testSetupEnforcement(
        bool $globalEnabled,
        bool $required,
        bool $enabled,
        bool $email,
        bool $totp,
        bool $redirectToSetup,
    ): void {
        $this->setGlobalTwoFactorEnabled($globalEnabled);
        $employee = $this->createEmployee($required, $enabled, $email, $totp);
        $security = $this->createMock(Security::class);
        $security->method('getUser')->willReturn($employee);
        $repository = $this->createMock(EmployeeRepository::class);
        $repository->expects($globalEnabled ? self::once() : self::never())
            ->method('loadEmployeeByIdentifier')
            ->with('employee@example.com', true)
            ->willReturn($employee);
        $router = $this->createMock(RouterInterface::class);
        $router->expects($redirectToSetup ? self::once() : self::never())
            ->method('generate')
            ->with('admin_employees_edit', ['employeeId' => 42])
            ->willReturn('/admin/employees/42/edit');
        $event = $this->createRequestEvent();

        (new RequiredTwoFactorSetupListener($security, $repository, $router))->onKernelRequest($event);

        if ($redirectToSetup) {
            self::assertInstanceOf(RedirectResponse::class, $event->getResponse());
            self::assertSame('/admin/employees/42/edit', $event->getResponse()->getTargetUrl());
            self::assertTrue($event->isPropagationStopped());
            self::assertSame($event->getRequest()->getUri(), $event->getRequest()->getSession()->get('_security.main.target_path'));
        } else {
            self::assertNull($event->getResponse());
            self::assertFalse($event->isPropagationStopped());
            self::assertSame('/existing-target', $event->getRequest()->getSession()->get('_security.main.target_path'));
        }
    }

    public function testTwoFactorInProgressIsLeftToTheAuthenticationFlow(): void
    {
        $this->setGlobalTwoFactorEnabled(true);
        $security = $this->createMock(Security::class);
        $security->method('getToken')->willReturn($this->createMock(TwoFactorTokenInterface::class));
        $security->expects(self::never())->method('getUser');
        $repository = $this->createMock(EmployeeRepository::class);
        $repository->expects(self::never())->method('loadEmployeeByIdentifier');
        $router = $this->createMock(RouterInterface::class);
        $router->expects(self::never())->method('generate');
        $event = $this->createRequestEvent();

        (new RequiredTwoFactorSetupListener($security, $repository, $router))->onKernelRequest($event);

        self::assertNull($event->getResponse());
        self::assertFalse($event->isPropagationStopped());
        self::assertSame('/existing-target', $event->getRequest()->getSession()->get('_security.main.target_path'));
    }

    private function createRequestEvent(): RequestEvent
    {
        $request = Request::create('/admin/orders');
        $request->attributes->set('_route', 'admin_orders_index');
        $request->setSession(new Session(new MockArraySessionStorage()));
        $request->getSession()->set('_security.main.target_path', '/existing-target');

        return new RequestEvent($this->createMock(HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST);
    }
}
