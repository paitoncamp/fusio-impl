<?php
/*
 * Fusio
 * A web-application to create dynamically RESTful APIs
 *
 * Copyright (C) 2015-2018 Christoph Kappestein <christoph.kappestein@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace Fusio\Impl\Tests\Filter;

use Fusio\Engine\Model\App;
use Fusio\Engine\Model\User;
use Fusio\Impl\Filter\Authentication;
use Fusio\Impl\Loader\Context;
use Fusio\Impl\Tests\DbTestCase;
use Fusio\Impl\Tests\Fixture;
use PSX\Framework\Test\Environment;
use PSX\Http\Filter\FilterChain;
use PSX\Http\Request;
use PSX\Http\Response;
use PSX\Uri\Uri;

/**
 * AuthenticationTest
 *
 * @author  Christoph Kappestein <christoph.kappestein@gmail.com>
 * @license http://www.gnu.org/licenses/agpl-3.0
 * @link    http://fusio-project.org
 */
class AuthenticationTest extends DbTestCase
{
    public function testHandle()
    {
        $context  = $this->newContext();
        $request  = new Request(new Uri('/foo'), 'GET', ['Content-Type' => ['application/json'], 'User-Agent' => ['FooAgent 1.0'], 'Authorization' => ['Bearer b41344388feed85bc362e518387fdc8c81b896bfe5e794131e1469770571d873']]);
        $response = new Response();

        $filterChain = $this->getMockBuilder(FilterChain::class)
            ->setMethods(['handle'])
            ->getMock();

        $filterChain->expects($this->once())
            ->method('handle')
            ->with($this->equalTo($request), $this->equalTo($response));

        $appRepository  = Environment::getService('app_repository');
        $userRepository = Environment::getService('user_repository');
        $projectKey     = Environment::getConfig()->get('fusio_project_key');

        $authentication = new Authentication($this->connection, $context, $projectKey, $appRepository, $userRepository);
        $authentication->handle($request, $response, $filterChain);

        $app  = $context->getApp();
        $user = $context->getUser();

        $this->assertInstanceOf(App::class, $app);
        $this->assertEquals('Foo-App', $app->getName());
        $this->assertEquals('5347307d-d801-4075-9aaa-a21a29a448c5', $app->getAppKey());
        $this->assertInstanceOf(User::class, $user);
        $this->assertEquals('Consumer', $user->getName());
    }

    /**
     * @expectedException \PSX\Http\Exception\UnauthorizedException
     */
    public function testHandleInvalidToken()
    {
        $context  = $this->newContext();
        $request  = new Request(new Uri('/foo'), 'GET', ['Content-Type' => ['application/json'], 'User-Agent' => ['FooAgent 1.0'], 'Authorization' => ['Bearer foobar']]);
        $response = new Response();

        $filterChain = $this->getMockBuilder(FilterChain::class)
            ->setMethods(['handle'])
            ->getMock();

        $filterChain->expects($this->never())
            ->method('handle')
            ->with($this->equalTo($request), $this->equalTo($response));

        $appRepository  = Environment::getService('app_repository');
        $userRepository = Environment::getService('user_repository');
        $projectKey     = Environment::getConfig()->get('fusio_project_key');

        $authentication = new Authentication($this->connection, $context, $projectKey, $appRepository, $userRepository);
        $authentication->handle($request, $response, $filterChain);
    }

    /**
     * @expectedException \PSX\Http\Exception\UnauthorizedException
     */
    public function testHandleInvalidAuthType()
    {
        $context  = $this->newContext();
        $request  = new Request(new Uri('/foo'), 'GET', ['Content-Type' => ['application/json'], 'User-Agent' => ['FooAgent 1.0'], 'Authorization' => ['Basic foobar']]);
        $response = new Response();

        $filterChain = $this->getMockBuilder(FilterChain::class)
            ->setMethods(['handle'])
            ->getMock();

        $filterChain->expects($this->never())
            ->method('handle')
            ->with($this->equalTo($request), $this->equalTo($response));

        $appRepository  = Environment::getService('app_repository');
        $userRepository = Environment::getService('user_repository');
        $projectKey     = Environment::getConfig()->get('fusio_project_key');

        $authentication = new Authentication($this->connection, $context, $projectKey, $appRepository, $userRepository);
        $authentication->handle($request, $response, $filterChain);
    }

    /**
     * @expectedException \PSX\Http\Exception\UnauthorizedException
     */
    public function testHandleNoAuthorizationHeader()
    {
        $context  = $this->newContext();
        $request  = new Request(new Uri('/foo'), 'GET', ['Content-Type' => ['application/json'], 'User-Agent' => ['FooAgent 1.0']]);
        $response = new Response();

        $filterChain = $this->getMockBuilder(FilterChain::class)
            ->setMethods(['handle'])
            ->getMock();

        $filterChain->expects($this->never())
            ->method('handle')
            ->with($this->equalTo($request), $this->equalTo($response));

        $appRepository  = Environment::getService('app_repository');
        $userRepository = Environment::getService('user_repository');
        $projectKey     = Environment::getConfig()->get('fusio_project_key');

        $authentication = new Authentication($this->connection, $context, $projectKey, $appRepository, $userRepository);
        $authentication->handle($request, $response, $filterChain);
    }

    private function newContext()
    {
        $context = new Context();
        $context->setRouteId(Fixture::getLastRouteId() + 1);

        return $context;
    }
}
