<?php
/*
 * Fusio
 * A web-application to create dynamically RESTful APIs
 *
 * Copyright (C) 2015-2016 Christoph Kappestein <k42b3.x@gmail.com>
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

namespace Fusio\Impl\Tests\Action;

use Fusio\Impl\Action\MqBeanstalk;
use Fusio\Impl\Tests\ActionTestCaseTrait;
use Fusio\Impl\App;
use Fusio\Impl\Tests\DbTestCase;
use Fusio\Impl\Form\Builder;
use PSX\Cache;
use PSX\Record\Record;
use PSX\Framework\Test\Environment;

/**
 * MqBeanstalkTest
 *
 * @author  Christoph Kappestein <k42b3.x@gmail.com>
 * @license http://www.gnu.org/licenses/agpl-3.0
 * @link    http://fusio-project.org
 */
class MqBeanstalkTest extends DbTestCase
{
    use ActionTestCaseTrait;

    public function testHandle()
    {
        // connection
        $connection = $this->getMock('Pheanstalk\Pheanstalk', ['useTube', 'put'], [], '', false);

        $connection->expects($this->once())
            ->method('useTube')
            ->with($this->equalTo('foo'))
            ->will($this->returnValue($connection));

        $connection->expects($this->once())
            ->method('put')
            ->with($this->callback(function ($body) {
                $this->assertJsonStringEqualsJsonString('{"foo": "bar"}', $body);

                return true;
            }))
            ->will($this->returnValue($connection));

        // connector
        $connector = $this->getMock('Fusio\Engine\ConnectorInterface', ['getConnection'], [], '', false);

        $connector->expects($this->once())
            ->method('getConnection')
            ->with($this->equalTo(1))
            ->will($this->returnValue($connection));

        $action = new MqBeanstalk();
        $action->setConnection(Environment::getService('connection'));
        $action->setConnector($connector);
        $action->setResponse(Environment::getService('response'));

        $parameters = $this->getParameters([
            'connection' => 1,
            'queue'      => 'foo',
        ]);

        $body = Record::fromArray([
            'foo' => 'bar'
        ]);

        $response = $action->handle($this->getRequest('POST', [], [], [], $body), $parameters, $this->getContext());

        $body = [
            'success' => true,
            'message' => 'Push was successful'
        ];

        $this->assertInstanceOf('Fusio\Engine\ResponseInterface', $response);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals([], $response->getHeaders());
        $this->assertEquals($body, $response->getBody());
    }

    public function testConfigure()
    {
        $action  = new MqBeanstalk();
        $builder = new Builder();
        $factory = Environment::getService('form_element_factory');

        $action->configure($builder, $factory);

        $this->assertInstanceOf('Fusio\Impl\Form\Container', $builder->getForm());
    }
}
