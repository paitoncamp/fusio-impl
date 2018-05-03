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

namespace Fusio\Impl\Tests\Export;

use Fusio\Impl\Tests\Fixture;
use PSX\Framework\Test\ControllerDbTestCase;
use PSX\Framework\Test\Environment;

/**
 * WsdlTest
 *
 * @author  Christoph Kappestein <christoph.kappestein@gmail.com>
 * @license http://www.gnu.org/licenses/agpl-3.0
 * @link    http://fusio-project.org
 */
class WsdlTest extends ControllerDbTestCase
{
    public function getDataSet()
    {
        return Fixture::getDataSet();
    }

    /**
     * @dataProvider providerDebugStatus
     */
    public function testGetResource($debug)
    {
        Environment::getContainer()->get('config')->set('psx_debug', $debug);

        $response = $this->sendRequest('/export/wsdl/*/foo', 'GET', array(
            'User-Agent' => 'Fusio TestCase',
        ));

        $this->assertEquals(410, $response->getStatusCode());
    }

    public function providerDebugStatus()
    {
        return [
            [true],
            [false],
        ];
    }
}
