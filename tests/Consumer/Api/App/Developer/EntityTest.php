<?php
/*
 * Fusio
 * A web-application to create dynamically RESTful APIs
 *
 * Copyright (C) 2015-2017 Christoph Kappestein <christoph.kappestein@gmail.com>
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

namespace Fusio\Impl\Tests\Consumer\Api\App\Developer;

use Fusio\Impl\Table;
use Fusio\Impl\Tests\Fixture;
use PSX\Framework\Test\ControllerDbTestCase;
use PSX\Framework\Test\Environment;

/**
 * EntityTest
 *
 * @author  Christoph Kappestein <christoph.kappestein@gmail.com>
 * @license http://www.gnu.org/licenses/agpl-3.0
 * @link    http://fusio-project.org
 */
class EntityTest extends ControllerDbTestCase
{
    public function getDataSet()
    {
        return Fixture::getDataSet();
    }

    public function testDocumentation()
    {
        $response = $this->sendRequest('/doc/*/consumer/app/developer/2', 'GET', array(
            'User-Agent'    => 'Fusio TestCase',
            'Authorization' => 'Bearer da250526d583edabca8ac2f99e37ee39aa02a3c076c0edc6929095e20ca18dcf'
        ));

        $actual = (string) $response->getBody();
        $expect = <<<'JSON'
{
    "path": "\/consumer\/app\/developer\/$app_id<[0-9]+>",
    "version": "*",
    "status": 1,
    "description": "",
    "schema": {
        "$schema": "http:\/\/json-schema.org\/draft-04\/schema#",
        "id": "urn:schema.phpsx.org#",
        "definitions": {
            "App": {
                "type": "object",
                "title": "app",
                "properties": {
                    "id": {
                        "type": "integer"
                    },
                    "status": {
                        "type": "integer"
                    },
                    "name": {
                        "type": "string",
                        "pattern": "[A-z0-9\\-\\_]{3,64}"
                    },
                    "url": {
                        "type": "string"
                    },
                    "appKey": {
                        "type": "string"
                    },
                    "appSecret": {
                        "type": "string"
                    },
                    "date": {
                        "type": "string",
                        "format": "date-time"
                    },
                    "scopes": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        }
                    }
                },
                "required": [
                    "name",
                    "url"
                ]
            },
            "Message": {
                "type": "object",
                "title": "message",
                "properties": {
                    "success": {
                        "type": "boolean"
                    },
                    "message": {
                        "type": "string"
                    }
                }
            },
            "GET-200-response": {
                "$ref": "#\/definitions\/App"
            },
            "PUT-request": {
                "$ref": "#\/definitions\/App"
            },
            "PUT-200-response": {
                "$ref": "#\/definitions\/Message"
            },
            "DELETE-200-response": {
                "$ref": "#\/definitions\/Message"
            }
        }
    },
    "methods": {
        "GET": {
            "responses": {
                "200": "#\/definitions\/GET-200-response"
            }
        },
        "PUT": {
            "request": "#\/definitions\/PUT-request",
            "responses": {
                "200": "#\/definitions\/PUT-200-response"
            }
        },
        "DELETE": {
            "responses": {
                "200": "#\/definitions\/DELETE-200-response"
            }
        }
    },
    "links": [
        {
            "rel": "openapi",
            "href": "\/export\/openapi\/*\/consumer\/app\/developer\/$app_id<[0-9]+>"
        },
        {
            "rel": "swagger",
            "href": "\/export\/swagger\/*\/consumer\/app\/developer\/$app_id<[0-9]+>"
        },
        {
            "rel": "raml",
            "href": "\/export\/raml\/*\/consumer\/app\/developer\/$app_id<[0-9]+>"
        }
    ]
}
JSON;

        $this->assertJsonStringEqualsJsonString($expect, $actual, $actual);
    }

    public function testGet()
    {
        $response = $this->sendRequest('http://127.0.0.1/consumer/app/developer/2', 'GET', array(
            'User-Agent'    => 'Fusio TestCase',
            'Authorization' => 'Bearer b8f6f61bd22b440a3e4be2b7491066682bfcde611dbefa1b15d2e7f6522d77e2'
        ));

        $body = (string) $response->getBody();
        $body = preg_replace('/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/m', '[datetime]', $body);
        $body = preg_replace('/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/m', '[app_key]', $body);

        $data = json_decode($body);
        $sec  = isset($data->appSecret) ? $data->appSecret : null;
        $body = str_replace(trim(json_encode($sec), '"'), '[app_secret]', $body);

        $expect = <<<'JSON'
{
    "id": 2,
    "userId": 1,
    "status": 1,
    "name": "Consumer",
    "url": "http:\/\/fusio-project.org",
    "appKey": "[app_key]",
    "appSecret": "[app_secret]",
    "date": "[datetime]",
    "scopes": [
        "consumer",
        "authorization"
    ],
    "tokens": [
        {
            "id": 5,
            "userId": 2,
            "status": 1,
            "token": "1b8fca875fc81c78538d541b3ed0557a34e33feaf71c2ecdc2b9ebd40aade51b",
            "scope": [
                "consumer"
            ],
            "ip": "127.0.0.1",
            "expire": "[datetime]",
            "date": "[datetime]"
        },
        {
            "id": 2,
            "userId": 1,
            "status": 1,
            "token": "b8f6f61bd22b440a3e4be2b7491066682bfcde611dbefa1b15d2e7f6522d77e2",
            "scope": [
                "consumer",
                "authorization"
            ],
            "ip": "127.0.0.1",
            "expire": "[datetime]",
            "date": "[datetime]"
        }
    ]
}
JSON;

        $this->assertEquals(200, $response->getStatusCode(), $body);
        $this->assertJsonStringEqualsJsonString($expect, $body, $body);
    }

    public function testPost()
    {
        $response = $this->sendRequest('http://127.0.0.1/consumer/app/developer/2', 'POST', array(
            'User-Agent'    => 'Fusio TestCase',
            'Authorization' => 'Bearer b8f6f61bd22b440a3e4be2b7491066682bfcde611dbefa1b15d2e7f6522d77e2'
        ), json_encode([
            'foo' => 'bar',
        ]));

        $body = (string) $response->getBody();

        $this->assertEquals(405, $response->getStatusCode(), $body);
    }

    public function testPut()
    {
        $response = $this->sendRequest('http://127.0.0.1/consumer/app/developer/2', 'PUT', array(
            'User-Agent'    => 'Fusio TestCase',
            'Authorization' => 'Bearer b8f6f61bd22b440a3e4be2b7491066682bfcde611dbefa1b15d2e7f6522d77e2'
        ), json_encode([
            'status' => 2,
            'name'   => 'Bar',
            'url'    => 'http://microsoft.com',
            'scopes' => ['foo', 'bar']
        ]));

        $body   = (string) $response->getBody();
        $expect = <<<'JSON'
{
    "success": true,
    "message": "App successful updated"
}
JSON;

        $this->assertEquals(200, $response->getStatusCode(), $body);
        $this->assertJsonStringEqualsJsonString($expect, $body, $body);

        // check database
        $sql = Environment::getService('connection')->createQueryBuilder()
            ->select('id', 'status', 'userId', 'name', 'url')
            ->from('fusio_app')
            ->where('id = 2')
            ->getSQL();

        $row = Environment::getService('connection')->fetchAssoc($sql);

        $this->assertEquals(2, $row['id']);
        $this->assertEquals(1, $row['status']);
        $this->assertEquals(1, $row['userId']);
        $this->assertEquals('Bar', $row['name']);
        $this->assertEquals('http://microsoft.com', $row['url']);

        $scopes = Environment::getService('table_manager')->getTable(Table\App\Scope::class)->getAvailableScopes(2);
        $scopes = Table\Scope::getNames($scopes);

        $this->assertEquals(['foo', 'bar'], $scopes);
    }

    public function testDelete()
    {
        $response = $this->sendRequest('http://127.0.0.1/consumer/app/developer/2', 'DELETE', array(
            'User-Agent'    => 'Fusio TestCase',
            'Authorization' => 'Bearer b8f6f61bd22b440a3e4be2b7491066682bfcde611dbefa1b15d2e7f6522d77e2'
        ));

        $body   = (string) $response->getBody();
        $expect = <<<'JSON'
{
    "success": true,
    "message": "App successful deleted"
}
JSON;

        $this->assertEquals(200, $response->getStatusCode(), $body);
        $this->assertJsonStringEqualsJsonString($expect, $body, $body);

        // check database
        $sql = Environment::getService('connection')->createQueryBuilder()
            ->select('id', 'status')
            ->from('fusio_app')
            ->where('id = 2')
            ->getSQL();

        $row = Environment::getService('connection')->fetchAssoc($sql);

        $this->assertEquals(2, $row['id']);
        $this->assertEquals(Table\App::STATUS_DELETED, $row['status']);
    }
}
