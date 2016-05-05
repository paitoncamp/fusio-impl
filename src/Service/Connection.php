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

namespace Fusio\Impl\Service;

use Fusio\Engine\Parser\ParserInterface;
use Fusio\Impl\Form\Container;
use Fusio\Impl\Form\Element;
use Fusio\Impl\Table\Connection as TableConnection;
use PSX\Http\Exception as StatusCode;
use PSX\Model\Common\ResultSet;
use PSX\OpenSsl\OpenSsl;
use PSX\Sql\Condition;
use PSX\Sql\Fields;
use PSX\Sql\Sql;

/**
 * Connection
 *
 * @author  Christoph Kappestein <k42b3.x@gmail.com>
 * @license http://www.gnu.org/licenses/agpl-3.0
 * @link    http://fusio-project.org
 */
class Connection
{
    const CIPHER_METHOD = 'AES-128-CBC';

    protected $connectionTable;
    protected $connectionParser;
    protected $secretKey;

    public function __construct(TableConnection $connectionTable, ParserInterface $connectionParser, $secretKey)
    {
        $this->connectionTable  = $connectionTable;
        $this->connectionParser = $connectionParser;
        $this->secretKey        = $secretKey;
    }

    public function getAll($startIndex = 0, $search = null)
    {
        $condition = !empty($search) ? new Condition(['name', 'LIKE', '%' . $search . '%']) : null;

        return new ResultSet(
            $this->connectionTable->getCount($condition),
            $startIndex,
            16,
            $this->connectionTable->getAll(
                $startIndex, 
                16, 
                'id', 
                Sql::SORT_DESC, 
                $condition, 
                Fields::blacklist(['class', 'config'])
            )
        );
    }

    public function get($connectionId)
    {
        $connection = $this->connectionTable->get($connectionId);

        if (!empty($connection)) {
            $config = self::decryptConfig($connection['config'], $this->secretKey);

            // remove all password fields from the config
            if (!empty($config) && is_array($config)) {
                $form = $this->connectionParser->getForm($connection['class']);
                if ($form instanceof Container) {
                    $elements = $form->getElements();
                    foreach ($elements as $element) {
                        if ($element instanceof Element\Input && $element['type'] == 'password') {
                            if (isset($config[$element['name']])) {
                                unset($config[$element['name']]);
                            }
                        }
                    }
                }
            } else {
                $config = new \stdClass();
            }

            $connection['config'] = $config;

            return $connection;
        } else {
            throw new StatusCode\NotFoundException('Could not find connection');
        }
    }

    public function create($name, $class, $config)
    {
        // check whether connection exists
        $condition  = new Condition();
        $condition->equals('name', $name);

        $connection = $this->connectionTable->getOneBy($condition);

        if (!empty($connection)) {
            throw new StatusCode\BadRequestException('Connection already exists');
        }

        // create connection
        $this->connectionTable->create(array(
            'name'   => $name,
            'class'  => $class,
            'config' => self::encryptConfig($config, $this->secretKey),
        ));
    }

    public function update($connectionId, $name, $class, $config)
    {
        $connection = $this->connectionTable->get($connectionId);

        if (!empty($connection)) {
            $this->connectionTable->update(array(
                'id'     => $connection->id,
                'name'   => $name,
                'class'  => $class,
                'config' => self::encryptConfig($config, $this->secretKey),
            ));
        } else {
            throw new StatusCode\NotFoundException('Could not find connection');
        }
    }

    public function delete($connectionId)
    {
        $connection = $this->connectionTable->get($connectionId);

        if (!empty($connection)) {
            $this->connectionTable->delete(array(
                'id' => $connection->id
            ));
        } else {
            throw new StatusCode\NotFoundException('Could not find connection');
        }
    }

    public static function encryptConfig($config, $secretKey)
    {
        if (empty($config)) {
            return null;
        }

        $iv   = OpenSsl::randomPseudoBytes(16);
        $data = serialize($config);
        $data = OpenSsl::encrypt($data, self::CIPHER_METHOD, $secretKey, 0, $iv);

        return base64_encode($iv) . '.' . $data;
    }

    public static function decryptConfig($data, $secretKey)
    {
        if (empty($data)) {
            return [];
        }

        $parts = explode('.', $data, 2);
        if (count($parts) == 2) {
            list($iv, $data) = $parts;

            $config = OpenSsl::decrypt($data, self::CIPHER_METHOD, $secretKey, 0, base64_decode($iv));
            $config = unserialize($config);

            return $config;
        } else {
            return [];
        }
    }
}
