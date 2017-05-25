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

namespace Fusio\Impl\Backend\View;

use Fusio\Impl\Backend\View\Log\QueryFilter;
use Fusio\Impl\Table;
use PSX\Sql\Fields;
use PSX\Sql\Reference;
use PSX\Sql\Sql;
use PSX\Sql\ViewAbstract;

/**
 * Log
 *
 * @author  Christoph Kappestein <christoph.kappestein@gmail.com>
 * @license http://www.gnu.org/licenses/agpl-3.0
 * @link    http://fusio-project.org
 */
class Log extends ViewAbstract
{
    public function getCollection($startIndex = 0, QueryFilter $filter)
    {
        $condition = $filter->getCondition();

        $definition = [
            'totalResults' => $this->getTable(Table\Log::class)->getCount($condition),
            'startIndex' => $startIndex,
            'itemsPerPage' => 16,
            'entry' => $this->doCollection([$this->getTable(Table\Log::class), 'getAll'], [$startIndex, 16, 'id', Sql::SORT_DESC, $condition, Fields::blacklist(['header', 'body'])], [
                'id' => 'id',
                'appId' => 'appId',
                'routeId' => 'routeId',
                'ip' => 'ip',
                'userAgent' => 'userAgent',
                'method' => 'method',
                'path' => 'path',
                'date' => $this->fieldDateTime('date'),
            ]),
        ];

        return $this->build($definition);
    }

    public function getEntity($id)
    {
        $definition = $this->doEntity([$this->getTable(Table\Log::class), 'get'], [$id], [
            'id' => 'id',
            'appId' => 'appId',
            'routeId' => 'routeId',
            'ip' => 'ip',
            'userAgent' => 'userAgent',
            'method' => 'method',
            'path' => 'path',
            'header' => 'header',
            'body' => 'body',
            'errors' => $this->doCollection([$this->getTable(Table\Log\Error::class), 'getByLogId'], [new Reference('id')], [
                'message' => 'message',
                'trace' => 'trace',
                'file' => 'file',
                'line' => 'line',
            ]),
            'date' => $this->fieldDateTime('date'),
        ]);

        return $this->build($definition);
    }
}
