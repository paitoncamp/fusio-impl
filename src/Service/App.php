<?php
/*
 * Fusio
 * A web-application to create dynamically RESTful APIs
 *
 * Copyright (C) 2015-2020 Christoph Kappestein <christoph.kappestein@gmail.com>
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

use Fusio\Impl\Authorization\TokenGenerator;
use Fusio\Impl\Authorization\UserContext;
use Fusio\Impl\Event\App\CreatedEvent;
use Fusio\Impl\Event\App\DeletedEvent;
use Fusio\Impl\Event\App\UpdatedEvent;
use Fusio\Impl\Event\AppEvents;
use Fusio\Impl\Table;
use PSX\DateTime\DateTime;
use PSX\Http\Exception as StatusCode;
use PSX\Sql\Condition;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

/**
 * App
 *
 * @author  Christoph Kappestein <christoph.kappestein@gmail.com>
 * @license http://www.gnu.org/licenses/agpl-3.0
 * @link    http://fusio-project.org
 */
class App
{
    /**
     * @var \Fusio\Impl\Table\App
     */
    protected $appTable;

    /**
     * @var \Fusio\Impl\Table\Scope
     */
    protected $scopeTable;

    /**
     * @var \Fusio\Impl\Table\App\Scope
     */
    protected $appScopeTable;

    /**
     * @var \Fusio\Impl\Table\App\Token
     */
    protected $appTokenTable;

    /**
     * @var string
     */
    protected $tokenSecret;

    /**
     * @var \Symfony\Component\EventDispatcher\EventDispatcherInterface
     */
    protected $eventDispatcher;

    /**
     * @param \Fusio\Impl\Table\App $appTable
     * @param \Fusio\Impl\Table\Scope $scopeTable
     * @param \Fusio\Impl\Table\App\Scope $appScopeTable
     * @param \Fusio\Impl\Table\App\Token $appTokenTable
     * @param string $tokenSecret
     * @param \Symfony\Component\EventDispatcher\EventDispatcherInterface $eventDispatcher
     */
    public function __construct(Table\App $appTable, Table\Scope $scopeTable, Table\App\Scope $appScopeTable, Table\App\Token $appTokenTable, $tokenSecret, EventDispatcherInterface $eventDispatcher)
    {
        $this->appTable        = $appTable;
        $this->scopeTable      = $scopeTable;
        $this->appScopeTable   = $appScopeTable;
        $this->appTokenTable   = $appTokenTable;
        $this->tokenSecret     = $tokenSecret;
        $this->eventDispatcher = $eventDispatcher;
    }

    public function create($userId, $status, $name, $url, $parameters = null, array $scopes = null, UserContext $context)
    {
        // check whether app exists
        $condition  = new Condition();
        $condition->equals('user_id', $userId);
        $condition->notEquals('status', Table\App::STATUS_DELETED);
        $condition->equals('name', $name);

        $app = $this->appTable->getOneBy($condition);

        if (!empty($app)) {
            throw new StatusCode\BadRequestException('App already exists');
        }

        // parse parameters
        if ($parameters !== null) {
            $parameters = $this->parseParameters($parameters);
        }

        // create app
        $appKey    = TokenGenerator::generateAppKey();
        $appSecret = TokenGenerator::generateAppSecret();

        try {
            $this->appTable->beginTransaction();

            $record = [
                'user_id'    => $userId,
                'status'     => $status,
                'name'       => $name,
                'url'        => $url,
                'parameters' => $parameters,
                'app_key'    => $appKey,
                'app_secret' => $appSecret,
                'date'       => new DateTime(),
            ];

            $this->appTable->create($record);

            $appId = $this->appTable->getLastInsertId();

            if ($scopes !== null) {
                // insert scopes
                $this->insertScopes($appId, $scopes);
            }

            $this->appTable->commit();
        } catch (\Throwable $e) {
            $this->appTable->rollBack();

            throw $e;
        }

        $this->eventDispatcher->dispatch(new CreatedEvent($appId, $record, $scopes, $context), AppEvents::CREATE);

        return $appId;
    }

    public function update($appId, $status, $name, $url, $parameters = null, array $scopes = null, UserContext $context)
    {
        $app = $this->appTable->get($appId);

        if (empty($app)) {
            throw new StatusCode\NotFoundException('Could not find app');
        }

        if ($app['status'] == Table\App::STATUS_DELETED) {
            throw new StatusCode\GoneException('App was deleted');
        }

        // parse parameters
        if ($parameters !== null) {
            $parameters = $this->parseParameters($parameters);
        } else {
            $parameters = $app['parameters'];
        }

        try {
            $this->appTable->beginTransaction();

            $record = [
                'id'         => $app['id'],
                'status'     => $status,
                'name'       => $name,
                'url'        => $url,
                'parameters' => $parameters,
            ];

            $this->appTable->update($record);

            if ($scopes !== null) {
                // delete existing scopes
                $this->appScopeTable->deleteAllFromApp($app['id']);

                // insert scopes
                $this->insertScopes($app['id'], $scopes);
            }

            $this->appTable->commit();
        } catch (\Throwable $e) {
            $this->appTable->rollBack();

            throw $e;
        }

        $this->eventDispatcher->dispatch(new UpdatedEvent($appId, $record, $scopes, $app, $context), AppEvents::UPDATE);
    }

    public function delete($appId, UserContext $context)
    {
        $app = $this->appTable->get($appId);

        if (empty($app)) {
            throw new StatusCode\NotFoundException('Could not find app');
        }

        if ($app['status'] == Table\App::STATUS_DELETED) {
            throw new StatusCode\GoneException('App was deleted');
        }

        $record = [
            'id'     => $app['id'],
            'status' => Table\App::STATUS_DELETED,
        ];

        $this->appTable->update($record);

        $this->eventDispatcher->dispatch(new DeletedEvent($appId, $app, $context), AppEvents::DELETE);
    }

    protected function insertScopes($appId, $scopes)
    {
        if (!empty($scopes) && is_array($scopes)) {
            $scopes = $this->scopeTable->getValidScopes($scopes);

            foreach ($scopes as $scope) {
                $this->appScopeTable->create(array(
                    'app_id'   => $appId,
                    'scope_id' => $scope['id'],
                ));
            }
        }
    }

    protected function parseParameters($parameters)
    {
        parse_str($parameters, $data);

        $params = [];
        foreach ($data as $key => $value) {
            if (!ctype_alnum($key)) {
                throw new StatusCode\BadRequestException('Invalid parameter key only alnum characters are allowed');
            }
            if (!preg_match('/^[\x21-\x7E]*$/', $value)) {
                throw new StatusCode\BadRequestException('Invalid parameter value only printable ascii characters are allowed');
            }
            $params[$key] = $value;
        }

        return http_build_query($params, '', '&');
    }
}
