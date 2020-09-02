<?php
/*
 * Fusio
 * A web-application to create dynamically RESTful APIs
 *
 * Copyright (C) 2020 Wira M. S (wira.msukoco@gmail.com)
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

namespace Fusio\Impl\Service\Security;

use Doctrine\DBAL\Connection;
use Firebase\JWT\JWT;
use Fusio\Engine\Repository\AppInterface;
use Fusio\Engine\Repository\UserInterface;
use Fusio\Impl\Loader\Context;
use Fusio\Impl\Table\App\Token as AppToken;
use Fusio\Engine\Model;
use PSX\Http\Exception\UnauthorizedException;
use PSX\Oauth2\Authorization\Exception\InvalidScopeException;

/**
 * TenantValidator
 *
 * @author  Wira M. S (wira.msukoco@gmail.com)
 * @license http://www.gnu.org/licenses/agpl-3.0
 * @link    http://fusio-project.org
 */
class TenantValidator
{
    /**
     * @var \Doctrine\DBAL\Connection 
     */
    private $connection;

    /**
     * @var string 
     */
    private $projectKey;

    /**
     * @var \Fusio\Engine\Repository\AppInterface
     */
    protected $appRepository;

    /**
     * @var \Fusio\Engine\Repository\UserInterface
     */
    protected $userRepository;

    /**
     * @param \Doctrine\DBAL\Connection $connection
     * @param string $projectKey
     */
    public function __construct(Connection $connection, string $projectKey, AppInterface $appRepository, UserInterface $userRepository)
    {
        $this->connection = $connection;
        $this->projectKey = $projectKey;
        $this->appRepository = $appRepository;
        $this->userRepository = $userRepository;
    }

    public function assertAuthorization(string $requestMethod, $tenantId, Context $context)
    {
        if ($requestMethod === 'OPTIONS') {
            $needsAuth = false;
        } else {
            $method = $context->getMethod();
            if (is_array($method)) {
                $needsAuth = !$method['public'];
            } else {
                $needsAuth = true;
            }
        }

        $requestMethod = $requestMethod == 'HEAD' ? 'GET' : $requestMethod;

        // tenantId is required if the method is not public.
        if (!empty($tenantId)) {
            $tenantIdPart= $tenantId;

            $params = array(
                'realm' => 'Tenancy',
            );

			$isValidTenantId = false;

			try {
				//TO DO : validate TenantId
				$isValidTenantId = $this->validateTenantId($tenantIdPart);
				if($isValidTenantId){
					return true;
				} else {
					throw new UnauthorizedException('Unknown TenantId', 'Tenancy', $params);
				}
			} catch (\UnexpectedValueException $e) {
				throw new UnauthorizedException($e->getMessage(), 'Tenancy', $params);
			}
		}else {
            throw new UnauthorizedException('Missing tenantId header', 'Tenancy', null);
        } 

        return true;
    }
	
	/**
	* @param string $tenantId
	* return true|false
	*/
	private function validateTenantId($tenantId)
	{
		$sql = "SELECT DISTINCT 1
                  FROM fusio_user_attribute user_attribute inner join fusio_user user on user_attribute.user_id = user.id
                 WHERE 
				 user_attribute.name='tenant_uid'
				 user_attribute.value = :tenantId
                   AND user.status = 0
                 ";

        $validTenantId = $this->connection->fetchAssoc($sql, array(
            'tenantId'  => $tenantId
        ));
		return !empty($validTenantId);
	}
    
    
}
