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

namespace Fusio\Impl\Authorization;

use Fusio\Impl\Filter\Authentication;
use PSX\Http\Filter\UserAgentEnforcer;

/**
 * TenancyProtectionTrait
 *
 * @author  Wira M. S (wira.msukoco@gmail.com)
 * @license http://www.gnu.org/licenses/agpl-3.0
 * @link    http://fusio-project.org
 */
trait TenantProtectionTrait
{
    /**
     * @var \Fusio\Impl\Loader\Context
     */
    protected $context;

    /**
     * @Inject
     * @var \Doctrine\DBAL\Connection
     */
    protected $connection;

    /**
     * @Inject
     * @var \Fusio\Impl\Service\Security\TokenValidator
     */
    protected $securityTokenValidator;
	
	
	/**
     * @Inject
     * @var \Fusio\Impl\Service\Security\TenantValidator
     */
    protected $securityTenantValidator;

    public function getPreFilter()
    {
        // it is required for every request to have an user agent which
        // identifies the client
        $filter[] = new UserAgentEnforcer();

        $filter[] = new Authentication(
            $this->securityTokenValidator,
			$this->securityTenantValidator,
            $this->context
        );

        return $filter;
    }
}
