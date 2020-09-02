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

namespace Fusio\Impl\Filter;

use Fusio\Impl\Loader\Context;
use Fusio\Impl\Service\Security\TokenValidator;
use Fusio\Impl\Service\Security\TenantValidator;
use PSX\Http\Exception\UnauthorizedException;
use PSX\Http\FilterChainInterface;
use PSX\Http\FilterInterface;
use PSX\Http\RequestInterface;
use PSX\Http\ResponseInterface;

/**
 * TenantAuthentication
 *
 * @author  Wira M. S (wira.msukoco@gmail.com)
 * @license http://www.gnu.org/licenses/agpl-3.0
 * @link    http://fusio-project.org
 */
class TenantAuthentication implements FilterInterface
{
    /**
     * @var \Fusio\Impl\Service\Security\TokenValidator
     */
    protected $tokenValidator;
	
	/**
     * @var \Fusio\Impl\Service\Security\TenantValidator
     */
    protected $tenantValidator;

    /**
     * @var \Fusio\Impl\Loader\Context
     */
    protected $context;

    public function __construct(TokenValidator $tokenValidator, TenantValidator, Context $context)
    {
        $this->tokenValidator = $tokenValidator;
		$this->tenantValidator = $tenantValidator;
        $this->context        = $context;
    }

    public function handle(RequestInterface $request, ResponseInterface $response, FilterChainInterface $filterChain)
    {
        $tokenvalidate_success = $this->tokenValidator->assertAuthorization(
            $request->getMethod(),
            $request->getHeader('Authorization'),
            $this->context
        );
		
		$tenantvalidate_success = $this->tenantValidator->assertAuthorization(
            $request->getMethod(),
            $request->getHeader('TenantId'),
            $this->context
        );

        if ($tokenvalidate_success && $tenantvalidate_success) {
            $filterChain->handle($request, $response);
        } else {
            throw new UnauthorizedException('Could not authorize request', 'Tenancy');
        }
    }
}
