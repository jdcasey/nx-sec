/*
 * Copyright (c) 2011 Red Hat, Inc.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see 
 * <http://www.gnu.org/licenses>.
 */

package com.redhat.rcm.nexus.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.sonatype.nexus.security.filter.authc.NexusSecureHttpAuthenticationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

public class RemoteUserNxAuthenticationFilter
    extends NexusSecureHttpAuthenticationFilter
{

    private final Log logger = LogFactory.getLog( this.getClass() );

    @Override
    protected AuthenticationToken createToken( final ServletRequest request, final ServletResponse response )
    {
        if ( request instanceof HttpServletRequest )
        {
            final HttpServletRequest req = (HttpServletRequest) request;
            final String remoteUser = req.getHeader( "REMOTE_USER" );

            if ( remoteUser != null )
            {
                logger.info( "Authenticating via REMOTE_USER: '" + remoteUser + "'..." );
                return new UsernamePasswordToken( remoteUser, "REMOTE_USER" );
            }
        }

        logger.info( "Authenticating conventionally..." );
        return super.createToken( request, response );
    }

}
