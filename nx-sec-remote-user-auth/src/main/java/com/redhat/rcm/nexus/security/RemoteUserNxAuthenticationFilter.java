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
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.sonatype.nexus.security.filter.authc.NexusSecureHttpAuthenticationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import java.util.Enumeration;

public class RemoteUserNxAuthenticationFilter
    extends NexusSecureHttpAuthenticationFilter
{

    private final Log logger = LogFactory.getLog( this.getClass() );
    
    private static final String HTTPD_NULL = "(null)";
    
    private static final String[] USER_HEADERS = {
      "REMOTE_USER",
      "X_REMOTE_USER",
    };

    @Override
    protected AuthenticationToken createToken( final ServletRequest request, final ServletResponse response )
    {
        if ( request instanceof HttpServletRequest )
        {
            final HttpServletRequest req = (HttpServletRequest) request;
            
            StringBuilder sb = new StringBuilder();
            sb.append( "\n\nHEADERS:" );
            for( Enumeration<String> e = req.getHeaderNames(); e.hasMoreElements(); )
            {
                String name = e.nextElement();
                for( Enumeration<String> vals = req.getHeaders( name ); vals.hasMoreElements(); )
                {
                    sb.append( "\n\t" + name + ": " + vals.nextElement() );
                }
            }
            sb.append( "\n\n" );
            logger.info( sb.toString() );
            
            String remoteUser = null;
            for ( String headerName : USER_HEADERS )
            {
                String val = req.getHeader( headerName );
                if ( val != null && !val.equalsIgnoreCase( HTTPD_NULL ) )
                {
                    remoteUser = val;
                    logger.info( "Authenticating via " + headerName + " header with value: '" + remoteUser + "'..." );
                    break;
                }
            }

            if ( remoteUser != null )
            {
                return new UsernamePasswordToken( remoteUser, "REMOTE_USER" );
            }
        }

        logger.warn( "PASS-THROUGH: Authenticating conventionally..." );
        return super.createToken( request, response );
    }

}
