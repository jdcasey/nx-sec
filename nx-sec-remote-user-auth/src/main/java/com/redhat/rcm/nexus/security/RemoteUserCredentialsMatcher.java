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
import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.component.annotations.Requirement;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authc.credential.CredentialsMatcher;
import org.jsecurity.realm.AuthenticatingRealm;
import org.jsecurity.realm.Realm;
import org.sonatype.security.realms.XmlAuthenticatingRealm;

@Component( role = CredentialsMatcher.class, hint = "remote-user", description = "REMOTE_USER Credentials Matcher" )
public class RemoteUserCredentialsMatcher
    implements CredentialsMatcher
{

    private final Log logger = LogFactory.getLog( this.getClass() );

    @Requirement( role = Realm.class, hint = XmlAuthenticatingRealm.ROLE )
    private AuthenticatingRealm delegate;

    @Override
    public boolean doCredentialsMatch( final AuthenticationToken token, final AuthenticationInfo info )
    {
        if ( ( info instanceof RemoteUserInfo ) && ( token instanceof UsernamePasswordToken ) )
        {
            final UsernamePasswordToken tok = (UsernamePasswordToken) token;
            final RemoteUserInfo inf = (RemoteUserInfo) info;

            logger.info( "verifying remote-user authentication in credentials matcher..." );
            return tok.getUsername().equals( inf.getUsername() );
        }

        logger.info( "verifying conventional authentication info in credentials matcher..." );
        return delegate.getCredentialsMatcher().doCredentialsMatch( token, info );
    }

}
