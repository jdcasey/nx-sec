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
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authc.credential.CredentialsMatcher;
import org.jsecurity.authz.AuthorizationInfo;
import org.jsecurity.realm.AuthenticatingRealm;
import org.jsecurity.realm.AuthorizingRealm;
import org.jsecurity.realm.Realm;
import org.jsecurity.subject.PrincipalCollection;
import org.sonatype.security.realms.XmlAuthenticatingRealm;

import java.util.Arrays;

@Component( role = Realm.class, hint = RemoteUserAuthenticationRealm.HINT, description = "REMOTE_USER NOP Authenticating Realm" )
public class RemoteUserAuthenticationRealm
    extends AuthorizingRealm
    implements Realm
{

    public static final String HINT = "RemoteUserAuthenticationRealm";

    private static final char[] REMOTE_USER_PASSWORD_CHARS = "REMOTE_USER".toCharArray();

    @Requirement( role = Realm.class, hint = XmlAuthenticatingRealm.ROLE )
    private AuthenticatingRealm delegate;

    @Requirement( hint = "remote-user" )
    private CredentialsMatcher credentialsMatcher;

    private final Log logger = LogFactory.getLog( this.getClass() );

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo( final PrincipalCollection principals )
    {
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo( final AuthenticationToken token )
        throws AuthenticationException
    {
        setCredentialsMatcher( credentialsMatcher );

        if ( token instanceof UsernamePasswordToken )
        {
            final UsernamePasswordToken tok = (UsernamePasswordToken) token;
            if ( Arrays.equals( REMOTE_USER_PASSWORD_CHARS, REMOTE_USER_PASSWORD_CHARS ) )
            {
                logger.info( "creating remote-user authentication info..." );
                final String remoteUser = tok.getUsername();
                return new RemoteUserInfo( remoteUser, getName() );
            }
        }

        logger.info( "creating conventional authentication info..." );
        return delegate.getAuthenticationInfo( token );
    }
}
