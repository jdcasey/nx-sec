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

import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.personality.plexus.lifecycle.phase.Initializable;
import org.codehaus.plexus.personality.plexus.lifecycle.phase.InitializationException;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authc.credential.CredentialsMatcher;
import org.jsecurity.authz.AuthorizationInfo;
import org.jsecurity.realm.AuthorizingRealm;
import org.jsecurity.realm.Realm;
import org.jsecurity.subject.PrincipalCollection;

import java.util.Arrays;

@Component( role = Realm.class, hint = RemoteUserRealm.ROLE, description = "REMOTE_USER NOP Authenticating Realm" )
public class RemoteUserRealm
    extends AuthorizingRealm
    implements Initializable, Realm
{

    public static final String ROLE = "RemoteUserRealm";

    private static final char[] REMOTE_USER_PASSWORD_CHARS = "REMOTE_USER".toCharArray();

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo( final PrincipalCollection principals )
    {
        return null;
    }

    public void initialize()
        throws InitializationException
    {
        setCredentialsMatcher( new CredentialsMatcher()
        {
            @Override
            public boolean doCredentialsMatch( final AuthenticationToken token, final AuthenticationInfo info )
            {
                if ( ( info instanceof RemoteUserInfo ) && ( token instanceof UsernamePasswordToken ) )
                {
                    final UsernamePasswordToken tok = (UsernamePasswordToken) token;
                    final RemoteUserInfo inf = (RemoteUserInfo) info;

                    return tok.getUsername().equals( inf.getUsername() );
                }

                return false;
            }
        } );
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo( final AuthenticationToken token )
        throws AuthenticationException
    {
        if ( token instanceof UsernamePasswordToken )
        {
            final UsernamePasswordToken tok = (UsernamePasswordToken) token;
            if ( Arrays.equals( REMOTE_USER_PASSWORD_CHARS, REMOTE_USER_PASSWORD_CHARS ) )
            {
                return new RemoteUserInfo( tok.getUsername(), getName() );
            }
        }

        return null;
    }

}
