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
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.sonatype.security.realms.XmlAuthenticatingRealm;

import javax.inject.Inject;
import javax.inject.Named;

import java.util.Arrays;

@Named( RemoteUserAuthenticationRealm.ID )
public class RemoteUserAuthenticationRealm
    extends AuthorizingRealm
    implements Realm
{

    public static final String ID = "RemoteUserAuthenticationRealm";

    private static final char[] REMOTE_USER_PASSWORD_CHARS = "REMOTE_USER".toCharArray();

//    @Inject
//    @Named( XmlAuthenticatingRealm.ROLE )
    private final AuthenticatingRealm delegate;

//    @Inject
//    @Named( "remote-user" )
    private final CredentialsMatcher credentialsMatcher;

    private final Log logger = LogFactory.getLog( this.getClass() );
    
    @Inject
    public RemoteUserAuthenticationRealm( @Named( XmlAuthenticatingRealm.ROLE ) Realm delegate, 
                                          @Named( RemoteUserCredentialsMatcher.ID ) CredentialsMatcher credentialsMatcher )
    {
        this.delegate = (AuthenticatingRealm) delegate;
        this.credentialsMatcher = credentialsMatcher;
    }

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
                logger.info( "creating remote-user authentication info for: " + tok.getUsername() );
                final String remoteUser = tok.getUsername();
                return new RemoteUserInfo( remoteUser, getName() );
            }
        }

        logger.warn( "PASS-THROUGH: creating conventional authentication info..." );
        return delegate.getAuthenticationInfo( token );
    }
}
