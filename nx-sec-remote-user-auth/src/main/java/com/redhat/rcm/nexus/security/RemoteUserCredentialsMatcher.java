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
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.Realm;
import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.component.annotations.Requirement;
import org.sonatype.security.realms.XmlAuthenticatingRealm;

import javax.inject.Inject;
import javax.inject.Named;

@Named( RemoteUserCredentialsMatcher.ID )
public class RemoteUserCredentialsMatcher
    implements CredentialsMatcher
{
    
    public static final String ID = "remote-user";

    private final Log logger = LogFactory.getLog( this.getClass() );

//    @Inject
//    @Named( XmlAuthenticatingRealm.ROLE )
    private final AuthenticatingRealm delegate;
    
    @Inject
    public RemoteUserCredentialsMatcher( @Named( XmlAuthenticatingRealm.ROLE ) Realm delegate )
    {
        this.delegate = (AuthenticatingRealm) delegate;
    }

    @Override
    public boolean doCredentialsMatch( final AuthenticationToken token, final AuthenticationInfo info )
    {
        if ( ( info instanceof RemoteUserInfo ) && ( token instanceof UsernamePasswordToken ) )
        {
            final UsernamePasswordToken tok = (UsernamePasswordToken) token;
            final RemoteUserInfo inf = (RemoteUserInfo) info;

            logger.info( "verifying remote-user authentication in credentials matcher for: " + inf.getUsername() );
            return tok.getUsername().equals( inf.getUsername() );
        }

        logger.warn( "PASS-THROUGH: verifying conventional authentication info in credentials matcher..." );
        return delegate.getCredentialsMatcher().doCredentialsMatch( token, info );
    }

}
