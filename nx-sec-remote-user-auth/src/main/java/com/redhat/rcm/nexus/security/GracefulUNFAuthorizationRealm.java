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

import org.codehaus.plexus.PlexusContainer;
import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.component.annotations.Requirement;
import org.codehaus.plexus.component.repository.exception.ComponentLookupException;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.AuthorizationInfo;
import org.jsecurity.realm.Realm;
import org.jsecurity.subject.PrincipalCollection;
import org.sonatype.configuration.ConfigurationException;
import org.sonatype.configuration.validation.InvalidConfigurationException;
import org.sonatype.security.SecuritySystem;
import org.sonatype.security.realms.XmlAuthorizingRealm;
import org.sonatype.security.usermanagement.DefaultUser;
import org.sonatype.security.usermanagement.NoSuchUserManagerException;
import org.sonatype.security.usermanagement.User;
import org.sonatype.security.usermanagement.UserNotFoundException;
import org.sonatype.security.usermanagement.UserStatus;
import org.sonatype.security.usermanagement.xml.SecurityXmlUserManager;

import java.util.Set;

@Component( role = Realm.class, hint = GracefulUNFAuthorizationRealm.HINT, description = "Graceful UserNotFound Authorization Realm" )
public class GracefulUNFAuthorizationRealm
    extends XmlAuthorizingRealm
    implements Realm
{

    public static final String HINT = "GracefulUNFAuthorizationRealm";

    @Requirement
    private PlexusContainer plexus;

    @Requirement
    private NxSecConfiguration nxSecConfig;

    private SecuritySystem securitySystem;

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo( final PrincipalCollection principals )
    {
        final String username = (String) principals.iterator().next();

        SecuritySystem securitySystem;
        try
        {
            securitySystem = getSecuritySystem();
        }
        catch ( final ComponentLookupException e )
        {
            throw new AuthorizationException( "Unable to lookup SecuritySystem", e );
        }

        final Set<User> users = securitySystem.listUsers();

        boolean found = false;
        if ( users != null && !users.isEmpty() )
        {
            for ( final User user : users )
            {
                if ( user.getUserId().equals( username ) )
                {
                    found = true;
                    break;
                }
            }
        }

        if ( !found )
        {
            final DefaultUser user = new DefaultUser();

            user.setUserId( username );
            user.setName( username );
            user.setStatus( UserStatus.active );
            user.setSource( SecurityXmlUserManager.SOURCE );

            try
            {
                user.setEmailAddress( username.indexOf( '@' ) > 0 ? username : username + "@"
                                + nxSecConfig.getEmailDomain() );
            }
            catch ( final ConfigurationException e )
            {
                throw new AuthorizationException( "Cannot read NxSec configuration.", e );
            }

            try
            {
                final User anonUser = securitySystem.getUser( securitySystem.getAnonymousUsername() );
                user.setRoles( anonUser.getRoles() );
            }
            catch ( final UserNotFoundException e )
            {
                throw new AuthorizationException( "Anonymous user is missing. Unable to create user: " + username, e );
            }

            try
            {
                securitySystem.addUser( user );
            }
            catch ( final InvalidConfigurationException e )
            {
                throw new AuthorizationException( "Unable to create user: " + username, e );
            }
            catch ( final NoSuchUserManagerException e )
            {
                throw new AuthorizationException( "Unable to create user: " + username, e );
            }
        }

        return super.doGetAuthorizationInfo( principals );
    }

    private SecuritySystem getSecuritySystem()
        throws ComponentLookupException
    {
        if ( securitySystem == null )
        {
            securitySystem = plexus.lookup( SecuritySystem.class );
        }
        return securitySystem;
    }

}
