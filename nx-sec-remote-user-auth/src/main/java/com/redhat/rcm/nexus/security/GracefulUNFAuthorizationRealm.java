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
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.codehaus.plexus.PlexusContainer;
import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.component.annotations.Requirement;
import org.codehaus.plexus.component.repository.exception.ComponentLookupException;
import org.sonatype.configuration.validation.InvalidConfigurationException;
import org.sonatype.security.SecuritySystem;
import org.sonatype.security.realms.XmlAuthorizingRealm;
import org.sonatype.security.usermanagement.DefaultUser;
import org.sonatype.security.usermanagement.NoSuchUserManagerException;
import org.sonatype.security.usermanagement.User;
import org.sonatype.security.usermanagement.UserNotFoundException;
import org.sonatype.security.usermanagement.UserStatus;
import org.sonatype.security.usermanagement.xml.SecurityXmlUserManager;

@Component( role = Realm.class, hint = GracefulUNFAuthorizationRealm.HINT, description = "Graceful UserNotFound Authorization Realm" )
public class GracefulUNFAuthorizationRealm
    extends XmlAuthorizingRealm
    implements Realm
{

    public static final String HINT = "GracefulUNFAuthorizationRealm";

    @Requirement
    private PlexusContainer plexus;
    
    @Requirement
    private NxSecConfiguration configuration;

    private final Log logger = LogFactory.getLog( this.getClass() );

    private SecuritySystem securitySystem;

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo( final PrincipalCollection principals )
    {
        if ( configuration.isAutoCreateEnabled() )
        {
            autoCreateOnDemand( principals );
        }

        return super.doGetAuthorizationInfo( principals );
    }

    private void autoCreateOnDemand( PrincipalCollection principals )
    {
        final String username = (String) principals.iterator().next();

        SecuritySystem securitySystem;
        try
        {
            securitySystem = getSecuritySystem();
        }
        catch ( final ComponentLookupException e )
        {
            logger.error( "Cannot retrieve handle to security system for user lookup." );

            throw new AuthorizationException( "Unable to lookup SecuritySystem", e );
        }

        try
        {
            securitySystem.getUser( username );
        }
        catch ( final UserNotFoundException unfe )
        {
            final String anonUserId = securitySystem.getAnonymousUsername();

            logger.info( "Cannot find pre-existing user: " + username + ". Creating as a clone of anonymous user: " + anonUserId
                            + "..." );

            final DefaultUser user = new DefaultUser();

            user.setUserId( username );
            user.setEmailAddress( username.indexOf( '@' ) > 0 ? username : username + "@" + configuration.getAutoCreateEmailDomain() );
            user.setName( username );
            user.setStatus( UserStatus.active );
            user.setSource( SecurityXmlUserManager.SOURCE );

            try
            {
                final User anonUser = securitySystem.getUser( anonUserId );
                user.setRoles( anonUser.getRoles() );
            }
            catch ( final UserNotFoundException e )
            {
                logger.error( "Anonymous user is missing. Unable to create user: " + username );

                throw new AuthorizationException( "Anonymous user is missing. Unable to create user: " + username, e );
            }

            try
            {
                securitySystem.addUser( user );
            }
            catch ( final InvalidConfigurationException e )
            {
                logger.error( "Unable to create user: " + username + ". Invalid configuration: " + e.getMessage() );

                throw new AuthorizationException( "Invalid configuration: " + e.getMessage() + "\nUnable to create user: " + username, e );
            }
            catch ( final NoSuchUserManagerException e )
            {
                logger.error( "Unable to create user: " + username + ". No such user manager: " + e.getMessage() );

                throw new AuthorizationException( "No such user-manager: " + e.getMessage() + "\nUnable to create user: " + username, e );
            }
        }
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
