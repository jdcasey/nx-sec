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
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.codehaus.plexus.PlexusContainer;
import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.component.annotations.Requirement;
import org.codehaus.plexus.component.repository.exception.ComponentLookupException;
import org.sonatype.configuration.ConfigurationException;
import org.sonatype.configuration.validation.InvalidConfigurationException;
import org.sonatype.security.SecuritySystem;
import org.sonatype.security.realms.XmlAuthorizingRealm;
import org.sonatype.security.usermanagement.DefaultUser;
import org.sonatype.security.usermanagement.NoSuchUserManagerException;
import org.sonatype.security.usermanagement.RoleIdentifier;
import org.sonatype.security.usermanagement.User;
import org.sonatype.security.usermanagement.UserManager;
import org.sonatype.security.usermanagement.UserNotFoundException;
import org.sonatype.security.usermanagement.UserStatus;
import org.sonatype.security.usermanagement.xml.SecurityXmlUserManager;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.inject.Named;

import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

@Named( GracefulUNFAuthorizationRealm.ID )
public class GracefulUNFAuthorizationRealm
    extends XmlAuthorizingRealm
    implements Realm
{

    public static final String ID = "GracefulUNFAuthorizationRealm";

//    @Inject
//    private final PlexusContainer plexus;
    
//    @Inject
    private final NxSecConfiguration configuration;

    private final Log logger = LogFactory.getLog( this.getClass() );

    private final SecuritySystem securitySystem;
    
    private final UserManager userManager;
    
    @Inject
    public GracefulUNFAuthorizationRealm( NxSecConfiguration configuration, SecuritySystem securitySystem, 
                                          @Named( value = "default" ) UserManager userManager )
    {
        this.configuration = configuration;
        this.securitySystem = securitySystem;
        this.userManager = userManager;
    }
    
    @Override
    protected void checkPermission(Permission permission, AuthorizationInfo info) {
        try
        {
            logger.info( "executing checkPermission(..)." );
            super.checkPermission( permission, info );
        }
        catch( RuntimeException e )
        {
            logger.error( "error executing checkPermission(..).", e );
            throw e;
        }
        
        logger.info( "done executing checkPermission(..)." );
    }
    

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo( final PrincipalCollection principals )
    {
        AuthorizationInfo result = null;
        try
        {
            if ( configuration.isAutoCreateEnabled() )
            {
                User user = autoCreateOnDemand( principals );
                if ( user != null )
                {
                    Set<String> roles = new LinkedHashSet<String>();
                    if ( user.getRoles() != null )
                    {
                        for ( RoleIdentifier rid : user.getRoles() )
                        {
                            roles.add( rid.getRoleId() );
                        }
                    }
                    
                    result = new SimpleAuthorizationInfo( roles );
                }
            }
        }
        catch ( ConfigurationException e )
        {
            throw new AuthorizationException( "Error loading nx-sec configuration.", e );
        }
        
        if ( result == null )
        {
            final String username = (String) principals.iterator().next();
            logger.info( "delegating doGetAuthorizationInfo(..) for: " + username + "." );
            
            try
            {
                result = super.doGetAuthorizationInfo( principals );
            }
            catch ( AuthorizationException e )
            {
                logger.error( "Delegated authorization failed for: " + username + ".", e );
                throw e;
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append( "AuthorizationInfo result: " );
        
        if ( result.getRoles() != null )
        {
            sb.append( "\n\nRoles:" );
            for ( String role : result.getRoles() )
            {
                sb.append( "\n\t" ).append( role );
            }
        }
        
        if ( result.getStringPermissions() != null )
        {
            sb.append( "\n\nString Permissions:" );
            for ( String perm : result.getStringPermissions() )
            {
                sb.append( "\n\t" ).append( perm );
            }
        }
        
        if ( result.getObjectPermissions() != null )
        {
            sb.append( "\n\nObject Permissions:" );
            for ( Object perm : result.getObjectPermissions() )
            {
                sb.append( "\n\t" ).append( perm );
            }
        }
        sb.append("\n\n");
        
        logger.info( sb.toString() );
        
        return result;
    }

    private User autoCreateOnDemand( PrincipalCollection principals )
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

        User user;
        try
        {
            user = securitySystem.getUser( username );
            StringBuffer sb = new StringBuffer();
            
            sb.append( "User already exists in Nexus: " ).append( username ).append( ":" );
            sb.append( "\nUser ID: " ).append( user.getUserId() );
            sb.append( "\nSource: " ).append( user.getSource() );
            sb.append( "\nEmail: " ).append( user.getEmailAddress() );
            
            Set<RoleIdentifier> roles = user.getRoles();
            sb.append( "\nRoles: " );
            for ( RoleIdentifier ri : roles )
            {
                sb.append("\n\t").append( ri.getRoleId() );
            }
            
            logger.info( sb.toString() );
        }
        catch ( final UserNotFoundException unfe )
        {
            final String anonUserId = securitySystem.getAnonymousUsername();

            logger.info( "Cannot find pre-existing user: " + username + ". Creating as a clone of anonymous user: " + anonUserId
                            + "..." );

            user = new DefaultUser();

            try
            {
                user.setEmailAddress( username.indexOf( '@' ) > 0 ? username : username + "@" + configuration.getAutoCreateEmailDomain() );
            }
            catch ( ConfigurationException e )
            {
                throw new AuthorizationException( "Error loading nx-sec configuration.", e );
            }
            
            user.setUserId( username );
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
                user = userManager.addUser( user, "" );
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
        
        return user;
    }

    private SecuritySystem getSecuritySystem()
        throws ComponentLookupException
    {
//        if ( securitySystem == null )
//        {
//            securitySystem = plexus.lookup( SecuritySystem.class );
//        }
        return securitySystem;
    }

}
