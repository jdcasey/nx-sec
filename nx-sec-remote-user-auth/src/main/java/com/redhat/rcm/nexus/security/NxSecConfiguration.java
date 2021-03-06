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

import static org.apache.commons.io.IOUtils.closeQuietly;
import static org.apache.commons.lang.StringUtils.isBlank;

import org.sonatype.configuration.ConfigurationException;
import org.sonatype.nexus.configuration.application.ApplicationConfiguration;

import javax.inject.Inject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.Properties;

//@Component( role = NxSecConfiguration.class, description = "Configuration for Nx-Sec" )
public class NxSecConfiguration
{

    private static final String KEY_AUTOCREATE_EMAIL_DOMAIN = "user.autocreate.email.domain";

    private static final String KEY_AUTOCREATE_ENABLED = "user.autocreate.enabled";

    private static final String KEY_TEMPLATE_USER_ID = "user.autocreate.template.user";

    private static final String NX_SEC_CONFIG_FILE = "nx-sec.properties";

    private static final String DEFAULT_AUTOCREATE_EMAIL_DOMAIN = "company.com";

    private static final boolean DEFAULT_AUTOCREATE_ENABLED = true;
    
//    @Inject
    private final ApplicationConfiguration appConfiguration;

    private boolean loaded = false;

    private String autoCreateEmailDomain = DEFAULT_AUTOCREATE_EMAIL_DOMAIN;

    private boolean autoCreateEnabled = DEFAULT_AUTOCREATE_ENABLED;

    private String templateUserId;
    
    @Inject
    public NxSecConfiguration( ApplicationConfiguration appConfiguration )
    {
        this.appConfiguration = appConfiguration;
    }

    public void load()
        throws ConfigurationException
    {
        File configFile = new File( appConfiguration.getConfigurationDirectory(), NX_SEC_CONFIG_FILE );
        if ( configFile.exists() && configFile.canRead() )
        {
            FileInputStream fis = null;
            try
            {
                fis = new FileInputStream( configFile );
                Properties props = new Properties();
                props.load( fis );

                autoCreateEnabled =
                    Boolean.valueOf( props.getProperty( KEY_AUTOCREATE_ENABLED,
                                                        Boolean.toString( DEFAULT_AUTOCREATE_ENABLED ) ) );

                autoCreateEmailDomain =
                    props.getProperty( KEY_AUTOCREATE_EMAIL_DOMAIN, DEFAULT_AUTOCREATE_EMAIL_DOMAIN );
                
                templateUserId = props.getProperty( KEY_TEMPLATE_USER_ID );
                
                if ( isBlank( autoCreateEmailDomain ) )
                {
                    autoCreateEmailDomain = DEFAULT_AUTOCREATE_EMAIL_DOMAIN;
                }

                loaded = true;
            }
            catch ( IOException e )
            {
                loaded = false;
                throw new ConfigurationException( "Cannot read " + configFile + ". Reason: " + e.getMessage(), e );
            }
            finally
            {
                closeQuietly( fis );
            }
        }
    }

    public void save()
        throws ConfigurationException
    {
        File configFile = new File( appConfiguration.getConfigurationDirectory(), NX_SEC_CONFIG_FILE );
        FileOutputStream fos = null;
        try
        {
            Properties props = new Properties();
            props.setProperty( KEY_AUTOCREATE_ENABLED, Boolean.toString( autoCreateEnabled ) );
            props.setProperty( KEY_AUTOCREATE_EMAIL_DOMAIN, autoCreateEmailDomain );

            fos = new FileOutputStream( configFile );
            props.store( fos, "Saved on: " + new Date() );
        }
        catch ( IOException e )
        {
            throw new ConfigurationException( "Cannot write " + configFile + ". Reason: " + e.getMessage(), e );
        }
        finally
        {
            closeQuietly( fos );
        }
    }

    protected ApplicationConfiguration getAppConfiguration()
    {
        return appConfiguration;
    }

    public String getAutoCreateEmailDomain()
        throws ConfigurationException
    {
        checkLoaded();
        return autoCreateEmailDomain;
    }

    public boolean isAutoCreateEnabled()
        throws ConfigurationException
    {
        checkLoaded();
        return autoCreateEnabled;
    }

    private synchronized void checkLoaded()
        throws ConfigurationException
    {
        if ( !loaded )
        {
            load();
        }
    }

//    protected NxSecConfiguration setAppConfiguration( ApplicationConfiguration appConfiguration )
//        throws ConfigurationException
//    {
//        this.appConfiguration = appConfiguration;
//        
//        load();
//        
//        return this;
//    }

    protected NxSecConfiguration setAutoCreateEmailDomain( String autoCreateEmailDomain )
    {
        this.autoCreateEmailDomain = autoCreateEmailDomain;
        return this;
    }

    protected NxSecConfiguration setAutoCreateEnabled( boolean autoCreateEnabled )
    {
        this.autoCreateEnabled = autoCreateEnabled;
        return this;
    }

    public String getTemplateUserId()
        throws ConfigurationException
    {
        checkLoaded();
        return templateUserId;
    }

}
