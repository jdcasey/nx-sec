/*
 *  Copyright (C) 2011 John Casey.
 *  
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *  
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.redhat.rcm.nexus.security;

import static org.apache.commons.io.IOUtils.closeQuietly;

import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.component.annotations.Requirement;
import org.sonatype.configuration.ConfigurationException;
import org.sonatype.nexus.configuration.application.ApplicationConfiguration;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

@Component( role = NxSecConfiguration.class )
public class NxSecConfiguration
{

    private static final String CONFIG_FILE = "nxsec.properties";

    private static final String EMAIL_DOMAIN = "account.email.domain";

    private static final String DEFAULT_EMAIL_DOMAIN = "company.com";

    private static final Properties DEFAULTS = new Properties()
    {
        private static final long serialVersionUID = 1L;

        {
            setProperty( EMAIL_DOMAIN, DEFAULT_EMAIL_DOMAIN );
        }
    };

    @Requirement
    private ApplicationConfiguration appConfig;

    private Properties configuration;

    public String getEmailDomain()
        throws ConfigurationException
    {
        final Properties config = loadConfiguration();

        return config.getProperty( EMAIL_DOMAIN );
    }

    private synchronized Properties loadConfiguration()
        throws ConfigurationException
    {
        if ( configuration == null )
        {
            final Properties p = new Properties();
            final File f = new File( appConfig.getConfigurationDirectory(), CONFIG_FILE );
            if ( f.exists() )
            {
                FileInputStream fis = null;
                try
                {
                    fis = new FileInputStream( f );
                    p.load( fis );
                    configuration = p;
                }
                catch ( final IOException e )
                {
                    throw new ConfigurationException( "Cannot read NxSec configuration from: " + f + "\nReason: "
                                    + e.getMessage(), e );
                }
                finally
                {
                    closeQuietly( fis );
                }
            }
            else
            {
                FileOutputStream fos = null;
                try
                {
                    fos = new FileOutputStream( f );
                    DEFAULTS.store( fos, "Default configuration for NxSec security customizations." );
                    configuration = new Properties();
                    configuration.putAll( DEFAULTS );
                }
                catch ( final IOException e )
                {
                    throw new ConfigurationException( "Cannot write default NxSec configuration to: " + f
                                    + "\nReason: " + e.getMessage(), e );
                }
                finally
                {
                    closeQuietly( fos );
                }
            }
        }

        return configuration;
    }

}
