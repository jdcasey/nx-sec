package com.redhat.rcm.nexus.security.res;

import org.sonatype.nexus.plugins.rest.AbstractNexusIndexHtmlCustomizer;
import org.sonatype.nexus.plugins.rest.NexusIndexHtmlCustomizer;

import javax.inject.Named;
import javax.inject.Singleton;

import java.util.Map;

@Named("remote-user-auth")
@Singleton
public class RemoteUserAuthIndexHtmlCustomizer
    extends AbstractNexusIndexHtmlCustomizer
    implements NexusIndexHtmlCustomizer
{
    @Override
    public String getPostHeadContribution( final Map<String, Object> ctx )
    {
        final String version =
            getVersionFromJarFile( "/META-INF/maven/com.redhat.rcm.nexus/nx-sec-remote-user-auth/pom.properties" );

        return "<script src=\"static/js/remoteUserAuth/nx-sec-remote-user-auth-all.js" + ( version == null ? "" : "?" + version )
            + "\" type=\"text/javascript\" charset=\"utf-8\"></script>";
    }
}
