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
        return "<script src=\"js/remoteUserAuth/nx-sec-remote-user-auth-all.js"
            + "\" type=\"text/javascript\" charset=\"utf-8\"></script>";
    }
}
