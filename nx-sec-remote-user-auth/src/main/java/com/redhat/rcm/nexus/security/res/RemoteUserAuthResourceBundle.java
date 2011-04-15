package com.redhat.rcm.nexus.security.res;

import java.util.ArrayList;
import java.util.List;

import org.sonatype.nexus.plugins.rest.AbstractNexusResourceBundle;
import org.sonatype.nexus.plugins.rest.DefaultStaticResource;
import org.sonatype.nexus.plugins.rest.NexusResourceBundle;
import org.sonatype.nexus.plugins.rest.StaticResource;

public class RemoteUserAuthResourceBundle
    extends AbstractNexusResourceBundle
    implements NexusResourceBundle
{
    @Override
    public List<StaticResource> getContributedResouces()
    {
        final List<StaticResource> result = new ArrayList<StaticResource>();

        result.add( new DefaultStaticResource( getClass().getResource( "/static/js/nx-sec-remote-user-auth-all.js" ),
                                               "/js/repoServer/nx-sec-remote-user-auth-all.js",
                                               "application/x-javascript" ) );

        return result;
    }

}
