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

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;

public class RemoteUserInfo
    implements AuthenticationInfo
{

    private static final long serialVersionUID = 2L;

    private final String realm;

    private final String remoteUser;

    public RemoteUserInfo( final String remoteUser, final String realm )
    {
        this.remoteUser = remoteUser;
        this.realm = realm;
    }

    public String getRemoteUser()
    {
        return remoteUser;
    }

    @Override
    public PrincipalCollection getPrincipals()
    {
        return new SimplePrincipalCollection( remoteUser, realm );
    }

    @Override
    public Object getCredentials()
    {
        return null;
    }

    public String getUsername()
    {
        return remoteUser;
    }

}
