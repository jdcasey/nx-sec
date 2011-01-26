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

import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.subject.PrincipalCollection;
import org.jsecurity.subject.SimplePrincipalCollection;

public class RemoteUserInfo
    implements AuthenticationInfo
{

    private final String user;

    private final String realm;

    public RemoteUserInfo( final String user, final String realm )
    {
        this.user = user;
        this.realm = realm;
    }

    @Override
    public PrincipalCollection getPrincipals()
    {
        return new SimplePrincipalCollection( user, realm );
    }

    @Override
    public Object getCredentials()
    {
        return null;
    }

    public String getUsername()
    {
        return user;
    }

}
