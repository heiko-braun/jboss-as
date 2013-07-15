/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2013, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.as.domain.management.access;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.ACCESS_CONTROL;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.CORE_SERVICE;

import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.access.DelegatingConfigurableAuthorizer;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.Resource;
import org.jboss.as.domain.management._private.DomainManagementResolver;

/**
 * {@link org.jboss.as.controller.ResourceDefinition} for the Access Control model.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AccessControlResourceDefinition extends SimpleResourceDefinition {

    public static final Resource RESOURCE = createResource();

    private final DelegatingConfigurableAuthorizer configurableAuthorizer;
    private final boolean isDomain;
    private final boolean isHostController;

    public static AccessControlResourceDefinition forDomain(DelegatingConfigurableAuthorizer configurableAuthorizer) {
        return new AccessControlResourceDefinition(configurableAuthorizer, true, false);
    }

    public static AccessControlResourceDefinition forHost(DelegatingConfigurableAuthorizer configurableAuthorizer) {
        return new AccessControlResourceDefinition(configurableAuthorizer, true, true);
    }

    public static AccessControlResourceDefinition forDomainServer(DelegatingConfigurableAuthorizer configurableAuthorizer) {
        return new AccessControlResourceDefinition(configurableAuthorizer, true, false);
    }

    public static AccessControlResourceDefinition forStandaloneServer(DelegatingConfigurableAuthorizer configurableAuthorizer) {
        return new AccessControlResourceDefinition(configurableAuthorizer, false, false);
    }

    private AccessControlResourceDefinition(DelegatingConfigurableAuthorizer configurableAuthorizer, boolean domain, boolean hostController) {
        super(PathElement.pathElement(CORE_SERVICE, ACCESS_CONTROL), DomainManagementResolver.getResolver("core.access-control"));
        this.configurableAuthorizer = configurableAuthorizer;
        isDomain = domain;
        isHostController = hostController;
    }

    @Override
    public void registerChildren(ManagementResourceRegistration resourceRegistration) {
        // Role Mapping
        if (!isHostController) {
            // TODO
        }

        // Scoped roles
        if (isDomain) {
            resourceRegistration.registerSubModel(new ServerGroupScopedRoleResourceDefinition(configurableAuthorizer));
            resourceRegistration.registerSubModel(new HostScopedRolesResourceDefinition(configurableAuthorizer));
        }

        // Constraints
        //  -- Application Type
        if (!isHostController) {
            resourceRegistration.registerSubModel(ApplicationTypeParentResourceDefinition.INSTANCE);
            //  -- Sensitivity Classification
            resourceRegistration.registerSubModel(SensitivityClassificationParentResourceDefinition.INSTANCE);
            //  -- Vault Expression
            resourceRegistration.registerSubModel(SensitivityResourceDefinition.createVaultExpressionConfiguration());
        }
    }

    private static Resource createResource() {
        Resource accessControlRoot =  Resource.Factory.create();
        accessControlRoot.registerChild(AccessConstraintResources.APPLICATION_PATH_ELEMENT, AccessConstraintResources.APPLICATION_RESOURCE);
        accessControlRoot.registerChild(AccessConstraintResources.SENSITIVITY_PATH_ELEMENT, AccessConstraintResources.SENSITIVITY_RESOURCE);
        accessControlRoot.registerChild(AccessConstraintResources.VAULT_PATH_ELEMENT, AccessConstraintResources.VAULT_RESOURCE);
        return accessControlRoot;
    }

}
