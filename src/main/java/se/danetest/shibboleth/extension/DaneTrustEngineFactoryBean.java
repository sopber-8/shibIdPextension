package se.danetest.shibboleth.extension;

/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.util.List;

import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.StaticCredentialResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.AbstractFactoryBean;

/**
 * Spring factory bean used to created {@link DaneTrustEngine}s based on a static credential resolver.
 */
public class DaneTrustEngineFactoryBean extends AbstractFactoryBean {
    
	 /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DaneTrustEngineFactoryBean.class);
    
    /** List of trusted credentials. */
    private List<Credential> credentials;

    /**
     * Gets the list of trusted credentials.
     * 
     * @return the list of trusted credentials
     */
    public List<Credential> getCredentials() {
    	log.debug("[DaneExtension] Returning credentials from DaneTrustEngine Factory Bean.");
        return credentials;
    }

    /**
     * Sets the list of trusted credentials.
     * 
     * @param newCredentials the new list of trusted credentials
     */
    public void setCredentials(List<Credential> newCredentials) {
    	log.debug("[DaneExtension] Setting credentials.");
        credentials = newCredentials;
    }

    /** {@inheritDoc} */
    @SuppressWarnings("rawtypes")
	public Class getObjectType() {
    	log.debug("[DaneExtension] Returning DaneTrustEngine class from DaneTrustEngine Factory Bean.");
        return DaneTrustEngine.class;
    }
    
    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
    	log.debug("[DaneExtension] Creating StaticCredentialResolver object.");
        StaticCredentialResolver credResolver = new StaticCredentialResolver(getCredentials());
        
        return new DaneTrustEngine(credResolver);
    }
}

