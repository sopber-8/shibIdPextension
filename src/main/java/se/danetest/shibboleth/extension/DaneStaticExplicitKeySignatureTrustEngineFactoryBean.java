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

import java.util.ArrayList;
import java.util.List;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.StaticCredentialResolver;
import org.opensaml.xml.security.keyinfo.BasicProviderKeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoProvider;
import org.opensaml.xml.security.keyinfo.provider.DSAKeyValueProvider;
import org.opensaml.xml.security.keyinfo.provider.InlineX509DataProvider;
import org.opensaml.xml.security.keyinfo.provider.RSAKeyValueProvider;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.beans.factory.config.AbstractFactoryBean;

/**
 * Spring factory bean used to created {@link ExplicitKeySignatureTrustEngine}s based on a static credential resolver.
 */
public class DaneStaticExplicitKeySignatureTrustEngineFactoryBean extends AbstractFactoryBean {
	
	/** Class logger. */
	private final Logger log = LoggerFactory.getLogger(DaneStaticExplicitKeySignatureTrustEngineFactoryBean.class);
    
    /** List of trusted credentials. */
    private List<Credential> credentials;

    /**
     * Gets the list of trusted credentials.
     * 
     * @return the list of trusted credentials
     */
    public List<Credential> getCredentials() {
    	log.debug("[DaneExtension] Returning credentials from DaneStaticExplicitKeySignatureTrustEngineFactoryBean");
        return credentials;
    }

    /**
     * Sets the list of trusted credentials.
     * 
     * @param newCredentials the new list of trusted credentials
     */
    public void setCredentials(List<Credential> newCredentials) {
    	log.debug("[DaneExtension] Set credentials");
        credentials = newCredentials;
        log.debug("[DaneExtension] Set credentials to newCredentials");
    }

    /** {@inheritDoc} */
    @SuppressWarnings("rawtypes")
	public Class getObjectType() {
    	log.debug("[DaneExtension] Returning DaneStaticExplicitKeySignatureTrustEngine");
        return DaneExplicitKeySignatureTrustEngine.class;
    }
    
    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
    	log.debug("[DaneExtension] createInstance()");
        StaticCredentialResolver credResolver = new StaticCredentialResolver(getCredentials());
        log.debug("[DaneExtension] created credResolver with a new StaticCredentialResolver(getCredentials())");
        List<KeyInfoProvider> keyInfoProviders = new ArrayList<KeyInfoProvider>();
        log.debug("[DaneExtension] created a arraylist of keyInfoProviders");
        keyInfoProviders.add(new DSAKeyValueProvider());
        log.debug("[DaneExtension] added DSAKeyValueProvider");
        keyInfoProviders.add(new RSAKeyValueProvider());
        log.debug("[DaneExtension] added RSAKeyValueProvider");
        keyInfoProviders.add(new InlineX509DataProvider());
        log.debug("[DaneExtension] added InlineX509DataProvider");
        KeyInfoCredentialResolver keyInfoCredResolver = new BasicProviderKeyInfoCredentialResolver(keyInfoProviders);
        log.debug("[DaneExtension] created keyInfoCredResolver from new BasicProviderKeyInfoCredentialResolver");
        log.debug("[DaneExtension] returning DaneExplicitKeySignatureTrustEngine(credResolver, keyUnfoResolver)");
        return new DaneExplicitKeySignatureTrustEngine(credResolver, keyInfoCredResolver);
    }
}

//
///*
// * Licensed to the University Corporation for Advanced Internet Development, 
// * Inc. (UCAID) under one or more contributor license agreements.  See the 
// * NOTICE file distributed with this work for additional information regarding
// * copyright ownership. The UCAID licenses this file to You under the Apache 
// * License, Version 2.0 (the "License"); you may not use this file except in 
// * compliance with the License.  You may obtain a copy of the License at
// *
// *    http://www.apache.org/licenses/LICENSE-2.0
// *
// * Unless required by applicable law or agreed to in writing, software
// * distributed under the License is distributed on an "AS IS" BASIS,
// * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// * See the License for the specific language governing permissions and
// * limitations under the License.
// */
//
//import java.util.List;
//
//import org.opensaml.xml.security.credential.Credential;
//import org.opensaml.xml.security.credential.StaticCredentialResolver;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.config.AbstractFactoryBean;
//
///**
// * Spring factory bean used to created {@link DaneTrustEngine}s based on a static credential resolver.
// */
//public class DaneTrustEngineFactoryBean extends AbstractFactoryBean {
//    
//	 /** Class logger. */
//    private final Logger log = LoggerFactory.getLogger(DaneTrustEngineFactoryBean.class);
//    
//    /** List of trusted credentials. */
//    private List<Credential> credentials;
//
//    /**
//     * Gets the list of trusted credentials.
//     * 
//     * @return the list of trusted credentials
//     */
//    public List<Credential> getCredentials() {
//    	log.debug("[DaneExtension] Returning credentials from DaneTrustEngine Factory Bean.");
//        return credentials;
//    }
//
//    /**
//     * Sets the list of trusted credentials.
//     * 
//     * @param newCredentials the new list of trusted credentials
//     */
//    public void setCredentials(List<Credential> newCredentials) {
//    	log.debug("[DaneExtension] Setting credentials.");
//        credentials = newCredentials;
//    }
//
//    /** {@inheritDoc} */
//    @SuppressWarnings("rawtypes")
//	public Class getObjectType() {
//    	log.debug("[DaneExtension] Returning DaneTrustEngine class from DaneTrustEngine Factory Bean.");
//        return DaneTrustEngine.class;
//    }
//    
//    /** {@inheritDoc} */
//    protected Object createInstance() throws Exception {
//    	log.debug("[DaneExtension] Creating StaticCredentialResolver object.");
//        StaticCredentialResolver credResolver = new StaticCredentialResolver(getCredentials());
//        
//        return new DaneTrustEngine(credResolver);
//    }
//}
//
