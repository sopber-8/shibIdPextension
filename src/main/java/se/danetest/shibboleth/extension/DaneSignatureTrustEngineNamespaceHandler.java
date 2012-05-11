package se.danetest.shibboleth.extension;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

public class DaneSignatureTrustEngineNamespaceHandler extends BaseSpringNamespaceHandler {
	
	private final Logger log = LoggerFactory.getLogger(DaneSignatureTrustEngineNamespaceHandler.class);

	public static final String NAMESPACE = "urn:mace:danetest:danetrustengine";

    public void init() {
    	log.debug("[DaneError] DaneSignatureTrustEngineNamespaceHandler.java row 14");
    	registerBeanDefinitionParser(DaneSignatureEngineBeanDefinitionParser.SCHEMA_TYPE, new DaneSignatureEngineBeanDefinitionParser());  
    }
}
