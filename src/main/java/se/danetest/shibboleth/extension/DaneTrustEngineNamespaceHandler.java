package se.danetest.shibboleth.extension;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

public class DaneTrustEngineNamespaceHandler extends BaseSpringNamespaceHandler {
	
	private final Logger log = LoggerFactory.getLogger(DaneTrustEngineNamespaceHandler.class);

	public static final String NAMESPACE = "urn:mace:danetest:danetrustengine";

    public void init() {
    	log.debug("[DaneExtension] Register the DaneSignatureTrustEngineBeanDefinitionParser.");
    	
    	registerBeanDefinitionParser(DaneTrustEngineBeanDefinitionParser.SCHEMA_TYPE, 
    									new DaneTrustEngineBeanDefinitionParser());
    	
    	log.debug("[DaneExtension] DaneSignatureTrustEngineBeanDefinitionParser has been registered. ");
    }
}
