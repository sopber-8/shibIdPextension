package se.danetest.shibboleth.extension;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

public class DaneExplicitKeySignatureTrustEngineNamespaceHandler extends BaseSpringNamespaceHandler {
	
	private final Logger log = LoggerFactory.getLogger(DaneExplicitKeySignatureTrustEngineNamespaceHandler.class);

	public static final String NAMESPACE = "urn:mace:danetest:danetrustengine";

    public void init() {
    	log.debug("[DaneExtension] Register the DaneSignatureTrustEngineBeanDefinitionParser.");
    	
    	registerBeanDefinitionParser(DaneStaticExplicitKeySignatureTrustEngineBeanDefinitionParser.SCHEMA_TYPE, 
    									new DaneStaticExplicitKeySignatureTrustEngineBeanDefinitionParser());
    	
    	log.debug("[DaneExtension] DaneExplicitKeySignatureTrustEngineNamespaceHandler has been registered. ");
    }
}
