package se.danetest.shibboleth.extension;

import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.config.SpringConfigurationUtils;


/** Spring bean definition parser for {urn:mace:shibboleth:2.0:security}StaticExplicitKey elements. */
public class DaneTrustEngineBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(DaneTrustEngineNamespaceHandler.NAMESPACE, "DaneTrustEngine");

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DaneTrustEngineBeanDefinitionParser.class);

    /** {@inheritDoc} */
    @SuppressWarnings("rawtypes")
	protected Class getBeanClass(Element element) {
    	log.debug("[DaneExtension] Returning the DaneSignatureTrustEngine class to requesting class/function.");
    	return DaneTrustEngineFactoryBean.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
    	log.debug("[DaneExtension] Starting to parse DaneTrustEngineSchema.");
    	log.info("[DaneExtension] Parsing configuration for {} trust engine with id: {}", XMLHelper.getXSIType(element).getLocalPart(),
                element.getAttributeNS(null, "id"));

    	log.debug("[DaneExtension] Temporary debug trace message. #1 ");
        List<Element> childElems = XMLHelper.getChildElementsByTagNameNS(element, DaneTrustEngineNamespaceHandler.NAMESPACE,
                "Credential");
        log.debug("[DaneExtension] Temporary debug trace message. #2 ");
        builder.addPropertyValue("credentials", SpringConfigurationUtils
                        .parseCustomElements(childElems, parserContext));
        log.debug("[DaneExtension] Temporary debug trace message. #3 ");
    }

    /** {@inheritDoc} */
    protected String resolveId(Element element, AbstractBeanDefinition definition, ParserContext parserContext) {
    	log.debug("[DaneExtension] Resolving attribute id.");
        return DatatypeHelper.safeTrim(element.getAttributeNS(null, "id"));
    }
}
