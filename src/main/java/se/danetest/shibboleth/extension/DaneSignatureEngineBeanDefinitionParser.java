package se.danetest.shibboleth.extension;

import javax.xml.namespace.QName;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;
//import org.opensaml.xml.util.DatatypeHelper;
//import org.opensaml.xml.util.XMLHelper;
//import org.springframework.beans.FatalBeanException;
//import org.springframework.beans.factory.support.AbstractBeanDefinition;
//import org.springframework.beans.factory.support.ManagedList;
//import edu.internet2.middleware.shibboleth.common.config.SpringConfigurationUtils;


public class DaneSignatureEngineBeanDefinitionParser extends AbstractSingleBeanDefinitionParser{
 
    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(DaneSignatureTrustEngineNamespaceHandler.NAMESPACE, "DaneTrustEngine");
    
    /** TrustEngine element name. */
    @SuppressWarnings("unused")
	private static final QName TRUST_ENGINE_NAME = new QName(DaneSignatureTrustEngineNamespaceHandler.NAMESPACE, "TrustEngine");
    
    /** TrustEngineRef element name. */
    @SuppressWarnings("unused")
	private static final QName TRUST_ENGINE_REF_NAME = new QName(DaneSignatureTrustEngineNamespaceHandler.NAMESPACE, "TrustEngineRef");
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DaneSignatureEngineBeanDefinitionParser.class);

    /** {@inheritDoc} */
    @SuppressWarnings("rawtypes")
	protected Class getBeanClass(Element element) {
    	log.debug("protected Class getBeanClass(Element element), return DaneSignatureTrustEngine.class;");
        return DaneSignatureTrustEngine.class;
    }
    
    /** {@inheritDoc} */
    protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
    	/**
        log.info("Parsing configuration for {} trust engine with id: {}", XMLHelper.getXSIType(element)
                .getLocalPart(), element.getAttributeNS(null, "id"));
        
        ManagedList managedChain = new ManagedList();
        
        Element child = XMLHelper.getFirstChildElement(element);
        while (child != null) {
            QName childName = XMLHelper.getNodeQName(child);
            if (TRUST_ENGINE_NAME.equals(childName)) {
                log.debug("Parsing chain trust engine member {}", element.getAttributeNS(null, "id"));
                managedChain.add(SpringConfigurationUtils.parseCustomElement(child, parserContext));
            } else if (TRUST_ENGINE_REF_NAME.equals(childName)) {
                log.debug("Parsing chain trust engine member reference {}", element.getAttributeNS(null, "ref") );
                managedChain.add(SpringConfigurationUtils.parseCustomElementReference(child, "ref", parserContext));
            } else {
                log.error("Unsupported child element of chaining trust engine '{}' encountered with name: {}", 
                        element.getAttributeNS(null, "id"), childName);
                throw new FatalBeanException("Unsupported child element of chaining trust engine encountered");
            }
            
            child = XMLHelper.getNextSiblingElement(child);
        }
        
        builder.addPropertyValue("chain", managedChain);
        */
    	log.debug("protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder)");
    }
    
 
    /** {@inheritDoc} 
    protected String resolveId(Element element, AbstractBeanDefinition definition, ParserContext parserContext) {
        return DatatypeHelper.safeTrim(element.getAttributeNS(null, "id"));
    }*/
    
}
