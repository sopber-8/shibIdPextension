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

/** Spring bean definition parser for {urn:mace:shibboleth:2.0:security}StaticExplicitKeySignature elements. */
public class DaneStaticExplicitKeySignatureTrustEngineBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(DaneExplicitKeySignatureTrustEngineNamespaceHandler.NAMESPACE, "DaneTrustEngine");

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DaneStaticExplicitKeySignatureTrustEngineBeanDefinitionParser.class);

    /** {@inheritDoc} */
    @SuppressWarnings("rawtypes")
	protected Class getBeanClass(Element element) {
        return DaneStaticExplicitKeySignatureTrustEngineFactoryBean.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
        log.info("Parsing configuration for {} trust engine with id: {}", XMLHelper.getXSIType(element).getLocalPart(),
                element.getAttributeNS(null, "id"));

        List<Element> childElems = XMLHelper.getChildElementsByTagNameNS(element, DaneExplicitKeySignatureTrustEngineNamespaceHandler.NAMESPACE,
                "Credential");
        builder.addPropertyValue("credentials", SpringConfigurationUtils
                        .parseCustomElements(childElems, parserContext));
    }

    /** {@inheritDoc} */
    protected String resolveId(Element element, AbstractBeanDefinition definition, ParserContext parserContext) {
        return DatatypeHelper.safeTrim(element.getAttributeNS(null, "id"));
    }
}

//import java.util.List;
//
//import javax.xml.namespace.QName;
//
//import org.opensaml.xml.util.DatatypeHelper;
//import org.opensaml.xml.util.XMLHelper;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.support.AbstractBeanDefinition;
//import org.springframework.beans.factory.support.BeanDefinitionBuilder;
//import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
//import org.springframework.beans.factory.xml.ParserContext;
//import org.w3c.dom.Element;
//
//import edu.internet2.middleware.shibboleth.common.config.SpringConfigurationUtils;
//
//
///** Spring bean definition parser for {urn:mace:shibboleth:2.0:security}StaticExplicitKey elements. */
//public class DaneTrustEngineBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {
//
//    /** Schema type. */
//    public static final QName SCHEMA_TYPE = new QName(DaneTrustEngineNamespaceHandler.NAMESPACE, "DaneTrustEngine");
//
//    /** Class logger. */
//    private final Logger log = LoggerFactory.getLogger(DaneTrustEngineBeanDefinitionParser.class);
//
//    /** {@inheritDoc} */
//    @SuppressWarnings("rawtypes")
//	protected Class getBeanClass(Element element) {
//    	log.debug("[DaneExtension] Returning the DaneSignatureTrustEngine class to requesting class/function.");
//    	return DaneTrustEngineFactoryBean.class;
//    }
//
//    /** {@inheritDoc} */
//    protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
//    	log.debug("[DaneExtension] Starting to parse DaneTrustEngineSchema.");
//    	log.info("[DaneExtension] Parsing configuration for {} trust engine with id: {}", XMLHelper.getXSIType(element).getLocalPart(),
//                element.getAttributeNS(null, "id"));
//
//    	log.debug("[DaneExtension] Temporary debug trace message. #1 ");
//        List<Element> childElems = XMLHelper.getChildElementsByTagNameNS(element, DaneTrustEngineNamespaceHandler.NAMESPACE,
//                "Credential");
//        log.debug("[DaneExtension] Temporary debug trace message. #2 ");
//        builder.addPropertyValue("credentials", SpringConfigurationUtils
//                        .parseCustomElements(childElems, parserContext));
//        log.debug("[DaneExtension] Temporary debug trace message. #3 ");
//    }
//
//    /** {@inheritDoc} */
//    protected String resolveId(Element element, AbstractBeanDefinition definition, ParserContext parserContext) {
//    	log.debug("[DaneExtension] Resolving attribute id.");
//        return DatatypeHelper.safeTrim(element.getAttributeNS(null, "id"));
//    }
//}
