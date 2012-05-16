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

import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.SigningUtil;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.KeyAlgorithmCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.trust.ExplicitKeyTrustEvaluator;
import org.opensaml.xml.security.trust.TrustedCredentialTrustEngine;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.BaseSignatureTrustEngine;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An implementation of {@link SignatureTrustEngine} which evaluates the validity and trustworthiness of XML and raw
 * signatures.
 * 
 * <p>
 * Processing is first performed as described in {@link BaseSignatureTrustEngine}. If based on this processing, it is
 * determined that the Signature's KeyInfo is not present or does not contain a resolveable valid (and trusted) signing
 * key, then all trusted credentials obtained by the trusted credential resolver will be used to attempt to validate the
 * signature.
 * </p>
 */
public class DaneExplicitKeySignatureTrustEngine extends BaseSignatureTrustEngine<Iterable<Credential>> implements
        TrustedCredentialTrustEngine<Signature> {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DaneExplicitKeySignatureTrustEngine.class);

    /** Resolver used for resolving trusted credentials. */
    private CredentialResolver credentialResolver;

    /** The external explicit key trust engine to use as a basis for trust in this implementation. */
    private ExplicitKeyTrustEvaluator keyTrust;

    /**
     * Constructor.
     * 
     * @param resolver credential resolver used to resolve trusted credentials.
     * @param keyInfoResolver KeyInfo credential resolver used to obtain the (advisory) signing credential from a
     *            Signature's KeyInfo element.
     */
    public DaneExplicitKeySignatureTrustEngine(CredentialResolver resolver, KeyInfoCredentialResolver keyInfoResolver) {
    	super(keyInfoResolver);
        log.debug("[DaneExtension] passed super keyInfoResolver = {}", keyInfoResolver);
        if (resolver == null) {
        	log.debug("[DaneExtension] resolver == 0");
            throw new IllegalArgumentException("Credential resolver may not be null");
        }
        log.debug("[DaneExtension] before credentialResolver = resolver");
        credentialResolver = resolver;
        log.debug("[DaneExtension] credentialResolver = resolver = {}", resolver);
        keyTrust = new ExplicitKeyTrustEvaluator();
    }

    /** {@inheritDoc} */
    public CredentialResolver getCredentialResolver() {
    	log.debug("[DaneExtension] returning credentialResolver = {}", credentialResolver);
        return credentialResolver;
    }

    /** {@inheritDoc} */
    public boolean validate(Signature signature, CriteriaSet trustBasisCriteria) throws SecurityException {
    	log.debug("[DaneExtension] validating with signature = {} and trustBasisCriteria = {}", signature,trustBasisCriteria);
        checkParams(signature, trustBasisCriteria);
        log.debug("[DaneExtension] signature = {} and trustBasisCriteria = {} parameters checked", signature, trustBasisCriteria);
        CriteriaSet criteriaSet = new CriteriaSet();
        log.debug("[DaneExtension] created new CriteriaSet called criteriaSet = {}", criteriaSet);
        criteriaSet.addAll(trustBasisCriteria);
        log.debug("[DaneExtension] added trustBasisCreteria to criteriaSet");
        if (!criteriaSet.contains(UsageCriteria.class)) {
        	log.debug("[DaneExtension] criteriaSet does not contain UsageCriteria.class");
            criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
            log.debug("[DaneExtension] added new UsageCriteria to criteriaSet");
        }
        String jcaAlgorithm = SecurityHelper.getKeyAlgorithmFromURI(signature.getSignatureAlgorithm());
        log.debug("[DaneExtension] SecurityHelper has fetched jcaAlgorithm(KeyAlgorithm from URI) = {} with Signature Algorithm", jcaAlgorithm);
        if (!DatatypeHelper.isEmpty(jcaAlgorithm)) {
        	log.debug("[DaneExtension] DatatypeHelper does not contain jcaAlgorithm");
            criteriaSet.add(new KeyAlgorithmCriteria(jcaAlgorithm), true);
            log.debug("[DaneExtension] added new KeyAlgorithmCirteria(jcaAlgoritm) = {} to criteriaSet, returned true", jcaAlgorithm);
        }

        Iterable<Credential> trustedCredentials = getCredentialResolver().resolve(criteriaSet);
        log.debug("[DaneExtension] trustedCredentials is set to getCredentialResolver().resolve(criteriaSet)");
        if (validate(signature, trustedCredentials)) {
        	log.debug("[DaneExtension] signature = {} and trustedCredentials = {} is validated, returns true", signature, trustBasisCriteria);
            return true;
        }

        // If the credentials extracted from Signature's KeyInfo (if any) did not verify the
        // signature and/or establish trust, as a fall back attempt to verify the signature with
        // the trusted credentials directly.
        log.debug("[DaneExtension] Attempting to verify signature using trusted credentials");

        for (Credential trustedCredential : trustedCredentials) {
            log.debug("[DaneExtension] for(Credentials trustedCredential : trustedCredentials), signature = {}, trustedCredential = {}", signature, trustedCredential);
            if (verifySignature(signature, trustedCredential)) {
                log.debug("[DaneExtension] Successfully verified signature = {} using resolved trustedCredential = {}", signature, trustedCredentials);
                return true;
            }
        }
        log.debug("[DaneExtension] Failed to verify signature using either KeyInfo-derived or directly trusted credentials, return false");
        return false;
    }

    /** {@inheritDoc} */
    public boolean validate(byte[] signature, byte[] content, String algorithmURI, CriteriaSet trustBasisCriteria,
            Credential candidateCredential) throws SecurityException {
       
    	log.debug("[DaneExtension] validating");
        checkParamsRaw(signature, content, algorithmURI, trustBasisCriteria);
        log.debug("[DaneExtension] parameters signature = {}, content = {}, algorithmURI = {} and trustBasisCriteria = {} checked");
        CriteriaSet criteriaSet = new CriteriaSet();
        log.debug("[DaneExtension] created new CriteriaSet called criteriaSet = {}", criteriaSet);
        criteriaSet.addAll(trustBasisCriteria);
        log.debug("[DaneExtension] added trustBasisCreteria to criteriaSet");
        if (!criteriaSet.contains(UsageCriteria.class)) {
        	log.debug("[DaneExtension] criteriaSet does not contain UsageCriteria.class");
            criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
            log.debug("[DaneExtension] added new UsageCriteria to criteriaSet");
        }
        String jcaAlgorithm = SecurityHelper.getKeyAlgorithmFromURI(algorithmURI);
        log.debug("[DaneExtension] SecurityHelper has fetched jcaAlgorithm(KeyAlgorithm from URI) = {} with algorithmURI", jcaAlgorithm);
        if (!DatatypeHelper.isEmpty(jcaAlgorithm)) {
        	log.debug("[DaneExtension] DatatypeHelper does not contain jcaAlgorithm");
            criteriaSet.add(new KeyAlgorithmCriteria(jcaAlgorithm), true);
            log.debug("[DaneExtension] added new KeyAlgorithmCirteria(jcaAlgoritm) to criteriaSet");
        }

        Iterable<Credential> trustedCredentials = getCredentialResolver().resolve(criteriaSet);
        log.debug("[DaneExtension] trustedCredentials is set to getCredentialResolver().resolve(criteriaSet)=",trustedCredentials);

        // First try the optional supplied candidate credential
        if (candidateCredential != null) {
        	 log.debug("[DaneExtension] candidateCredentials != null");

            if (SigningUtil.verifyWithURI(candidateCredential, algorithmURI, signature, content)) {
                log.debug("[DaneExtension] Successfully verified signature using supplied candidate credential = {}, algorithmURO = {}, signature = {}, content = {}");
                log.debug("[DaneExtension] Attempting to establish trust of supplied candidate credential");
                if (evaluateTrust(candidateCredential, trustedCredentials)) {
                    log.debug("[DaneExtension]  Successfully established trustedCredentials = {} of supplied candidateCredential = {}, return true", trustedCredentials, candidateCredential);
                    return true;
                } else {
                    log.debug("[DaneExtension] Failed to established trustedCredentials = {} of supplied candidateCredential = {}", trustedCredentials, candidateCredential);
                }
            }
        }

        // If the candidate verification credential did not verify the
        // signature and/or establish trust, or if no candidate was supplied,
        // as a fall back attempt to verify the signature with the trusted credentials directly.
        log.debug("[DaneExtension] Attempting to verify signature using trusted credentials");

        for (Credential trustedCredential : trustedCredentials) {
        	log.debug("[DaneExtension] for(Credentials trustedCredential : trustedCredentials)");
            if (SigningUtil.verifyWithURI(trustedCredential, algorithmURI, signature, content)) {
                log.debug("[DaneExtension] Successfully verified signature = {} using resolved trustedCredentials = {}, algorithmURI = {}, content = {}, return true");
                return true;
            }
        }
        log.debug("[DaneExtension] Failed to verify signature using either supplied candidate credential"
                + " or directly trusted credentials, return false");
        return false;
    }

    /** {@inheritDoc} */
    protected boolean evaluateTrust(Credential untrustedCredential, Iterable<Credential> trustedCredentials)
            throws SecurityException {
         log.debug("[DaneExtension]  evaluateTrust(Credential untrustedCredential = {}, Iterable<Credential> trustedCredentials = {})", untrustedCredential, trustedCredentials);
        return keyTrust.validate(untrustedCredential, trustedCredentials);
    }
}



/*
 {
//
//import java.net.InetAddress;
//import java.net.UnknownHostException;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.opensaml.xml.security.CriteriaSet;
//import org.opensaml.xml.security.credential.Credential;
//import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
//import org.opensaml.xml.security.keyinfo.KeyInfoCriteria;
//import org.opensaml.xml.signature.Signature;
//import org.opensaml.xml.signature.SignatureTrustEngine;
//import org.opensaml.xml.signature.SignatureValidator;
//import org.opensaml.xml.security.SecurityException;
//import org.opensaml.xml.validation.ValidationException;
//
//public class DaneTrustEngine<TrustEngineType> implements SignatureTrustEngine {
//
//	 /** Class logger. */
//    private final Logger log = LoggerFactory.getLogger(DaneTrustEngine.class);
// /*  
//    public void simpleLookupDNS (String[] args) throws UnknownHostException {
//    	InetAddress ip = InetAddress.getByName("www.danetest.se");
//    	String ipaddress = (String)ip.getHostAddress();
//    		if(ipaddress.equals("46.137.37.201")){
//    		System.out.println(ipaddress);
//    		}
//    		else {
//    			throw new UnknownHostException("Host is wrong");
//    		}
//    		log.debug("public static void simpleLookupDNS (String[] args) throws UnknownHostException");
//    	}
//*/
//
//    /** KeyInfo credential resolver used to obtain the signing credential from a Signature's KeyInfo. */
//    private KeyInfoCredentialResolver keyInfoCredentialResolver;
//
//    /**
//     * Constructor.
//     * 
//     * @param keyInfoResolver KeyInfo credential resolver used to obtain the (advisory) signing credential from a
//     *            Signature's KeyInfo element.
//     */
//    public DaneTrustEngine(KeyInfoCredentialResolver keyInfoResolver) {
//        if (keyInfoResolver == null) {
//        	log.debug("[DaneExtension] DaneSignatureTrustEngine.java row 46");
//            throw new IllegalArgumentException("KeyInfo credential resolver may not be null");
//        }
//        keyInfoCredentialResolver = keyInfoResolver;
//        log.debug("[DaneExtension] DaneSignatureTrustEngine.java row 50");
//    }
//    
//    /** {@inheritDoc} */
//    public KeyInfoCredentialResolver getKeyInfoResolver() {
//    	log.debug("[DaneExtension] DaneSignatureTrustEngine.java row 55");
//        return keyInfoCredentialResolver;
//    }
//    
//    /**
//     * Attempt to establish trust by resolving signature verification credentials from the Signature's KeyInfo. If any
//     * credentials so resolved correctly verify the signature, attempt to establish trust using subclass-specific trust
//     * logic against trusted information as implemented in {@link #evaluateTrust(Credential, Object)}.
//     * 
//     * @param signature the Signature to evaluate
//     * @param trustBasis the information which serves as the basis for trust evaluation
//     * @return true if the signature is verified by any KeyInfo-derived credential which can be established as trusted,
//     *         otherwise false
//     * @throws SecurityException if an error occurs during signature verification or trust processing
//     */
//	@SuppressWarnings("unchecked")
//	public boolean validate(Signature token, CriteriaSet trustBasisCriteria)
//			throws SecurityException {
//		if(token.getKeyInfo() != null){
//			log.debug("[DaneExtension] DaneSignatureTrustEngine.java row 74");
//			KeyInfoCriteria keyInfoCriteria = new KeyInfoCriteria(token.getKeyInfo());
//	        CriteriaSet keyInfoCriteriaSet = new CriteriaSet(keyInfoCriteria);
//	         
//	        for (Credential kiCred : getKeyInfoResolver().resolve(keyInfoCriteriaSet)) {
//	                if (verifySignature(token, kiCred)) {
//	                	log.debug("[DaneExtension] DaneSignatureTrustEngine.java row 80");	                 
//	                    if (evaluateTrust(kiCred, (TrustEngineType)trustBasisCriteria)) {
//	                    	log.debug("[DaneExtension] DaneSignatureTrustEngine.java row 82");
//	                        return true;
//	                    } else {
//	                    	log.debug("[DaneExtension] DaneSignatureTrustEngine.java row 85");
//	                    }
//	                }
//	         }
//	        log.debug("[DaneExtension] DaneSignatureTrustEngine.java row 89");
//	    } 
//			
//		else {
//			log.debug("[DaneExtension] DaneSignatureTrustEngine.java row 93");
//	    }
//
//		log.debug("[DaneExtension] DaneSignatureTrustEngine.java row 96");
//   return false;
//	}
//
//	 /**
//     * Attempt to verify a signature using the key from the supplied credential.
//     * 
//     * @param signature the signature on which to attempt verification
//     * @param credential the credential containing the candidate validation key
//     * @return true if the signature can be verified using the key from the credential, otherwise false
//     */
//	protected boolean verifySignature(Signature signature, Credential credential) {
//	    SignatureValidator validator = new SignatureValidator(credential);
//		    try {
//		    	log.debug("[DaneExtension] DaneSignatureTrustEngine.java row 110");
//		        validator.validate(signature);
//		    } catch (ValidationException e) {
//		    	log.debug("[DaneExtension] DaneSignatureTrustEngine.java row 113");
//		        return false;
//		    }
//		    log.debug("[DaneExtension] DaneSignatureTrustEngine.java row 116");
//	    return true;
//		}
//
//	/**
//     * Evaluate the untrusted KeyInfo-derived credential with respect to the specified trusted information.
//     * 
//     * @param untrustedCredential the untrusted credential being evaluated
//     * @param trustBasis the information which serves as the basis for trust evaluation
//     * 
//     * @return true if the trust can be established for the untrusted credential, otherwise false
//     * 
//     * @throws SecurityException if an error occurs during trust processing
//     */
//	protected boolean evaluateTrust(Credential untrustedCredential, TrustEngineType trustEngineCriteria)
//            throws SecurityException {
//		log.debug("[DaneExtension] DaneSignatureTrustEngine.java row 132");
//		return false;
//	}
//
//	public boolean validate(byte[] signature, byte[] content, String algorithmURI, CriteriaSet trustEngineCriteria,
//			Credential candidateCredential) throws SecurityException {
//		log.debug("[DaneExtension] DaneSignatureTrustEngine.java row 138");
//		return false;
//	}
//}
