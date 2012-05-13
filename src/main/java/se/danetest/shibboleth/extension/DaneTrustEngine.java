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
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.trust.ExplicitKeyTrustEvaluator;
import org.opensaml.xml.security.trust.TrustedCredentialTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Trust engine that evaluates a credential's key against key(s) expressed within a set of trusted credentials obtained
 * from a trusted credential resolver.
 * 
 * The credential being tested is valid if its public key or secret key matches the public key, or secret key
 * respectively, contained within any of the trusted credentials produced by the given credential resolver.
 */
public class DaneTrustEngine implements TrustedCredentialTrustEngine<Credential> {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DaneTrustEngine.class);

    /** Resolver used for resolving trusted credentials. */
    private CredentialResolver credentialResolver;

    /** Trust evaluator. */
    private ExplicitKeyTrustEvaluator trustEvaluator;

    /**
     * Constructor.
     * 
     * @param resolver credential resolver which is used to resolve trusted credentials
     */
    public DaneTrustEngine(CredentialResolver resolver) {
    	log.debug("[DaneExtension] DaneTrustEngine constructor started.");
        if (resolver == null) {
        	log.error("[DaneExtension] No credentials given in relying-party.xml.");
            throw new IllegalArgumentException("Credential resolver may not be null");
        }
        credentialResolver = resolver;
    
        trustEvaluator = new ExplicitKeyTrustEvaluator();
        log.debug("[DaneExtension] DaneTrustEngine constructor finished. ");
    }

    /** {@inheritDoc} */
    public CredentialResolver getCredentialResolver() {
    	log.debug("[DaneExtension] DaneTrustEngine returning credential resolver to the class/method requesting it.");
        return credentialResolver;
    }

    /** {@inheritDoc} */
    public boolean validate(Credential untrustedCredential, CriteriaSet trustBasisCriteria) throws SecurityException {
    	log.debug("[DaneExtension] Validation process started...");
        checkParams(untrustedCredential, trustBasisCriteria);

        log.debug("[DaneExtension] Attempting to validate untrusted credential");
        Iterable<Credential> trustedCredentials = getCredentialResolver().resolve(trustBasisCriteria);

        return trustEvaluator.validate(untrustedCredential, trustedCredentials);
    }

    /**
     * Check the parameters for required values.
     * 
     * @param untrustedCredential the credential to be evaluated
     * @param trustBasisCriteria the set of trusted credential criteria
     * @throws SecurityException thrown if required values are absent or otherwise invalid
     */
    protected void checkParams(Credential untrustedCredential, CriteriaSet trustBasisCriteria)
        throws SecurityException {
    	log.debug("[DaneExtension] Checking credential parameters.");

        if (untrustedCredential == null) {
            throw new SecurityException("Untrusted credential was null");
        }
        if (trustBasisCriteria == null) {
            throw new SecurityException("Trust basis criteria set was null");
        }
        if (trustBasisCriteria.isEmpty()) {
            throw new SecurityException("Trust basis criteria set was empty");
        }
        log.debug("[DaneExtension] Credential parameters check done. Everything seems to be alright.");
    }

}

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
