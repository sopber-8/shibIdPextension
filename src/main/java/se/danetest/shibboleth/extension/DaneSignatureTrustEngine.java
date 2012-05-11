package se.danetest.shibboleth.extension;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoCriteria;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.validation.ValidationException;

public class DaneSignatureTrustEngine<TrustEngineType> implements SignatureTrustEngine {

	 /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DaneSignatureTrustEngine.class);
 /*  
    public void simpleLookupDNS (String[] args) throws UnknownHostException {
    	InetAddress ip = InetAddress.getByName("www.danetest.se");
    	String ipaddress = (String)ip.getHostAddress();
    		if(ipaddress.equals("46.137.37.201")){
    		System.out.println(ipaddress);
    		}
    		else {
    			throw new UnknownHostException("Host is wrong");
    		}
    		log.debug("public static void simpleLookupDNS (String[] args) throws UnknownHostException");
    	}
*/

    /** KeyInfo credential resolver used to obtain the signing credential from a Signature's KeyInfo. */
    private KeyInfoCredentialResolver keyInfoCredentialResolver;

    /**
     * Constructor.
     * 
     * @param keyInfoResolver KeyInfo credential resolver used to obtain the (advisory) signing credential from a
     *            Signature's KeyInfo element.
     */
    public DaneSignatureTrustEngine(KeyInfoCredentialResolver keyInfoResolver) {
        if (keyInfoResolver == null) {
        	log.debug("[DaneError] DaneSignatureTrustEngine.java row 46");
            throw new IllegalArgumentException("KeyInfo credential resolver may not be null");
        }
        keyInfoCredentialResolver = keyInfoResolver;
        log.debug("[DaneError] DaneSignatureTrustEngine.java row 50");
    }
    
    /** {@inheritDoc} */
    public KeyInfoCredentialResolver getKeyInfoResolver() {
    	log.debug("[DaneError] DaneSignatureTrustEngine.java row 55");
        return keyInfoCredentialResolver;
    }
    
    /**
     * Attempt to establish trust by resolving signature verification credentials from the Signature's KeyInfo. If any
     * credentials so resolved correctly verify the signature, attempt to establish trust using subclass-specific trust
     * logic against trusted information as implemented in {@link #evaluateTrust(Credential, Object)}.
     * 
     * @param signature the Signature to evaluate
     * @param trustBasis the information which serves as the basis for trust evaluation
     * @return true if the signature is verified by any KeyInfo-derived credential which can be established as trusted,
     *         otherwise false
     * @throws SecurityException if an error occurs during signature verification or trust processing
     */
	@SuppressWarnings("unchecked")
	public boolean validate(Signature token, CriteriaSet trustBasisCriteria)
			throws SecurityException {
		if(token.getKeyInfo() != null){
			log.debug("[DaneError] DaneSignatureTrustEngine.java row 74");
			KeyInfoCriteria keyInfoCriteria = new KeyInfoCriteria(token.getKeyInfo());
	        CriteriaSet keyInfoCriteriaSet = new CriteriaSet(keyInfoCriteria);
	         
	        for (Credential kiCred : getKeyInfoResolver().resolve(keyInfoCriteriaSet)) {
	                if (verifySignature(token, kiCred)) {
	                	log.debug("[DaneError] DaneSignatureTrustEngine.java row 80");	                 
	                    if (evaluateTrust(kiCred, (TrustEngineType)trustBasisCriteria)) {
	                    	log.debug("[DaneError] DaneSignatureTrustEngine.java row 82");
	                        return true;
	                    } else {
	                    	log.debug("[DaneError] DaneSignatureTrustEngine.java row 85");
	                    }
	                }
	         }
	        log.debug("[DaneError] DaneSignatureTrustEngine.java row 89");
	    } 
			
		else {
			log.debug("[DaneError] DaneSignatureTrustEngine.java row 93");
	    }

		log.debug("[DaneError] DaneSignatureTrustEngine.java row 96");
   return false;
	}

	 /**
     * Attempt to verify a signature using the key from the supplied credential.
     * 
     * @param signature the signature on which to attempt verification
     * @param credential the credential containing the candidate validation key
     * @return true if the signature can be verified using the key from the credential, otherwise false
     */
	protected boolean verifySignature(Signature signature, Credential credential) {
	    SignatureValidator validator = new SignatureValidator(credential);
		    try {
		    	log.debug("[DaneError] DaneSignatureTrustEngine.java row 110");
		        validator.validate(signature);
		    } catch (ValidationException e) {
		    	log.debug("[DaneError] DaneSignatureTrustEngine.java row 113");
		        return false;
		    }
		    log.debug("[DaneError] DaneSignatureTrustEngine.java row 116");
	    return true;
		}

	/**
     * Evaluate the untrusted KeyInfo-derived credential with respect to the specified trusted information.
     * 
     * @param untrustedCredential the untrusted credential being evaluated
     * @param trustBasis the information which serves as the basis for trust evaluation
     * 
     * @return true if the trust can be established for the untrusted credential, otherwise false
     * 
     * @throws SecurityException if an error occurs during trust processing
     */
	protected boolean evaluateTrust(Credential untrustedCredential, TrustEngineType trustEngineCriteria)
            throws SecurityException {
		log.debug("[DaneError] DaneSignatureTrustEngine.java row 132");
		return false;
	}

	public boolean validate(byte[] signature, byte[] content, String algorithmURI, CriteriaSet trustEngineCriteria,
			Credential candidateCredential) throws SecurityException {
		log.debug("[DaneError] DaneSignatureTrustEngine.java row 138");
		return false;
	}
}
