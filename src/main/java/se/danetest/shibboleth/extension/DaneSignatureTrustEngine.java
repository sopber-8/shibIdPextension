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
        	log.debug("DaneSignatureTrustEngine(KeyInfoCredentialResolver keyInfoResolver)");
            throw new IllegalArgumentException("KeyInfo credential resolver may not be null");
        }
        keyInfoCredentialResolver = keyInfoResolver;
        log.debug("DaneSignatureTrustEngine(KeyInfoCredentialResolver keyInfoResolver)");
    }
    
    /** {@inheritDoc} */
    public KeyInfoCredentialResolver getKeyInfoResolver() {
    	log.debug("public KeyInfoCredentialResolver getKeyInfoResolver()");
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
			 KeyInfoCriteria keyInfoCriteria = new KeyInfoCriteria(token.getKeyInfo());
	         CriteriaSet keyInfoCriteriaSet = new CriteriaSet(keyInfoCriteria);
	         
	         for (Credential kiCred : getKeyInfoResolver().resolve(keyInfoCriteriaSet)) {
	                if (verifySignature(token, kiCred)) {
	                    log.debug("public boolean validate(Signature token, CriteriaSet trustBasisCriteria)throws SecurityException, Successfully verified signature using KeyInfo-derived credential");
	                    log.debug("public boolean validate(Signature token, CriteriaSet trustBasisCriteria)throws SecurityException, Attempting to establish trust of KeyInfo-derived credential");
	                    if (evaluateTrust(kiCred, (TrustEngineType)trustBasisCriteria)) {
	                        log.debug("public boolean validate(Signature token, CriteriaSet trustBasisCriteria)throws SecurityException, Successfully established trust of KeyInfo-derived credential");
	                        return true;
	                    } else {
	                        log.debug("public boolean validate(Signature signature, TrustEngineType trustEngineCriteria)throws SecurityException, Failed to establish trust of KeyInfo-derived credential");
	                    }
	                }
	         }
	         log.debug("public boolean validate(Signature token, CriteriaSet trustBasisCriteria)throws SecurityException");
	    } 
			
		else {
			log.debug("public boolean validate(Signature token, CriteriaSet trustBasisCriteria)throws SecurityException, Signature contained no KeyInfo element, could not resolve verification credentials");
	    }

	log.debug("public boolean validate(Signature token, CriteriaSet trustBasisCriteria)throws SecurityException, Failed to verify signature and/or establish trust using any KeyInfo-derived credentials");
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
		        validator.validate(signature);
		    } catch (ValidationException e) {
		        log.debug("protected boolean verifySignature(Signature signature, Credential credential), Signature validation using candidate validation credential failed", e);
		        return false;
		    }
	    log.debug("protected boolean verifySignature(Signature signature, Credential credential), Signature validation using candidate credential was successful");
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
			log.debug("protected boolean evaluateTrust(Credential untrustedCredential, TrustEngineType trustEngineCriteria)");
		return false;
	}

	public boolean validate(byte[] signature, byte[] content, String algorithmURI, CriteriaSet trustEngineCriteria,
			Credential candidateCredential) throws SecurityException {
		// TODO Auto-generated method stub
			log.debug("public boolean validate(byte[] signature, byte[] content, String algorithmURI, CriteriaSet trustEngineCriteria, Credential candidateCredential) throws SecurityException");
		return false;
	}
}
