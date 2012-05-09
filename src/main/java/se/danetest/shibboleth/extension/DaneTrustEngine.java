package se.danetest.shibboleth.extension;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.security.SecurityException;

//import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;

public class DaneTrustEngine<TrustEngineType> implements SignatureTrustEngine {

	 /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DaneTrustEngine.class);
    
    public static void simpleLookupDNS (String[] args) throws UnknownHostException {
    	InetAddress ip = InetAddress.getByName("www.danetest.se");
    	String ipaddress = (String)ip.getHostAddress();
    		if(ipaddress.equals("46.137.37.201")){
    		System.out.println(ipaddress);
    		}
    	}
    
	public boolean validate(Signature token, CriteriaSet trustBasisCriteria)
			throws SecurityException {
		// TODO Auto-generated method stub
		return false;
	}

	public KeyInfoCredentialResolver getKeyInfoResolver() {
		// TODO Auto-generated method stub
		return null;
	}

	public boolean validate(byte[] signature, byte[] content,
			String algorithmURI, CriteriaSet trustBasisCriteria,
			Credential candidateCredential) throws SecurityException {
		// TODO Auto-generated method stub
		return false;
	}
}
