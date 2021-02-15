package com.necho.platform.util;

import java.security.Key;
import javax.crypto.Cipher;
import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;
import javax.crypto.spec.SecretKeySpec;

public class EncryptDecryptUtil {
	
	 private static final String ALGO = "AES";
	    private static final byte[] keyValue =
	            new byte[]{'S', 'U', 'M', 'T', 'O', 'T', 'A', 'L', 'E', 'X', 'P', 'E', 'N', 'S', 'E', '!'};

	    /**
	     * Encrypt a string with AES algorithm.
	     *
	     * @param data is a string
	     * @return the encrypted string
	     */
	    public static String encrypt(String data) throws Exception {
	        Key key = generateKey();
	        Cipher c = Cipher.getInstance(ALGO);
	        c.init(Cipher.ENCRYPT_MODE, key);
	        byte[] encVal = c.doFinal(data.getBytes());
	        return new BASE64Encoder().encode(encVal);
	    }
	    
	    /**
	     * Decrypt a string with AES algorithm.
	     *
	     * @param encryptedData is a string
	     * @return the decrypted string
	     */
	    public static String decrypt(String encryptedData) throws Exception {
	        Key key = generateKey();
	        Cipher c = Cipher.getInstance(ALGO);
	        c.init(Cipher.DECRYPT_MODE, key);
	        byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedData);
	        byte[] decValue = c.doFinal(decordedValue);
	        return new String(decValue);
	    }

	    /**
	     * Generate a new encryption key.
	     */
	    private static Key generateKey() throws Exception {
	        return new SecretKeySpec(keyValue, ALGO);
	    }

	    public static void main(String[] args) {
			String originalString ="redab977";
			String encryptedString="";
			String decryptedString="";
			try {
			 encryptedString = encrypt(originalString);
			}
			catch(Exception e) {
				e.printStackTrace();
			}
			//System.out.println(encryptedString);
			
			try {
			decryptedString = decrypt(encryptedString);
			}
			catch(Exception e) {
				e.printStackTrace();
			}
			//System.out.println(decryptedString);
			//0Nr6EtT+0KOoh0ZsItdgrA==
			
			System.out.println("Original String :"+ originalString);
			System.out.println("Encrypted String:"+ encryptedString);
			System.out.println("Decrypted String:"+ decryptedString);
			
			
		}
}
