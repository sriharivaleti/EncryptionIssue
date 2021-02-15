package com.necho.platform.util;

import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptDecryptUtil {
	
    private static final String encryptionKey           = "SUMTOTALEXPENSE!";
    private static final String characterEncoding       = "UTF-8";
    private static final String cipherTransformation    = "AES/CBC/PKCS5PADDING";
    private static final String aesEncryptionAlgorithem = "AES";    
    
    /**
     * Method for Encrypt Plain String Data
     * @param plainText
     * @return encryptedText
     */
    public static String encrypt(String plainText){
        String encryptedText = "";
        try {
            Cipher cipher   = Cipher.getInstance(cipherTransformation);
            byte[] key      = encryptionKey.getBytes(characterEncoding);
            SecretKeySpec secretKey = new SecretKeySpec(key, aesEncryptionAlgorithem);
            IvParameterSpec ivparameterspec = new IvParameterSpec(key);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivparameterspec);
            byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF8"));
            Base64.Encoder encoder = Base64.getEncoder();
            encryptedText = encoder.encodeToString(cipherText);

        } catch (Exception e) {
            System.out.println("Encrypt Exception : "+e.getMessage());
             System.exit(0);
        }
        return encryptedText;
    }

    /**
     * Method For Get encryptedText and Decrypted provided String
     * @param encryptedText
     * @return decryptedText
     */
    public static String decrypt(String encryptedText){
        String decryptedText = "";
        try {
            Cipher cipher = Cipher.getInstance(cipherTransformation);
            byte[] key = encryptionKey.getBytes(characterEncoding);
            SecretKeySpec secretKey = new SecretKeySpec(key, aesEncryptionAlgorithem);
            IvParameterSpec ivparameterspec = new IvParameterSpec(key);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivparameterspec);
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] cipherText = decoder.decode(encryptedText.getBytes("UTF8"));
            decryptedText = new String(cipher.doFinal(cipherText), "UTF-8");

        } catch (Exception e) {
        	System.out.println("decrypt Exception : "+e.getMessage());
            System.exit(0);
        }
        return decryptedText;
    }
    public static void main(String[] args) {
		
    	String mode = args[0];
    	String inputValue = args[1];
    	
    	if(mode.equalsIgnoreCase("-e")) {
    		System.out.println("Original Text Passed :" + inputValue);
    		System.out.println("Encrypted Value is   :"+ encrypt(inputValue));
    	}
    	
    	else if(mode.equalsIgnoreCase("-d")) {
    		System.out.println("Original Text Passed :" + inputValue);
    		System.out.println("Decrypted Value is   :"+ decrypt(inputValue));
    	}
    	else {
    		System.out.println("Allowed First Argument(s) for the application are -e for Encryption -d for decryption. Retry again");
    	}
	}
}
