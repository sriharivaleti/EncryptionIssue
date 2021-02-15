package com.necho.platform.util;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class EncryptDecryptUtil {
	
	private static final String strKey           = "sumtotalexpense!";
	private static final String cipherTransformation    = "Blowfish";
	
	public static String encrypt(String strClearText) throws Exception{
		String strData="";
		
		try {
			SecretKeySpec skeyspec=new SecretKeySpec(strKey.getBytes(),cipherTransformation);
			Cipher cipher=Cipher.getInstance(cipherTransformation);
			cipher.init(Cipher.ENCRYPT_MODE, skeyspec);
			byte[] encrypted=cipher.doFinal(strClearText.getBytes());
			strData=new String(encrypted);
			
		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e);
		}
		return strData;
	}
	
	public static String decrypt(String strEncrypted) throws Exception{
		String strData="";
		
		try {
			SecretKeySpec skeyspec=new SecretKeySpec(strKey.getBytes(),cipherTransformation);
			Cipher cipher=Cipher.getInstance(cipherTransformation);
			cipher.init(Cipher.DECRYPT_MODE, skeyspec);
			byte[] decrypted=cipher.doFinal(strEncrypted.getBytes());
			strData=new String(decrypted);
			
		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e);
		}
		return strData;
	}
	
	public static void main(String[] args) {
		try {
		String originalString = "pass.1word";
		String encryptedString = EncryptDecryptUtil.encrypt(originalString);
		String decryptedString = EncryptDecryptUtil.decrypt(encryptedString);
		System.out.println("originalString  : "+originalString);
		System.out.println("encryptedString : "+encryptedString);
		System.out.println("decryptedString : "+decryptedString);
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		
	}
	
	

}
