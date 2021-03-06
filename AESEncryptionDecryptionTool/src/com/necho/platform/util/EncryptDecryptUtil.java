package com.necho.platform.util;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.util.Properties;
import java.util.Scanner;

import javax.crypto.Cipher;
import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;
import javax.crypto.spec.SecretKeySpec;

public class EncryptDecryptUtil {

	private static String ALGO = "AES";
	private static String keyValue = null;

	/**
	 * Encrypt a string with AES algorithm.
	 *
	 * @param data
	 *            is a string
	 * @return the encrypted string
	 */
	public static String encrypt(String plainText) {
		String encryptedText = "";
		try {
			Key key = generateKey();
			Cipher c = Cipher.getInstance(ALGO);
			c.init(Cipher.ENCRYPT_MODE, key);
			byte[] encVal = c.doFinal(plainText.getBytes());
			encryptedText = new BASE64Encoder().encode(encVal);

		} catch (Exception e) {
			System.out.println("Encrypt Exception : " + e.getMessage());
			System.exit(0);
		}
		return encryptedText;
	}

	/**
	 *      * Method For Get encryptedText and Decrypted provided String
	 *      * @param encryptedText      * @return decryptedText      
	 */
	public static String decrypt(String encryptedText) {
		String decryptedText = "";
		try {
			Key key = generateKey();
			Cipher c = Cipher.getInstance(ALGO);
			c.init(Cipher.DECRYPT_MODE, key);
			byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedText);
			byte[] decValue = c.doFinal(decordedValue);
			decryptedText = new String(decValue);

		} catch (Exception e) {
			System.out.println("decrypt Exception : " + e.getMessage());
			System.exit(0);
		}
		return decryptedText;
	}

	/**
	 * Generate a new encryption key.
	 */
	private static Key generateKey() throws Exception {
		return new SecretKeySpec(keyValue.getBytes(), ALGO);
	}

	public static void main(String[] args) {
		InputStream inputStream;
		String mode = null;
		;
		String originalValues = null;

		try {

			Properties prop = new Properties();
			String propFileName = "config.properties";

			inputStream = EncryptDecryptUtil.class.getClassLoader().getResourceAsStream(propFileName);

			if (inputStream != null) {
				prop.load(inputStream);
			} else {
				throw new FileNotFoundException("property file '" + propFileName + "' not found in the classpath");
			}

			keyValue = prop.getProperty("AES.keyValue") != null ? prop.getProperty("AES.keyValue") : "sumtotalexpense!" ;
			System.out.println("keyValue : " + keyValue);
			originalValues = prop.getProperty("originalValues");
			System.out.println("originalvalues : " + originalValues);
			mode = prop.getProperty("mode");

		} catch (Exception e) {
			System.out.println("Exception: " + e);
			System.exit(0);
		} finally {
			inputStream = null;
		}

		String values[] = originalValues.split(",");
		try {
			File f = new File ("PasswordEncryption.txt");
			FileWriter file = new FileWriter(f);
			for (int i = 0; i < values.length; i++) {
				String inputValue = values[i];

				if (mode.equalsIgnoreCase("e")) {
					file.write("\nOriginal Value: " + inputValue+"\n");
					file.write("Encrypted Value for "+inputValue +": " + encrypt(inputValue)+"\n");
					
				}

				else if (mode.equalsIgnoreCase("d")) {
					file.write("\nOriginal Value: " + inputValue+"\n");
					file.write("Decrypted Value for "+inputValue +": " + decrypt(inputValue)+"\n");
					
				} else {
					System.out.println(
							"Allowed First Argument(s) for the application are -e for Encryption -d for decryption. Retry again");
					file.close();
					f.delete();
				}
			}
			if(file != null)
					file.close();
			System.out.println("Press any key to exit...");
			(new Scanner(System.in)).nextLine();
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Press any key to exit...");
			(new Scanner(System.in)).nextLine();
		}

	}
}
