package com.kr.vikash;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class EncryptionDecryptionWithString {

	private SecretKey key;
	private final Integer KEY_SIZE = 128;
	private final Integer TAG_LENGTH = 128;
	private Cipher encryptionCipher;
	private String ALGORITHM = "AES";

	public void initialize() throws Exception {
		KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM);
		generator.init(KEY_SIZE);
		key = generator.generateKey();
	}

	public String encrypt(String message) throws Exception {
		byte[] messageInBytes = message.getBytes();
		encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedBytes = encryptionCipher.doFinal(messageInBytes);
		return encode(encryptedBytes);
	}

	public String decrypt(String encryptedMessage) throws Exception {
		byte[] messageInBytes = decode(encryptedMessage);
		Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH, encryptionCipher.getIV());
		decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
		byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes);
		return new String(decryptedBytes);
	}

	private String encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}

	private byte[] decode(String data) {
		return Base64.getDecoder().decode(data);
	}

	public static void main(String[] args) {
		try {
			EncryptionDecryptionWithString encryptionDecryptionWithString = new EncryptionDecryptionWithString();
			encryptionDecryptionWithString.initialize();
			String encryptedMessage = encryptionDecryptionWithString.encrypt("Vikash");
			String decryptedMessage = encryptionDecryptionWithString.decrypt(encryptedMessage);
			System.out.println("Encrypted Message : " + encryptedMessage);
			System.out.println("Decrypted Message : " + decryptedMessage);
		} catch (Exception e) {
			System.err.println("Unable to Encrypt Message : " + e.getMessage());
		}
	}
}
