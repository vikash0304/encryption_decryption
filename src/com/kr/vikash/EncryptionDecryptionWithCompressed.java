package com.kr.vikash;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class EncryptionDecryptionWithCompressed {
	
	private SecretKey key;
	private final Integer KEY_SIZE = 128;
	private final Integer TAG_LENGTH = 128;
	private Cipher encryptionCipher;
	private String ALGORITHM = "AES";

    public static void main(String[] args) {
        try {
        	EncryptionDecryptionWithCompressed encryptionDecryptionWithCompressed = new EncryptionDecryptionWithCompressed();
        	encryptionDecryptionWithCompressed.init();
            Map<String, String> message = new HashMap<>();
            message.put("Name", "vikash");
            message.put("Address", "Pune");
            String encryptedMessage = encryptionDecryptionWithCompressed.encryptAndCompress(message);
            Map<String, String> decryptedMessage = encryptionDecryptionWithCompressed.decrypt(encryptedMessage);

            System.out.println("Encrypted Message : " + encryptedMessage);
            System.out.println("Decrypted Message : " + decryptedMessage);
        } catch (Exception e) {
        	System.err.println("Unable to Encrypt Message : " + e.getMessage());
        }
    }

	public void init() throws Exception {
		KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM);
		generator.init(KEY_SIZE);
		key = generator.generateKey();
	}

	public String encrypt(Map<String, String> message) throws Exception {
		byte[] messageInBytes = convertMapToByteArray(message);
		encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedBytes = encryptionCipher.doFinal(messageInBytes);
		return encode(encryptedBytes);
	}
	
    public Map<String, String> decrypt(String encryptedMessage) throws Exception {
        byte[] messageInBytes = decode(encryptedMessage);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes);
        return convertByteArrayToMap(decryptedBytes);
    }

	private String encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}
	
    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }
    
    private byte[] convertMapToByteArray(Map<String, String> message) throws IOException {
    	ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
    	ObjectOutputStream out = new ObjectOutputStream(byteOut);
    	out.writeObject(message);
    	return byteOut.toByteArray();
    }
    
    private Map<String, String> convertByteArrayToMap(byte[] message) throws Exception {
    	ByteArrayInputStream byteIn = new ByteArrayInputStream(message);
        ObjectInputStream in = new ObjectInputStream(byteIn);
        Map<String, String> data2 = (Map<String, String>) in.readObject();
		return data2;
    }

    public String encryptAndCompress(Map<String, String> message) throws Exception {
        byte[] messageInBytes = convertMapToByteArray(message);
        
        ByteArrayOutputStream compressedBytesOut = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(compressedBytesOut)) {
            gzip.write(messageInBytes);
        }
        byte[] compressedMessage = compressedBytesOut.toByteArray();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionCipher.doFinal(compressedMessage);
        return encode(encryptedBytes);
    }
}
