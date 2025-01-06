import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

class AES{
	public static void main(String[] args) throws Exception{
		String input = "This is my text";

		SecretKey key = generateRandomKey(128);
		IvParameterSpec ivParameterSpec = generateIv();

		String algorithm = "AES/CBC/PKCS5Padding";

		String cipherText = encrypt(algorithm, input, key, ivParameterSpec);
		String plainText = decrypt(algorithm, cipherText, key, ivParameterSpec);

		System.out.printf("cipher text: %s\n", cipherText);
		System.out.printf("plain text: %s\n", plainText);
	}

	/*
	 * Generating Secret key( this key should be hidden)
	 * There are 2 ways to generating secret key
	 * 		generating from a random number
	 * 		deriving from a given password
	*/
	// n: bits (128, 192, 256)
	public static SecretKey generateRandomKey(int n) throws NoSuchAlgorithmException{
		// generate random key

		// get key generator instance
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(n);

		SecretKey key = keyGenerator.generateKey();
		return key;
	}

	/*
	 * Generate random Initial Vector
	 * This Initial Vector has the same size(16 bytes) as the block that is encrypted
	 * This IV ensures different ciphertexts even if the same plaintext 
	 * 	and key are used multiple times.
	 */
	public static IvParameterSpec generateIv(){
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	/*
	 * Before implement string encryption, we first need to generate the secret key and IV
	 */
	public static String encrypt(String algorithm, String input, 
	SecretKey key, IvParameterSpec iv) throws Exception{
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		byte[] cipherText = cipher.doFinal(input.getBytes());
		return Base64.getEncoder().encodeToString(cipherText);
	}

	/*Decrypt mode */
	public static String decrypt(String algorithm, String cipherText, SecretKey key,
    							IvParameterSpec iv) throws Exception {
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		byte[] plainText = cipher.doFinal(Base64.getDecoder()
			.decode(cipherText));
		return new String(plainText);
	}
}