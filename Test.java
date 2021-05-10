import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

public class Test {

	static PrivateKey privateKey;
    static PublicKey publicKey;
    public static void main(String[] args) throws Exception {
    	//First generate a public/private key pair
        SecretKey Symmetrickey_128 = createSymetricAESKey(128);
        SecretKey Symmetrickey_256 = createSymetricAESKey(256);
        //System.out.println("The Symmetrickey_128 Key is :"+ DatatypeConverter.printHexBinary(Symmetrickey_128.getEncoded()));
       // System.out.println("The Symmetrickey_256 Key is :"+ DatatypeConverter.printHexBinary(Symmetrickey_256.getEncoded()));


        encryptAndDecrypt(Symmetrickey_128 ,"Symmetrickey_128");
        encryptAndDecrypt(Symmetrickey_256,"Symmetrickey_256");

    }

    public static void encryptAndDecrypt(SecretKey mes , String name) throws Exception{

    	System.out.println(name+" Key is 		  :"+ DatatypeConverter.printHexBinary(mes.getEncoded()));
    	KeyPair pair = generateKeyPair();
        //Our secret message
        String message = DatatypeConverter.printHexBinary(mes.getEncoded()).toString();

        //Encrypt the message
        String cipherText = encrypt(message, pair.getPublic());
        System.out.println("cipherText"+ name+"                :" + cipherText);
        //Now decrypt it
        String decipheredMessage = decrypt(cipherText, pair.getPrivate());

        System.out.println("decipheredMessage"+name+"         :"+decipheredMessage);

        System.out.println("Is equal plantext and decipheredMessage   :" +decipheredMessage.equals(message));
    }
    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes());

        return Base64.getEncoder().encodeToString(cipherText);
    }
    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes));
    }
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }
    // Function to create a secret key
    public static SecretKey createSymetricAESKey(int bit)throws Exception
    {
        // Creating a new instance of
        // SecureRandom class.
        SecureRandom securerandom = new SecureRandom();
        // Passing the string to
        // KeyGenerator
        KeyGenerator keygenerator  = KeyGenerator.getInstance("AES");
        // Initializing the KeyGenerator
        keygenerator.init(bit, securerandom);
        SecretKey key = keygenerator.generateKey();
        return key;
    }


}
