import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;

public class HybridEncryptionExample {
    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        // Generar una clave secreta
        // Clave personalizada (debe tener 16, 24 o 32 bytes para AES-128, AES-192 o AES-256, respectivamente)
        String clavePersonalizada = "claveSecreta1234";
        byte[] claveBytes = clavePersonalizada.getBytes(); // Convertir la clave a bytes
        SecretKey claveAES = new SecretKeySpec(claveBytes, "AES"); // Crear una instancia de SecretKeySpec con la clave

        // Mensaje a cifrar
        System.out.print("Introduzca el mensaje a cifrar: ");
        String message = sc.nextLine();

        byte[] encryptedMessage = encrypt(message, claveAES); // Cifrar el mensaje

        // Generamos un par de claves con RSA
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        byte[] claveAESCifrada = cifrarConRSA(claveAES.getEncoded(), publicKey); // Ciframos la clave AES con RSA

        // Mostramos la clave cifrada con el mensaje cifrado
        System.out.println("Mensaje cifrado con AES: " + Base64.getEncoder().encodeToString(encryptedMessage));
        System.out.println("ClaveAES cifrada con RSA: " + Base64.getEncoder().encodeToString(claveAESCifrada));

        // Descifrar el mensaje
        String decryptedMessage = decrypt(encryptedMessage, new SecretKeySpec(descifrarConRSA(claveAESCifrada, privateKey), "AES"));
        byte[] mensajeDescifrado = descifrarConRSA(claveAESCifrada, privateKey);

        System.out.println("Mensaje descifrado: " + decryptedMessage);
    }

    public static byte[] encrypt(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(message.getBytes());
    }

    public static String decrypt(byte[] encryptedMessage, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }

    private static byte[] cifrarConRSA(byte[] datos, PublicKey clavePublica) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, clavePublica);
        return cipher.doFinal(datos);
    }

    private static byte[] descifrarConRSA(byte[] datosCifrados, PrivateKey clavePrivada) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, clavePrivada);
        return cipher.doFinal(datosCifrados);
    }
}
