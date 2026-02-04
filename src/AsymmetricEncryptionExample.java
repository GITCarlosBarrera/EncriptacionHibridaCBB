import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AsymmetricEncryptionExample {

    public static void main(String[] args) throws Exception {
        // Generar un par de claves RSA
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String message = "Cifro el mensaje";

        System.out.println("Mensaje original: " + message);
        // Cifrar mensaje con la clave pública RSA
        byte[] mensajeCifrado = cifrarConRSA(message.getBytes(), publicKey);

        System.out.println("Mensaje cifrado: " + Base64.getEncoder().encodeToString(mensajeCifrado));

        // Descifrar mensaje con la clave privada RSA
        byte[] mensajeDescifrado = descifrarConRSA(mensajeCifrado, privateKey);
        String mensajeDescifradoString = new String(mensajeDescifrado, "UTF-8");
        System.out.println("Mensaje descifrado: " + mensajeDescifradoString);
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