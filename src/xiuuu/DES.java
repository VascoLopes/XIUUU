package xiuuu;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class DES {

    public static byte[] encriptaDes(String mensagem, SecretKey chaveDES) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cifraDES;
        // Cria a cifra 
        cifraDES = Cipher.getInstance("DES");

        // Inicializa a cifra para o processo de encriptação
        cifraDES.init(Cipher.ENCRYPT_MODE, chaveDES);

        // Texto puro
        byte[] textoPuro = mensagem.getBytes();
        // Texto encriptado
        byte[] textoEncriptado = cifraDES.doFinal(textoPuro);
        return textoEncriptado;
    }

    public static String decriptaDes(byte[] mensagem, SecretKey chaveDES) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

        Cipher cifraDES;
        cifraDES = Cipher.getInstance("DES");
        cifraDES.init(Cipher.DECRYPT_MODE, chaveDES);

        // Decriptografa o texto
        byte[] textoDesincriptado = cifraDES.doFinal(mensagem);
        String value = new String(textoDesincriptado, "UTF-8");
        return value;
    }
}
