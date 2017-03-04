package xiuuu;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.SecureRandom;
import java.math.BigInteger;

public class Merkle {

    Cipher cipher;

    public SecureRandom random = new SecureRandom();

    public Merkle() {
        try {
            cipher = Cipher.getInstance("DES");
        } catch (javax.crypto.NoSuchPaddingException e) {
        } catch (java.security.NoSuchAlgorithmException e) {
        }
    }

    public String random_string(int length) {
        // Gera uma random string com o tamanho dado
        String k = new BigInteger(400, random).toString(32);
        k = k.substring(0, length);
        return k;
    }

    public SecretKey random_key(int length) {
        // Adiciona zeros á string como padding devido ao tamnho ser muito pequeno
        byte[] k = (this.random_string(length) + "00000000").getBytes();
        try {
            DESKeySpec sks = new DESKeySpec(k);
            SecretKeyFactory sf = SecretKeyFactory.getInstance("DES");
            return sf.generateSecret(sks);
        } catch (java.security.spec.InvalidKeySpecException e) {
        } catch (java.security.NoSuchAlgorithmException e) {
        } catch (java.security.InvalidKeyException e) {
        }
        return null;
    }

    public byte[] encrypt(SecretKey key, String data) throws java.security.InvalidKeyException {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] utf8 = data.getBytes("UTF8");
            byte[] ciphertext = cipher.doFinal(utf8);
            return ciphertext;
        } catch (javax.crypto.BadPaddingException e) {
        } catch (IllegalBlockSizeException e) {
        } catch (UnsupportedEncodingException e) {
        }
        return null;
    }

    public String decrypt(SecretKey key, byte[] ciphertext) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] utf8 = cipher.doFinal(ciphertext);
            return new String(utf8, "UTF8");
        } catch (javax.crypto.BadPaddingException e) {
        } catch (IllegalBlockSizeException e) {
        } catch (UnsupportedEncodingException e) {
        } catch (java.security.InvalidKeyException e) {
        }
        return null;
    }
}
