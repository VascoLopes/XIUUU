package xiuuu;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import sun.security.x509.X509CertImpl;
import static xiuuu.AESEncryption.decryptText;
import static xiuuu.RSA.areKeysPresent;
import static xiuuu.RSA.generateKey;
import static xiuuu.DES.*;
import static xiuuu.RSA.decrypt;

public class ClienteRecetor implements Runnable {

    public static final String PRIVATE_KEY_FILE = "C:/keys/private.key";
    public static final String PUBLIC_KEY_FILE = "C:/keys/public.key";

    ServerSocket serverSocket;
    PrintStream streamToClient;
    BufferedReader streamFromClient;
    Socket fromClient;
    ObjectInputStream in, in2;
    ObjectOutputStream out;
    static int count = 0;
    Thread thread;
    Socket toClient;
    int ip;
    Merkle mkl = new Merkle();
    int keyLen = 4;
    String k2 = "VascoBoinoNelsonAndre"; //k2 para o caso5
    String keyDecripted; //para o algoritmo 5 (troca de chaves, agente de confiança)
    String kSemAgente = "ErdnaNoslenOniobOcsav";
    String kSessaoSemAgente;

    public ClienteRecetor() {

    }

    public ClienteRecetor(int porta) {
        try {
            serverSocket = new ServerSocket(porta);
        } catch (Exception e) {
            System.out.println("Socket could not be created" + e);
        }
        thread = new Thread(this);
        thread.start();
    }

    public void run() {
        try {
            while (true) {
                PublicKey publicKey = null;
                fromClient = serverSocket.accept();
                in = new ObjectInputStream(fromClient.getInputStream());
                int algoritmo = (int) in.readObject();

                if (algoritmo == 1) //Diffie-Hellman
                {
                    Random rnd = new Random();
                    try {
                        in = new ObjectInputStream(fromClient.getInputStream());
                        BigInteger P = (BigInteger) in.readObject();
                        BigInteger g = (BigInteger) in.readObject();
                        BigInteger X = (BigInteger) in.readObject();

                        String nome = (String) in.readObject();
                        BigInteger y;
                        int maxNumBitLength = P.bitLength();
                        do {
                            y = new BigInteger(maxNumBitLength, rnd);
                            // compare random number lessthan ginven number
                        } while (y.compareTo(P) > 0 || y.compareTo(BigInteger.valueOf(0)) == 0);
                        BigInteger Y = g.modPow(y, P);
                        BigInteger k = X.modPow(y, P);

                        out = new ObjectOutputStream(fromClient.getOutputStream());
                        out.writeObject(Y);//daqui 
                        byte[] array = k.toByteArray();

                        if (array[0] == 0) {
                            byte[] tmp = new byte[array.length - 1];
                            System.arraycopy(array, 1, tmp, 0, tmp.length);
                            array = tmp;
                        }

                        SecretKey key = new SecretKeySpec(array, 0, array.length, "DES");

                        //ate aqui é para passar para SK
                        String keyChosen = Base64.getEncoder().encodeToString(key.getEncoded());
                        for (int i = 1; i <= 4; i++) {
                            keyChosen = keyChosen + i;
                            byte[] bytesOfMessage = keyChosen.getBytes("UTF-8");
                            MessageDigest md = MessageDigest.getInstance("MD5");
                            md.update(bytesOfMessage);
                            byte[] digest = md.digest();
                            StringBuffer sb = new StringBuffer();
                            for (byte b : digest) {
                                sb.append(String.format("%02x", b & 0xff));
                            }
                            keyChosen = sb.toString();

                        }

                        SecretKey keyOk = new SecretKeySpec(keyChosen.getBytes(), 0, 16, "AES");

                        in2 = new ObjectInputStream(fromClient.getInputStream());
                        String aviso_recebido2 = (String) in2.readObject();
                        byte[] criptograma = (byte[]) in2.readObject();
                        PublicKey pkRecebida = (PublicKey) in2.readObject();
                        byte[] signatureBytes = (byte[]) in2.readObject();
                        if (aviso_recebido2.equals("aqui vai o criptograma")) {
                            Signature sig = Signature.getInstance("SHA256WithRSA");
                            sig.initVerify(pkRecebida);
                            sig.update(criptograma);
                            String mensagem_original;
                            if (sig.verify(signatureBytes)) {
                                mensagem_original = decryptText(criptograma, keyOk);
                                System.out.println("Recebeu um segredo.\n" + nome + "> " + mensagem_original);
                            } else {
                                System.out.println("Recebeu um segredo mas a assinatura não estava correta!");
                            }
                        }
                    } catch (java.io.StreamCorruptedException ex) {

                    }
                }

                if (algoritmo == 2) //Puzzles de Merkle
                {
                    in = new ObjectInputStream(fromClient.getInputStream());
                    String aviso_recebido = (String) in.readObject();
                    ArrayList<byte[]> puzzles = (ArrayList<byte[]>) in.readObject();
                    String nome = (String) in.readObject();
                    int cifra_escolhida = (int) in.readObject();
                    if (aviso_recebido.equals("aqui vao os puzzles")) {
                        int chosen = mkl.random.nextInt(puzzles.size());
                        String chave = "";
                        boolean solved = false;
                        while (!solved) {
                            chave = mkl.decrypt(mkl.random_key(keyLen), (byte[]) puzzles.get(chosen));
                         
                            if (chave != null && chave.substring(0, 4).equals("Key=")) {
                                solved = true;
                            }
                        }

                        String key = chave.substring(4, 20); //chave
                        out = new ObjectOutputStream(fromClient.getOutputStream());
                        out.writeObject(chave.substring(30));

                        byte[] encodedKey = key.getBytes();
                        SecretKey originalKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");

                        in2 = new ObjectInputStream(fromClient.getInputStream());
                        String aviso_recebido2 = (String) in2.readObject();
                        byte[] criptograma = (byte[]) in2.readObject();

                        if (aviso_recebido2.equals("aqui vai o criptograma")) {
                            String mensagem_original = "";
                            if (cifra_escolhida == 1) {
                                mensagem_original = decryptText(criptograma, originalKey);
                            } else if (cifra_escolhida == 2) {
                                String keyz = key + key;
                                byte[] doidoi = keyz.getBytes(Charset.forName("UTF-8"));

                                SecretKey originaKey = new SecretKeySpec(doidoi, 0, 8, "DES");

                                mensagem_original = decriptaDes(criptograma, originaKey);
                            }
                            System.out.println("Recebeu um segredo.\n" + nome + "> " + mensagem_original);
                        }
                    }
                }

                if (algoritmo == 3) //RSA
                {
                    in = new ObjectInputStream(fromClient.getInputStream());
                    String aviso_recebido = (String) in.readObject();
                    String ip_cliente_emissor = (String) in.readObject();
                    int porta_cliente_emissor = (int) in.readObject();
                    String nome = (String) in.readObject();
                    ObjectInputStream inputStream = null;
                    if (aviso_recebido.equals("manda-me a pk")) {
                        try {
                            // Verifica se os ficheiros ja existem
                            if (!areKeysPresent()) {
                                // Se nao existirem cria
                                generateKey();
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }

                        // Encripta a string usando a pk
                        inputStream = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
                        publicKey = (PublicKey) inputStream.readObject();

                        out = new ObjectOutputStream(fromClient.getOutputStream());
                        out.writeObject(publicKey);
                    }

                    in2 = new ObjectInputStream(fromClient.getInputStream());
                    String aviso_recebido2 = (String) in2.readObject();
                    byte[] criptograma = (byte[]) in2.readObject();
                    if (aviso_recebido2.equals("aqui vai o criptograma")) {

                        X509CertImpl cert = (X509CertImpl) in2.readObject();
                        PublicKey publicKeySignature = (PublicKey) in2.readObject();
                        //DECRIPTAR USANDO SK
                        try {
                            cert.checkValidity();
                            cert.verify(publicKeySignature);

                            inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
                            final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
                            final String mensagem_original = decrypt(criptograma, privateKey);

                            System.out.println("Recebeu um segredo.\n" + nome + "> " + mensagem_original);
                        } catch (Exception e) {
                            System.out.println("Recebeu um segredo de '" + nome + "' mas o certificado digital não estava valido");
                        }
                    }
                }

                if (algoritmo == 4) {   //Distribuição de novas chaves de cifra a partir de chaves pré-distribuídas e envio de um segredo
                    in = new ObjectInputStream(fromClient.getInputStream());
                    byte[] criptKey = (byte[]) in.readObject();
                    String nome = (String) in.readObject();
                    byte[] criptMesg = (byte[]) in.readObject();

                    byte[] keyByte = kSemAgente.getBytes();
                    SecretKey originalKey = new SecretKeySpec(keyByte, 0, 16, "AES");

                    kSessaoSemAgente = decryptText(criptKey, originalKey);

                    keyByte = kSessaoSemAgente.getBytes();
                    originalKey = new SecretKeySpec(keyByte, 0, 16, "AES");

                    String mensagem = decryptText(criptMesg, originalKey);
                    System.out.println("Recebeu um segredo.\n" + nome + "> " + mensagem);

                }

                if (algoritmo == 5) {   //Distribuição de novas chaves de cifra usando um agente de confiança e envio de um segredo
                    String nome = (String) in.readObject();

                    byte[] encriptedK = (byte[]) in.readObject();

                    byte[] keyByte = k2.getBytes();
                    SecretKey originalKey = new SecretKeySpec(keyByte, 0, 16, "AES");

                    keyDecripted = decryptText(encriptedK, originalKey);
                }

                if (algoritmo == 55) {  //Distribuição de novas chaves de cifra usando um agente de confiança e envio de um segredo
                    in = new ObjectInputStream(fromClient.getInputStream());
                    String nome = (String) in.readObject();
                    byte[] criptograma = (byte[]) in.readObject();

                    byte[] keyByte = keyDecripted.getBytes();
                    SecretKey originalKey = new SecretKeySpec(keyByte, 0, 16, "AES");

                    String mensagem = decryptText(criptograma, originalKey);

                    System.out.println("Recebeu um segredo.\n" + nome + "> " + mensagem);
                }

            }
        } catch (java.net.SocketException ex) {

        } catch (IOException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ClienteRecetor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(ClienteRecetor.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void close() throws IOException, InterruptedException {
        try {
            serverSocket.close();
        } catch (java.net.SocketException ex) {
            System.out.println("Erro");
        }

    }
}
