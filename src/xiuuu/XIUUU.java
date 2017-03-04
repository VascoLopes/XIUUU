package xiuuu;

//Discentes:
//André Rodrigues (34363)
//Guilherme Boino (33480)
//Nelson Fonseca (33514)
//Vasco Lopes (34507)
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import static java.lang.System.exit;
import java.math.BigInteger;
import static java.math.BigInteger.probablePrime;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Encoder;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;
import static xiuuu.RSA.encrypt;
import static xiuuu.AESEncryption.encryptText;
import static xiuuu.DiffieHellman.*;
import static xiuuu.DES.*;
import static xiuuu.RSA.areKeysPresent;
import static xiuuu.RSA.generateKey;

public class XIUUU {

    public static final String PRIVATE_KEY_FILE = "C:/keys/private.key";
    public static final String PUBLIC_KEY_FILE = "C:/keys/public.key";

    public static void main(String[] args) throws ClassNotFoundException, IOException, InvalidKeyException, Exception {

        System.out.println("-----BEM-VINDO AO XIUU-----\n");
        int opcDados = 0;
        int flag = 0, flag2 = 0; //flag1 é para pedir nome e porta apenas 1x, flag2 é para conectar apenas 1x ao server
        int porta = -1, porta2 = 0;//porta2 é do servidor
        String nome = "";
        int opcao = -1;
        String ip = "";
        Cliente cliente = new Cliente();
        ClienteRecetor clienteRecetor = new ClienteRecetor();
        String k1 = "AndreNelsonBoinoVasco"; //k1 para o caso5
        String kSemAgente = "ErdnaNoslenOniobOcsav";
        Cliente cliente9 = null;

        do {
            System.out.println("Pretende entrar em modo:\n1-Cliente\n2-Servidor\n3-Help\n0-Sair");
            opcao = Ler.umInt();
            switch (opcao) {
                case 1: //MODO CLIENTE
                {
                    if (flag == 0) {
                        do {
                            System.out.println("Introduza o seu nome: "); //verificações de input
                            nome = Ler.umaString();
                            System.out.println("Qual a porta que deseja abrir?");
                            porta = Ler.umInt();
                            System.out.println("Insira o IP do servidor:");
                            ip = Ler.umaString();
                            System.out.println("Insira a porta do servidor");
                            porta2 = Ler.umInt();
                            flag = 1;
                            do {
                                System.out.println("Nome: " + nome + " | Porta: " + porta + " | IP do servidor: " + ip + " | Porta do servidor: " + porta2);
                                System.out.println("1- Confirmar Valores\n2- Voltar a introduzir");
                                opcDados = Ler.umInt();
                            } while (opcDados != 1 && opcDados != 2);
                        } while (opcDados != 1);
                    }

                    int opc2 = -1;
                    int flag3 = 0;
                    do {
                        if (flag2 == 0 || flag3 == 0) {
                            cliente = new Cliente(ip, porta2, nome, porta, 1, false);
                            flag3 = 1;
                        }
                        if (flag2 == 0) {
                            if (opc2 != 2) {
                                clienteRecetor = new ClienteRecetor(porta);
                            }
                            flag2 = 1;
                        }
                        System.out.println("\n-----MODO CLIENTE-----\n1-Comunicar com outro cliente\n2-Listar clientes ativos\n3-Gerar segredo criptográfico através de chave gerada por palavra-passe (PBKDF2)\n0-Voltar");
                        opc2 = Ler.umInt();

                        switch (opc2) {

                            case 1: {
                                System.out.println("Insira o ip a conectar:");
                                String ipSendMessage = Ler.umaString();
                                if (ipSendMessage.equals(ip)) {
                                    System.out.println("Impossível enviar segredo ao servidor!");
                                    break;
                                } else {
                                    System.out.println("Insira a porta a que se vai conectar");
                                    int portaSendMessage = Ler.umInt();

                                    System.out.println("Escreva o segredo que pretende enviar");
                                    String mensagem = Ler.umaString();

                                    /* System.out.println("Qual é o modo que pretende cifrar a mensagem?\n1 - Protocolo de acordo de chaves Diffie-Hellman\n2 - Puzzle de Merkle\n3 - Troca com RSA\n4 - Distribuição de novas chaves de cifra a partir de chaves pré-distribuídas e envio de um segredo\n5 - Distribuição de novas chaves de cifra usando um agente de confiança e envio de um segredo\n0 - Voltar");
                                    int cifra = Ler.umInt();*/
                                    int cifra = 1;
                                    do {

                                        System.out.println("Qual é o modo que pretende cifrar a mensagem?\n1 - Protocolo de acordo de chaves Diffie-Hellman\n2 - Puzzle de Merkle\n3 - Troca com RSA\n4 - Distribuição de novas chaves de cifra a partir de chaves pré-distribuídas e envio de um segredo\n5 - Distribuição de novas chaves de cifra usando um agente de confiança e envio de um segredo\n0 - Voltar");
                                        cifra = Ler.umInt();
                                        if (cifra <= 0 || cifra > 5) {
                                            System.out.println("Opção inválida, tente novamente!");
                                        }
                                    } while (cifra <= 0 || cifra > 5);

                                    try {
                                        if (cifra != 5) {
                                            cliente9 = new Cliente(ipSendMessage, portaSendMessage, cifra);
                                            cliente9.algoritmoEscolhido(cifra);
                                        }
                                    } catch (Exception e) {
                                        break;
                                    }

                                    switch (cifra) {
                                        case 1: { //Diffie-Hellman
                                            byte[] encryptedMessage = null;
                                            try {
                                                //verifica se existe o par de chaves, caso nao exista
                                                if (!areKeysPresent()) {
                                                    // gera o par de chaves com o RSA e armazena-as
                                                    generateKey();
                                                }
                                            } catch (Exception e) {
                                                e.printStackTrace();
                                            }
                                            SecureRandom rnd = new SecureRandom();

                                            boolean b;
                                            BigInteger P;
                                            do {
                                                P = probablePrime(1024, rnd);
                                                b = P.isProbablePrime(100);
                                            } while (!b);

                                            BigInteger g; //gerador
                                            g = findPrimeRoot(P); //encontra um gerador para P                                        
                                            int maxNumBitLength = P.bitLength();

                                            BigInteger x;
                                            do {
                                                x = new BigInteger(maxNumBitLength, rnd);
                                            } while (x.compareTo(P) > 0 || x.compareTo(BigInteger.valueOf(0)) == 0);

                                            BigInteger X = g.modPow(x, P); //X = g^x % P

                                            BigInteger Y = cliente9.sendNum(P, g, X, nome);
                                            BigInteger k = Y.modPow(x, P);
                                            //daqui para ao proximo é para fazer SK a partir do biginteger
                                            byte[] array = k.toByteArray();
                                            if (array[0] == 0) {
                                                byte[] tmp = new byte[array.length - 1];
                                                System.arraycopy(array, 1, tmp, 0, tmp.length);
                                                array = tmp;
                                            }
                                            SecretKey key = new SecretKeySpec(array, 0, array.length, "DES");

                                            //
                                            String keyChosen = Base64.getEncoder().encodeToString(key.getEncoded());

                                            //calcular md5 para ter tamanho certo para o AES
                                            for (int i = 1; i <= 4; i++) {
                                                keyChosen = keyChosen + i;
                                                byte[] bytesOfMessage = keyChosen.getBytes("UTF-8");
                                                MessageDigest md = MessageDigest.getInstance("MD5");
                                                md.update(bytesOfMessage);
                                                byte[] digest = md.digest();
                                                StringBuffer sb = new StringBuffer();
                                                for (byte b1 : digest) {
                                                    sb.append(String.format("%02x", b1 & 0xff));
                                                }
                                                keyChosen = sb.toString();

                                            }

                                            SecretKey keyOk = new SecretKeySpec(keyChosen.getBytes(), 0, 16, "AES"); //0 a 16 na string porque a secret key forma sempre mais bits do que os 16, então é necessario reduzir os 32 da string para formar uma secretkey que é aceite pelo AES-128

                                            try {
                                                encryptedMessage = encryptText(mensagem, keyOk);
                                            } catch (Exception ex) {
                                                Logger.getLogger(XIUUU.class.getName()).log(Level.SEVERE, null, ex);
                                            }
                                            ObjectInputStream inputStream = null;

                                            inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
                                            PrivateKey privateKeySignature = (PrivateKey) inputStream.readObject();

                                            inputStream = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
                                            PublicKey publicKeySignature = (PublicKey) inputStream.readObject();

                                            Signature sig = Signature.getInstance("SHA256WithRSA");
                                            sig.initSign(privateKeySignature);
                                            sig.update(encryptedMessage);
                                            byte[] signatureBytes = sig.sign();

                                            cliente9.enviaCriptogramaAlg1(encryptedMessage, publicKeySignature, signatureBytes);
                                            System.out.println("Segredo enviado!\n");
                                            break;
                                        }
                                        case 2: //Puzzles de Merkle
                                        {
                                            int cifra_escolhida = 0;
                                            do {
                                                System.out.println("Qual o algoritmo de cifra que pretende utilizar?\n1-AES-ECB\n2-DES");
                                                cifra_escolhida = Ler.umInt();
                                                if (cifra_escolhida > 2 || cifra_escolhida < 1) {
                                                    System.out.println("Opção inválida, tente novamente!\n");
                                                }

                                            } while (cifra_escolhida != 1 && cifra_escolhida != 2);

                                            Merkle mkl = new Merkle();
                                            int totalPuzzles = 10000;
                                            int keyLen = 4;

                                            //Gera puzzles
                                            ArrayList<byte[]> puzzles = new ArrayList<byte[]>();
                                            ArrayList<String> keys = new ArrayList<String>();
                                            for (int i = 0; i < totalPuzzles; ++i) {
                                                String aux = mkl.random_string(16);
                                                keys.add(i, aux);
                                                byte[] ciphertext = mkl.encrypt(mkl.random_key(keyLen), "Key=" + aux + " & Puzzle=" + i);
                                                puzzles.add(ciphertext);
                                            }
                                            //Baralha os puzzles
                                            Collections.shuffle(puzzles);
                                            String chosen = cliente9.enviaPuzzles(puzzles, nome, cifra_escolhida);

                                            String keyChosen = keys.get(Integer.parseInt(chosen));
                                            //keyChosen é a chave simetrica

                                            byte[] encodedKey = keyChosen.getBytes();

                                            SecretKey originalKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");

                                            byte[] encryptedMessage = null;
                                            try {
                                                if (cifra_escolhida == 1) {
                                                    encryptedMessage = encryptText(mensagem, originalKey);
                                                } else if (cifra_escolhida == 2) {
                                                    String keyz = keyChosen + keyChosen;
                                                    byte[] doidoi = keyz.getBytes(Charset.forName("UTF-8"));

                                                    SecretKey originaKey = new SecretKeySpec(doidoi, 0, 8, "DES");

                                                    encryptedMessage = encriptaDes(mensagem, originaKey);
                                                }
                                            } catch (Exception ex) {
                                                Logger.getLogger(XIUUU.class.getName()).log(Level.SEVERE, null, ex);
                                            }

                                            cliente9.enviaCriptograma(encryptedMessage);
                                            System.out.println("Segredo enviado!\n");

                                            break;
                                        }

                                        case 3: //RSA
                                        {
                                            try {
                                                //criar certificado, colocar os valores e assinar
                                                try {
                                                    //verifica se existe o par de chaves, caso nao exista
                                                    if (!areKeysPresent()) {
                                                        // gera o par de chaves com o RSA e armazena-as
                                                        generateKey();
                                                    }
                                                } catch (Exception e) {
                                                    e.printStackTrace();
                                                }
                                                ObjectInputStream inputStream = null;
                                                inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
                                                PrivateKey privateKeySignature = (PrivateKey) inputStream.readObject();

                                                inputStream = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
                                                PublicKey publicKeySignature = (PublicKey) inputStream.readObject();

                                                X509CertInfo info = new X509CertInfo();
                                                Date from = new Date();
                                                int days = 10; //10 dias
                                                Date to = new Date(from.getTime() + days * 86400000l);
                                                CertificateValidity interval = new CertificateValidity(from, to);
                                                BigInteger sn = new BigInteger(64, new SecureRandom());
                                                X500Name owner = new X500Name("CN=localhost, O=client");

                                                info.set(X509CertInfo.VALIDITY, interval);
                                                info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
                                                try {
                                                    info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
                                                    info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
                                                } catch (Exception e) {
                                                    info.set(X509CertInfo.SUBJECT, owner);
                                                    info.set(X509CertInfo.ISSUER, owner);
                                                }

                                                info.set(X509CertInfo.KEY, new CertificateX509Key(publicKeySignature));
                                                info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
                                                AlgorithmId algo = new AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid);
                                                info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
                                                X509CertImpl cert = new X509CertImpl(info);
                                                cert.sign(privateKeySignature, "SHA1withRSA");
                                                //                         

                                                //Pedir a pk ao cliente recetor da mensagem  
                                                final PublicKey pk = cliente9.getPKfromClient2(ipSendMessage, portaSendMessage, porta, nome);  //minha porta aberta,meu nome
                                                byte[] findTamanho = mensagem.getBytes();
                                                //Cifrar mensagem com pk

                                                if (findTamanho.length > 245) {
                                                    System.out.println("O segredo tem de ser mais pequeno para usar este algoritmo");
                                                } else {
                                                    byte[] criptograma = encrypt(mensagem, pk);

                                                    cliente9.enviaCriptogramaAlg3(criptograma, cert, publicKeySignature);
                                                    System.out.println("Segredo enviado!\n");
                                                    break;
                                                }
                                            } catch (Exception e) {
                                                System.out.println(e);//Caso não se consiga conectar a outro utilizador, não rebenta
                                            }

                                            break;
                                        }
                                        case 4: {   //Distribuição de novas chaves de cifra a partir de chaves pré-distribuídas e envio de um segredo
                                            Merkle mk = new Merkle(); //para fazer uma key aleatoria, função criada no Merkle.java
                                            String k = mk.random_string(20); //nova chave de sessão

                                            byte[] decodedKey = kSemAgente.getBytes();
                                            SecretKey originalKey = new SecretKeySpec(decodedKey, 0, 16, "AES");

                                            byte[] criptogramaKey = encryptText(k, originalKey);

                                            decodedKey = k.getBytes();
                                            originalKey = new SecretKeySpec(decodedKey, 0, 16, "AES");
                                            byte[] criptogramaMensagem = encryptText(mensagem, originalKey);

                                            cliente9.enviaCriptogramaAlg4(criptogramaKey, nome, criptogramaMensagem);

                                            System.out.println("Segredo enviado!\n");
                                            break;
                                        }

                                        case 5: {   //Distribuição de novas chaves de cifra usando um agente de confiança e envio de um segredo
                                            try {
                                                Merkle mk = new Merkle(); //para fazer uma key aleatoria, função criada no Merkle.java
                                                String k = mk.random_string(20);

                                                byte[] decodedKey = k1.getBytes();
                                                SecretKey originalKey = new SecretKeySpec(decodedKey, 0, 16, "AES");

                                                byte[] criptogramaKey = encryptText(k, originalKey); //função do AESEncryption.java
                                                try {
                                                    cliente.close();
                                                    Cliente cliente2 = new Cliente(porta2, ip, nome, ipSendMessage, portaSendMessage, criptogramaKey);
                                                    TimeUnit.SECONDS.sleep(2); //para acabar o trabalho e so depois fechar
                                                    cliente2.close2();

                                                    cliente9 = new Cliente(ipSendMessage, portaSendMessage, cifra);
                                                    System.out.println("Segredo enviado!\n");
                                                } catch (Exception e) {
                                                    System.out.println("O servidor não está ativo");
                                                }
                                                int cifra55 = 55;

                                                byte[] keyByte = k.getBytes();
                                                SecretKey trueKey = new SecretKeySpec(keyByte, 0, 16, "AES"); //k em SecretKey

                                                byte[] mensagemEncriptada = encryptText(mensagem, trueKey); //segredo encriptado

                                                cliente9.algoritmoEscolhido(cifra55);
                                                cliente9.enviaCriptogramaAlg5(mensagemEncriptada, nome);

                                                break;
                                            } catch (Exception e) {
                                            }
                                        }
                                        case 0: {
                                            System.out.println("");
                                            break;
                                        }

                                        default:
                                            System.out.println("Opção inválida, tente novamente!\n");
                                    }
                                    break;
                                }
                            }
                            case 2: {
                                try {
                                    cliente.close();
                                    cliente = new Cliente(ip, porta2, nome, porta, 1, false);
                                    cliente.getInfo();
                                } catch (Exception e) {
                                    System.out.println("O servidor não está ativo");
                                }
                                break;
                            }
                            case 3: {
                                System.out.println("Insira a palavra-passe:");
                                String password = Ler.umaString();
                                System.out.println("Escreva o segredo:");
                                String mensagem2 = Ler.umaString();
                                int hash_escolhido;
                                do {
                                    System.out.println("Qual a função de hash que pretende utilizar?\n1-SHA1\n2-SHA224\n3-SHA256\n4-SHA384\n5-SHA512");
                                    hash_escolhido = Ler.umInt();
                                    if (hash_escolhido > 5 || hash_escolhido < 1) {
                                        System.out.println("Opção inválida, tente novamente!\n");
                                    }

                                } while (hash_escolhido != 1 && hash_escolhido != 2 && hash_escolhido != 3 && hash_escolhido != 4 && hash_escolhido != 5);

                                PBKDF2 pbkdf2 = new PBKDF2(password, hash_escolhido);    //Password
                                String encrypted = pbkdf2.encrypt(mensagem2);
                                System.out.println("Segredo cifrado: " + encrypted);      //Tamanho do resultado é o mesmo independetemente da função de hash usada pois usa uma secret key para cifrar a mensagem. 
                                break;
                            }
                            case 0: {
                                System.out.println("");
                                try {
                                    flag = 0;
                                    flag3 = 0;
                                    opcDados = 0;
                                    cliente.close();
                                    cliente = new Cliente(ip, porta2, nome, porta, 1, true);
                                    clienteRecetor.close();
                                    cliente.close();
                                    cliente9.close();
                                } catch (java.lang.NullPointerException e) {
                                }
                                break;
                            }
                            default:
                                System.out.println("Opcão inválida!");
                        }
                    } while (opc2 != 0);
                    break;
                }
                case 2: //MODO SERVIDOR
                {
                    System.out.println("Insira a porta:");
                    int porta3 = Ler.umInt();
                    do {
                        if (porta == porta3) {
                            System.out.println("Porta indisponível! Introduza outra:");
                            porta3 = Ler.umInt();
                        }

                        
                    } while (porta == porta3);

                    Server server = new Server(porta3);
                    System.out.println("\nServidor ligado!\n");

                    int opc3 = -1;
                    do {
                        System.out.println("1-Desligar servidor\n2-Listar clientes ativos");
                        opc3 = Ler.umInt();
                        if (opc3 == 1) {
                            server.close();
                            System.out.println("Servidor fechado!\n");
                            break;
                        }
                        if (opc3 == 2) {
                            server.getInfo();
                        } else {
                            System.out.println("Opção inválida!");
                        }
                    } while (opc3 != 1);
                    break;
                }
                case 3:{ //Help
                    System.out.println("Encontra aqui uma pequena ajuda caso tenha dúvidas ao operar com a nossa aplicação.\n" +
"	-Caso pretenda enviar um segredo, terá de entrar no menu principal como cliente.\n" +
"		Após inserir os dados iniciais, escolha a opção \"Comunicar com outro utilizador\". Nesta fase terá de inserir o IP (de quem pretende que receba o seu segredo), porta a conectar e o segredo que pretende transmitir. \n" +
"		De seguida escolha um dos cinco modos de troca de segredos disponiveis (alguns modos geram uma chave a partir de outras pré-distribuidas e, alguns têm mais do que uma opção de cifra).\n" +
"			1-> Protocolo de acordo de chaves Diffie-Hellman\n" +
"			2-> Puzzles de Merkle\n" +
"			3-> RSA\n" +
"			4-> Gerar uma nova chave a partir de chaves pré-distribuídas \n" +
"			5-> Distribuição de novas chaves de cifra usando um agente de confiança e envio de um segredo\\n\n" +
"		Se os dados inseridos estiverem corretos, o destinatário receberá o seu segredo com sucesso.\n" +
"\n" +
"	-Caso pretenda ver os clientes que estão ligados à aplicação,\n" +
"		entre no menu principal como cliente e escolha a opção \"Listar utilizadores disponíveis\"(funcionalidade disponível só quando estiver conectado ao servidor)\n" +
"\n" +
"	-Caso pretenda gerar um segredo criptográfico através de uma chave gerada por palavra-passe,\n" +
"		entre no menu principal como cliente e escolha a opção 3. Será gerado e mostrado no ecrã um segredo gerado através do tipo de cifra PBKDF2 (com a função de hash que selecionar).\n" +
"\n" +
"	-Caso pretenda ligar uma máquina como servidor, entre no menu inicial em modo de servidor e introduza a porta que pretende abrir.\n" +
"	Terá ao seu dispor a opção de desligar o servidor a qualquer momento, assim como a de listar os clientes ativos.\\n\n" +
"\n" +
"	-Para sair da aplicação, escolha a opção \"Sair\" do menu inicial.\n");
                    break;
                }
                case 0: //Sair
                    break;
                default:
                    System.out.println("Opção inválida, tente novamente!\n");
            }
        } while (opcao != 0);
        exit(0);
    }

}
