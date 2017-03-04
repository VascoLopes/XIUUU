package xiuuu;

import java.io.*;
import java.net.*;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import static xiuuu.AESEncryption.decryptText;
import static xiuuu.AESEncryption.encryptText;

public class Server implements Runnable {

    ServerSocket serverSocket;
    PrintStream streamToClient;
    BufferedReader streamFromClient;
    Socket fromClient;
    ObjectInputStream in, in2;
    ObjectOutputStream out;
    static int count = 0;
    Thread thread;
    Vector<infoCliente> list = new Vector<infoCliente>();
    int ip;
    String k1 = "AndreNelsonBoinoVasco"; //k1 para o caso5
    String k2 = "VascoBoinoNelsonAndre"; //k2 para o caso5

    public Server(int porta) {
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
                int flag = 0;
                fromClient = serverSocket.accept();
                in = new ObjectInputStream(fromClient.getInputStream());
                int escolha = (int) in.readObject();

                if (escolha == 1) {//registo de cliente
                    infoCliente novo = new infoCliente(fromClient.getInetAddress().toString(), (String) in.readObject(), (int) in.readObject());
                    String ip_novo = fromClient.getInetAddress().toString();
                    if (count == 1) {
                        list.add(novo);
                    }

                    for (int y = 0; y < list.size(); y++) {
                        if (list.elementAt(y).getIp().equals(ip_novo)) {
                            flag = 1;
                        }
                    }
                    if (flag != 1) {
                        list.add(novo);
                    }
                    out = new ObjectOutputStream(fromClient.getOutputStream());
                    out.writeObject(list.size());

                    for (int i = 0; i < list.size(); i++) {
                        out.flush();
                        out.writeObject(list.elementAt(i).toString());
                    }
                }
                if (escolha == 2) { //agente de confiança
                    String nome = (String) in.readObject();
                    int portadestino = (int) in.readObject();
                    String ipdestino = (String) in.readObject();
                    byte[] criptogramaKey = (byte[]) in.readObject();
                    byte[] decodedKey = k1.getBytes();
                    SecretKey originalKey = new SecretKeySpec(decodedKey, 0, 16, "AES");

                    try {
                        String k = decryptText(criptogramaKey, originalKey); //função do AESEncryption.java

                        byte[] key2Bytes = k2.getBytes();
                        SecretKey k2Key = new SecretKeySpec(key2Bytes, 0, 16, "AES");

                        byte[] kencriptadocomK2 = encryptText(k, k2Key);

                        Socket toClient;
                        toClient = new Socket(ipdestino, portadestino);
                        out = new ObjectOutputStream(toClient.getOutputStream());
                        out.writeObject(5);
                        out.writeObject(nome);
                        out.writeObject(kencriptadocomK2);
                    } catch (Exception ex) {
                        Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
                if (escolha == 0) {

                    String ipof = "" + fromClient.getInetAddress();
                    ipof = ipof.substring(1);
                    for (int i = 0; i < list.size(); i++) {
                        String ipsai = list.elementAt(i).getIp().substring(1);
                        if (ipsai.equals(ipof)) {
                            list.remove(i);
                        }
                    }

                }
            }
        } catch (java.net.SocketException ex) {
        } catch (IOException ex) {

        } catch (ClassNotFoundException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void close() throws IOException {
        try {
            serverSocket.close();
        } catch (java.net.SocketException ex) {
            System.out.println("Servidor fechado\n");
        }
    }

    public void getInfo() {
        int flag = 0;
        for (int i = 0; i < list.size(); i++) {
            System.out.println(list.elementAt(i).toString());
            flag = 1;
        }
        if (flag == 0) {
            System.out.println("Não há clientes ativos!");
        }
        System.out.println("");
    }
}
