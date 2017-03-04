package xiuuu;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import sun.security.x509.X509CertImpl;

public class Cliente {

    PrintStream streamToServer;
    BufferedReader streamFromServer;
    Socket toServer;
    Socket toClient;
    PrintStream streamToServer2;
    BufferedReader streamFromServer2;
    Socket toServer2;
    ObjectInputStream in;
    static int count = 0;
    Vector<infoCliente> list = new Vector<infoCliente>();

    public Cliente() {

    }

    public Cliente(String ipSendMessage, int portaSendMessage, int escolha) {
        connecToClient(ipSendMessage, portaSendMessage, escolha);
    }

    public Cliente(String ip, int porta, String nome, int portaescuta, int escolha, boolean desliga)//porta é do servidor, portaescuta é a do cliente
    {
        connectToServer(ip, porta, nome, portaescuta, escolha, desliga);
    }

    public Cliente(int porta, String ip2, String nome, String ip, int portaescuta, byte[] criptogramaKey) {
        connectToServer2(porta, ip2, nome, ip, portaescuta, criptogramaKey);
    }

    private void connectToServer(String ip, int porta, String nome, int portaescuta, int escolha, boolean desliga) {
        try {
            try {
                if (desliga == false) {
                    //System.out.println("A fazer um pedido ao servidor...");
                }
                toServer = new Socket(ip, porta);
                toServer.setSoTimeout(4000);
                if (desliga == false) {
                    //System.out.println("Sucesso!");
                }

            } catch (Exception e) {
                System.out.println("Servidor desligado");
            }
            ObjectOutputStream out;
            out = new ObjectOutputStream(toServer.getOutputStream());
            if (desliga == true) {
                out.writeObject(0);
            } else {
                out.writeObject(escolha);
            }
            out.writeObject(nome);
            out.writeObject(portaescuta);
            if (desliga == true) {
                out.writeObject(ip);
            }
        } catch (Exception e) {

        }
    }

    private void connectToServer2(int porta, String ip2, String nome, String ip, int portaescuta, byte[] criptogramaKey) {
        try {
            toServer2 = new Socket(ip2, porta);

            ObjectOutputStream out;
            try {
                out = new ObjectOutputStream(toServer2.getOutputStream());
                int x = 2;
                out.writeObject(x);
                out.writeObject(nome);
                out.writeObject(portaescuta);
                out.writeObject(ip);
                out.writeObject(criptogramaKey);
            } catch (IOException ex) {
                Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (Exception e) {
        }

    }

    public void close() throws IOException {
        toServer.close();
    }

    public void close2() throws IOException {
        toServer2.close();
    }

    public void getInfo() throws IOException, ClassNotFoundException {
        in = new ObjectInputStream(toServer.getInputStream());
        String aux;
        int size = (int) in.readObject();
        for (int i = 0; i < size; i++) {
            aux = (String) in.readObject();
            System.out.println(aux);

        }
    }

    public void connecToClient(String ip, int porta, int escolha) {
        try {
            toClient = new Socket(ip, porta);
           
        } catch (IOException ex) {
            if (escolha != 0) //Para não dar esta mensagem no Voltar  
            {
                System.out.println("Cliente desligado");
            }
        }
    }

    public PublicKey getPKfromClient2(String ipSendMessage, int portaSendMessage, int minha_porta, String nome) throws IOException, ClassNotFoundException {
        ObjectOutputStream aviso;
        aviso = new ObjectOutputStream(toClient.getOutputStream());
        aviso.writeObject("manda-me a pk");
        String meu_ip = toClient.getLocalAddress().toString();
        aviso.writeObject(meu_ip);
        aviso.writeObject(minha_porta);
        aviso.writeObject(nome);

        ObjectInputStream pk;
        pk = new ObjectInputStream(toClient.getInputStream());
        PublicKey publicK = (PublicKey) pk.readObject();

        return publicK;
    }

    public void enviaCriptograma(byte[] cript) throws IOException {
        ObjectOutputStream criptograma;
        criptograma = new ObjectOutputStream(toClient.getOutputStream());
        criptograma.writeObject("aqui vai o criptograma");
        criptograma.writeObject(cript);
    }

    public void enviaCriptogramaAlg1(byte[] cript, PublicKey pk, byte[] signatureBytes) throws IOException {
        ObjectOutputStream criptograma;
        criptograma = new ObjectOutputStream(toClient.getOutputStream());
        criptograma.writeObject("aqui vai o criptograma");
        criptograma.writeObject(cript);
        criptograma.writeObject(pk);
        criptograma.writeObject(signatureBytes);
    }
    
    public void enviaCriptogramaAlg3(byte[] cript, X509CertImpl cert, PublicKey publicKeySignature) throws IOException {
        ObjectOutputStream criptograma;
        criptograma = new ObjectOutputStream(toClient.getOutputStream());
        criptograma.writeObject("aqui vai o criptograma");
        criptograma.writeObject(cript);
        criptograma.writeObject(cert);
        criptograma.writeObject(publicKeySignature);
    }
    
    public void enviaCriptogramaAlg4(byte[] criptkey, String nome, byte[] criptMesg) throws IOException {
        ObjectOutputStream criptograma;
        criptograma = new ObjectOutputStream(toClient.getOutputStream());
        criptograma.writeObject(criptkey);
        criptograma.writeObject(nome);
        criptograma.writeObject(criptMesg);
    }

    public void enviaCriptogramaAlg5(byte[] cript, String nome) throws IOException {
        ObjectOutputStream criptograma;
        criptograma = new ObjectOutputStream(toClient.getOutputStream());
        criptograma.writeObject(nome);
        criptograma.writeObject(cript);
    }

    public String enviaPuzzles(ArrayList<byte[]> puzzles, String nome, int cifra_escolhida) throws IOException, ClassNotFoundException //tivemos de mudar a cena para String em vez de int
    {
        ObjectOutputStream out;
        out = new ObjectOutputStream(toClient.getOutputStream());
        out.writeObject("aqui vao os puzzles");
        out.writeObject(puzzles);
        out.writeObject(nome);
        out.writeObject(cifra_escolhida);
        ObjectInputStream in;
        in = new ObjectInputStream(toClient.getInputStream());
        String chosen = (String) in.readObject();

        return chosen;
    }

    public void algoritmoEscolhido(int algoritmo) throws IOException {
        ObjectOutputStream out;
        out = new ObjectOutputStream(toClient.getOutputStream());
        out.writeObject(algoritmo);
    }

    public BigInteger sendNum(BigInteger P, BigInteger g, BigInteger X, String nome) throws IOException, ClassNotFoundException {
        ObjectOutputStream out;
        
        out = new ObjectOutputStream(toClient.getOutputStream());
        out.writeObject(P);
        out.writeObject(g);
        out.writeObject(X);
        out.writeObject(nome);

        ObjectInputStream in;
        in = new ObjectInputStream(toClient.getInputStream());
        BigInteger Y = (BigInteger) in.readObject();
        return Y;
    }
}
