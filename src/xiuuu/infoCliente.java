package xiuuu;

public class infoCliente {

    private String ip;
    private String nome;
    private int porta;

    public infoCliente() {
        ip = "";
        nome = "";
        porta = 0;
    }

    public void infoClienteempty() {
        this.ip = "";
        this.nome = "";
        this.porta = 0;
    }

    public infoCliente(String ip, String nome, int porta) {
        this.ip = ip;
        this.nome = nome;
        this.porta = porta;
    }

    @Override
    public String toString() {
        return "Nome:" + nome + " | IP:" + ip.substring(1) + " | Porta:" + porta;
    }

    public String getIp() {
        return ip;
    }

}
