
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author kingtahir
 */
public class Server {
    private DataInputStream input = null;
    private DataOutputStream output = null;
    private Socket sc = null;
    private ServerSocket srvr = null;
    private PrivateKey privateKey;
    private SecretKey Ks;
    private SecretKeySpec clientMACkey;
    private SecretKeySpec serverMACkey;
    private ByteArrayOutputStream outputStream;
    
    public Server(int port){
    try{
        int byte_count = 0; 
        Random random = new Random();
        srvr = new ServerSocket(port);
        System.out.println("----- Server Side -----");
        System.out.println("..... Waiting for the Client .....");
        sc = srvr.accept();
        input = new DataInputStream(new BufferedInputStream(sc.getInputStream()));
        output = new DataOutputStream(sc.getOutputStream());
        System.out.println("Connection is established with Client!!\n");
        try{
        // First Phase of the Handshake
        System.out.println("\n----- Start of Phase 1 -----");
        // Server will receive a Hello Message from Client
        byte[] clientmsg = new byte[10000];
        byte_count = input.read(clientmsg);
        byte[] exact_msg = Arrays.copyOfRange(clientmsg, 0, byte_count);
        String helloMsg = new String(exact_msg);
        String[] helloMsgArray = helloMsg.split("\\|");
        int N1_client = Integer.parseInt(helloMsgArray[0]);
        String KeyExchangeProtocol = helloMsgArray[3];
        String MacAlgorithm= helloMsgArray[5];
        System.out.println("The received Hello Message from Client is: " + helloMsg);
        
        // Server sends a Hello Message to Client
        int N1_server = random.nextInt();
        String serverDN = "CN=Agithahiti";
        helloMsg = helloMsg + "|" + serverDN + "|" + N1_server;
        output.write(helloMsg.getBytes());
        //System.out.println("The sent Hello Message to Client is: " + helloMsg);
        System.out.println("----- End of Phase 1 -----");
        
        // Second Phase of the Handshake
        System.out.println("\n----- Start of Phase 2 -----");
        // Server sends its Certificate
        X509Certificate cert = certificate(KeyExchangeProtocol, MacAlgorithm);
        output.write(cert.getEncoded());
        //System.out.println("The sent Certificate to Client is: " + cert.toString());
        // Server sends a Hello Done Message to Client
        String helloDoneMsg = "Server Hello Message is Done";
        output.write(helloDoneMsg.getBytes());
        //System.out.println("The sent Hello Done Message to Client is: " + helloDoneMsg);
        System.out.println("----- End of Phase 2 -----");
        
        // Phase 3 of the Handshake
        System.out.println("\n----- Start of Phase 3 -----");
        // Server will receive a Pre Master Secret from Client
        clientmsg = new byte[10000];
        byte_count = input.read(clientmsg);
        exact_msg = Arrays.copyOfRange(clientmsg, 0, byte_count);
        byte[] decrypted_pre_master_secret = this.decryptWithRSA(exact_msg);
        Integer N1_client_server = N1_client + N1_server;
        outputStream = new ByteArrayOutputStream();
        outputStream.write(decrypted_pre_master_secret);
        outputStream.write("master secret".getBytes("UTF-8"));
        outputStream.write(N1_client_server.byteValue());
        byte[] master_secret = outputStream.toByteArray();
        master_secret = Arrays.copyOfRange(master_secret,0,48);
        
        //Establish Keys
        this.clientMACkey = new SecretKeySpec(Arrays.copyOfRange(master_secret, 0, 8), "HmacSHA1");
        this.serverMACkey = new SecretKeySpec(Arrays.copyOfRange(master_secret, 8, 16), "HmacSHA1");
        SecretKeyFactory DESFactory = SecretKeyFactory.getInstance("DES");        
        DESKeySpec desKeyspec = new DESKeySpec(Arrays.copyOfRange(master_secret,16,24));
        this.Ks = DESFactory.generateSecret(desKeyspec);  
        System.out.println("----- End of Phase 3 -----");
        
        // Phase 4 of the Handshake
        System.out.println("\n----- Start of Phase 4 -----");
        // Server receives Change Cipher Spec Message from Client
        clientmsg = new byte[10000];
        byte_count = input.read(clientmsg);
        byte[] change_cipher_spec_msg = Arrays.copyOfRange(clientmsg, 0, byte_count);
        System.out.println("Client Sent Change Cipher Spec Message: " + change_cipher_spec_msg[0]);
        
        Integer change_cipher_spec_val = 1;
        byte ccs = change_cipher_spec_val.byteValue();
        //Server Sends Change Cipher Spec Message to Client
        output.write(ccs);
        //System.out.println("Server Sends Change Cipher Spec Message: " + ccs);
        
        // Server is informed by Client
        clientmsg = new byte[10000];
        byte_count = input.read(clientmsg);
        exact_msg = Arrays.copyOfRange(clientmsg, 0, byte_count);
        System.out.println("Server is informed by Client: " + new String(exact_msg));
        
        //Server informs Client
        String inform_msg = "Future messages will now be encrypted with Ks";
        byte[] inform_bytes = inform_msg.getBytes();
        output.write(inform_bytes);
        //System.out.println("Server informs Client: " + inform_msg);
        
        // Server receives encrypted Finished Message from Client
        clientmsg = new byte[10000];
        byte_count = input.read(clientmsg);
        exact_msg = Arrays.copyOfRange(clientmsg, 0, byte_count);
        byte[] decrypted_finished_msg = decryptWithDES(exact_msg);
        System.out.println("Client Sent Finished Message: " + new String(decrypted_finished_msg));
        
        // Server sends an encrypted message of informing the client that Handshake is over with the session key (Ks)
        String finished_msg = "Handshake Finished";
        byte[] encrypted_finished_msg = encryptWithDES(finished_msg.getBytes());
        output.write(encrypted_finished_msg);
        //System.out.println("Server Sends Finished Message: " + finished_msg);
        System.out.println("----- End of Phase 4 -----");
       
        System.out.println("----- SSL Connection Established -----\n");
        
        Scanner userin = new Scanner(System.in);
        String message;
       while(true){
        //Receiving Client's message
       
        outputStream = new ByteArrayOutputStream();
        int count = 0;
        while(count < 3){
            clientmsg = new byte[10000];
            byte_count = input.read(clientmsg);
            if(byte_count == -1){
                System.err.println("Client Disconnected");
                System.exit(0);
            }
            exact_msg = Arrays.copyOfRange(clientmsg,0,byte_count);
            Thread.sleep(1000);
            messageFromClient(exact_msg,outputStream);
            count++;
        }
        String client_message = new String(outputStream.toByteArray());
        System.out.println("Message from Client: " + client_message);
        
        //Send Message to Client
        System.out.println("Enter your message (enter exit to leave chat): ");
        message = userin.nextLine();
        if(message.equalsIgnoreCase("exit")) break;
        System.out.println("Waiting for response...");
        if(message.length() < 3){
            for(int j = 0; j < 3 - message.length() + 1; j++){
                message += " ";
            }
        }
        
        messageToClient(fragment(message, (int) Math.ceil(message.length()/3.0)));
       } 
        }catch(Exception e){
            System.err.println(e);
        }
        
        input.close();
        output.close();
        sc.close();
    }catch (Exception e) {
           System.err.println(e);
        }

    }
    
    public X509Certificate certificate(String KeyExchangeProtocol, String MacAlgorithm) throws Exception{
        CertAndKeyGen keyGen = new CertAndKeyGen(KeyExchangeProtocol, MacAlgorithm, null);
        keyGen.generate(1024);
        X500Name issuer = new X500Name("CN=Agithahiti");
        X509Certificate cert = keyGen.getSelfCertificate(issuer, 1000);
        
        // Private Key of the Server
        this.privateKey = keyGen.getPrivateKey();
        return cert;
    }
    
    public byte[] decryptWithRSA(byte[] message) throws Exception{
        Cipher deCipher = Cipher.getInstance("RSA");
        deCipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        // Decrypting the message
        byte[] decryptedMSG = deCipher.doFinal(message);
        
        return decryptedMSG;
    }
    
    
    public byte[] encryptWithDES(byte[] message) throws Exception{
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.Ks);
        byte[] ciphertext = cipher.doFinal(message);
  
        
        return ciphertext;
    }
    
    public byte[] decryptWithDES(byte[] message) throws Exception{
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.Ks);
 
        return cipher.doFinal(message);
    }
    
    public void messageFromClient(byte[] exact_msg, ByteArrayOutputStream outputStream) throws Exception{
        Mac sha1 = Mac.getInstance("HmacSHA1");
        sha1.init(this.clientMACkey);
        byte recordbyte = exact_msg[0];
        Integer recordheader = (recordbyte & 0xFF);
        byte[] decrypted_frag = decryptWithDES(Arrays.copyOfRange(exact_msg,1,exact_msg.length));
        byte[] message = Arrays.copyOfRange(decrypted_frag,0,recordheader);
        byte[] hash = Arrays.copyOfRange(decrypted_frag,recordheader,decrypted_frag.length);
        if(!Arrays.equals(sha1.doFinal(message),hash)){
            System.err.println("Integrity Compromised");
            System.exit(0);
        }
        outputStream.write(message);
    }
    
    public byte[][] fragment(String data, int fragsize) throws Exception{
        int x = 0;
        byte[][] fragments = new byte[(int) Math.ceil(data.getBytes("UTF-8").length / (double)fragsize)][fragsize];
        for(int i = 0; i < fragments.length; i++){
            fragments[i] = Arrays.copyOfRange(data.getBytes("UTF-8"), x, x+fragsize);
            x += fragsize;
        }
        return fragments;
    }
    
    public void messageToClient(byte[][] fragments) throws Exception{
        Mac sha1 = Mac.getInstance("HmacSHA1");
        sha1.init(this.serverMACkey);
        byte[] concat;
        for(int i = 0; i < fragments.length; i++){
            outputStream = new ByteArrayOutputStream();
            Integer recordheader = fragments[i].length;
            outputStream.write(fragments[i]);
            byte[] hash = sha1.doFinal(fragments[i]);
            outputStream.write(hash);
            concat = outputStream.toByteArray();
            byte[] encrypted_concat = encryptWithDES(concat);
            
            outputStream = new ByteArrayOutputStream();
            outputStream.write(recordheader.byteValue());
            outputStream.write(encrypted_concat);
            Thread.sleep(1000);
            output.write(outputStream.toByteArray());
        }
        
    }
    
    public static void main(String[] args) throws Exception{
        Server server = new Server(5000);
    }
    
}
