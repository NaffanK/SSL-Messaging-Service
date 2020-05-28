
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;
import static java.lang.Math.random;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.Cipher; 
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author kingtahir
 */
public class Client {
    private Socket socket = null;
    private DataOutputStream output = null;
    private DataInputStream input = null;
    private PublicKey srvrPU;
    private Key Ks;
    private SecretKeySpec clientMACkey;
    private SecretKeySpec serverMACkey;
    private ByteArrayOutputStream outputStream;
    
    public Client(String address, int port){
        try {
            socket = new Socket(address, port);
            input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            output = new DataOutputStream(socket.getOutputStream());
        } catch (Exception e) {
           System.err.println(e);
        }
        SecureRandom random = new SecureRandom();
        int byte_count = 0;
        
        try{
            
        System.out.println("----- Client Side -----");    
        // Phase 1 of the Handshake
        // Client Sends the First Message and the First Nonce to its Server
        System.out.println("\n----- Start of Phase 1 -----");
        int N1_client = random.nextInt();
        String sessionID = "001";
        String sslVer = "2.0";
        String KeyExchangeProtocol = "RSA";
        String CipherExchangeProtocol = "DES";
        String MacAlgorithm = "SHA1WithRSA";
        String helloMsg = "" + N1_client + "|" + sessionID + "|" + sslVer + "|" + KeyExchangeProtocol + "|" + CipherExchangeProtocol + "|" + MacAlgorithm;
        
        // Sending to the Server
        output.write(helloMsg.getBytes());
        //System.out.println("The sent Hello Message to Server is: " + helloMsg);
        
        // Client will receive a Hello Message from Server
        byte[] servermsg = new byte[10000];
        byte_count = input.read(servermsg);
        byte[] exact_msg = Arrays.copyOfRange(servermsg, 0, byte_count);
        helloMsg = new String(exact_msg);
        System.out.println("The received Hello Message from Server is: " + helloMsg);
        String serverDN = helloMsg.split("\\|")[helloMsg.split("\\|").length - 2];
        int N1_prev = Integer.parseInt(helloMsg.split("\\|")[0]);
        int N1_server = Integer.parseInt(helloMsg.split("\\|")[helloMsg.split("\\|").length - 1]);
        if(N1_client == N1_prev){
            System.out.println("----- Replay Attack Prevented -----\nNonce matched.");
        }
        System.out.println("----- End of Phase 1 -----");
        
        // Phase 2 of the Handshake
        // Client will receive a certificate from Server
        System.out.println("\n----- Start of Phase 2 -----");
        servermsg = new byte[10000];
        byte_count = input.read(servermsg);
        exact_msg = Arrays.copyOfRange(servermsg, 0, byte_count);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(exact_msg);
        X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);
        System.out.println("The received Certificate from Server is: " + cert.toString());
        
        // Validating the Server's Certificate 
        cert.checkValidity();
        
        // Verifying Server Certificate Public Key
        cert.verify(cert.getPublicKey());
        
        //Verify the Issuer DN
        if(cert.getIssuerDN().getName().equals(serverDN)){
            System.out.println("----- Domain Name of the Issuer has Matched -----\n");
        }
        
        // Client will receive a Hello Done Message from Server
        servermsg = new byte[10000];
        byte_count = input.read(servermsg);
        exact_msg = Arrays.copyOfRange(servermsg, 0, byte_count);
        String helloDoneMsg = new String(exact_msg);
        System.out.println("The received Hello Done Message from Server is: " + helloDoneMsg);
        System.out.println("----- End of Phase 2 -----");
        
        // Phase 3 of the Handshake
        System.out.println("\n----- Start of Phase 3 -----");
        SecureRandom secrandom = new SecureRandom(); 
        byte[] pre_master_secret = new byte[48];
        secrandom.nextBytes(pre_master_secret);
        this.srvrPU = cert.getPublicKey();
        byte[] encrypted_pre_master_secret = this.encryptWithRSA(pre_master_secret);
        
        // Sending the Pre Master Secret to the Server
        output.write(encrypted_pre_master_secret);
 
        //byte[] master_secret = md5.digest(pre_master_secret + sha.digest('A' + pre_master_secret + N1_client + N1_server)) + md5.digest(pre_master_secret + sha.digest('BB' + pre_master_secret + N1_client + N1_server)) + md5.digest(pre_master_secret + sha.digest('CCC' + pre_master_secret + N1_client +  N1_server));
        Integer N1_client_server = N1_client + N1_server;
        outputStream = new ByteArrayOutputStream();
        outputStream.write(pre_master_secret);
        outputStream.write("master secret".getBytes("UTF-8"));
        outputStream.write(N1_client_server.byteValue());
        byte[] master_secret = outputStream.toByteArray();
        master_secret = Arrays.copyOfRange(master_secret,0,48);
        
        //Establish keys
        this.clientMACkey = new SecretKeySpec(Arrays.copyOfRange(master_secret, 0, 8), "HmacSHA1");
        this.serverMACkey = new SecretKeySpec(Arrays.copyOfRange(master_secret, 8, 16), "HmacSHA1");
        SecretKeyFactory DESFactory = SecretKeyFactory.getInstance("DES");
        DESKeySpec desKeyspec = new DESKeySpec(Arrays.copyOfRange(master_secret,16,24));
        this.Ks = DESFactory.generateSecret(desKeyspec); 
        System.out.println("----- End of Phase 3 -----");
                
        // Phase 4 of the HandShake
        System.out.println("\n----- Start of Phase 4 -----");
        Integer change_cipher_spec_val = 1;
        byte change_cipher_spec_msg = change_cipher_spec_val.byteValue();
        
        //Client Sends Change Cipher Spec Message to Server
        output.write(change_cipher_spec_msg);
        //System.out.println("Client Sends Change Cipher Spec Message: " + change_cipher_spec_msg);
        
        // Server receives Change Cipher Spec Message from Client
        servermsg = new byte[10000];
        byte_count = input.read(servermsg);
        byte[] ccs = Arrays.copyOfRange(servermsg, 0, byte_count);
        System.out.println("Server Sent Change Cipher Spec Message: " + ccs[0]);
        
        // Client Sends a Message to Server that future messages from the client are encrypted with the session key (Ks)
        String inform_msg = "Future messages will now be encrypted with Ks";
        byte[] inform_bytes = inform_msg.getBytes();
        output.write(inform_bytes);
        //System.out.println("Client informs Server: " + inform_msg);
        
         // Client is informed by Server
        servermsg = new byte[10000];
        byte_count = input.read(servermsg);
        exact_msg = Arrays.copyOfRange(servermsg, 0, byte_count);
        System.out.println("Client is informed by Server: " + new String(exact_msg));
        
        // Client sends an encrypted message of informing the server that Handshake is over with the session key (Ks)
        String finished_msg = "Handshake Finished";
        byte[] encrypted_finished_msg = encryptWithDES(finished_msg.getBytes());
        output.write(encrypted_finished_msg);
        //System.out.println("Client Sends Finished Message: " + finished_msg);
        
        // Client receives encrypted Finished Message from Server
        servermsg = new byte[10000];
        byte_count = input.read(servermsg);
        exact_msg = Arrays.copyOfRange(servermsg, 0, byte_count);
        byte[] decrypted_finished_msg = decryptWithDES(exact_msg);
        System.out.println("Server Sent Finished Message: " + new String(decrypted_finished_msg));
        System.out.println("----- End of Phase 4 -----");
        
        System.out.println("----- SSL Connection Established -----\n");
        
        Scanner userin = new Scanner(System.in);
        String message;
      while(true){  
        //Send Message to Server
        System.out.println("Enter your message (enter exit to leave chat): ");
        message = userin.nextLine();
        if(message.equalsIgnoreCase("exit")) break;
        System.out.println("Waiting for response...");
        if(message.length() < 3){
            for(int j = 0; j < 3 - message.length() + 1; j++){
                message += " ";
            }
        }
        messageToServer(fragment(message, (int) Math.ceil(message.length()/3.0)));
        
        //Receiving Server's message
        outputStream = new ByteArrayOutputStream();
        int count = 0;
        while(count < 3){
            servermsg = new byte[10000];
            byte_count = input.read(servermsg);
            if(byte_count == -1){
                System.err.println("Server Disconnected");
                System.exit(0);
            }
            exact_msg = Arrays.copyOfRange(servermsg,0,byte_count);
            Thread.sleep(1000);
            messageFromServer(exact_msg,outputStream);
            count++;
        }
        String server_message = new String(outputStream.toByteArray());
        System.out.println("Message from Server: " + server_message);
      }      
        }catch(Exception e){
            System.err.println(e);
        }
        try {
            input.close();
            output.close();
            socket.close();
        } catch (Exception e) {
           System.err.println(e);
        }
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
    
    public byte[] encryptWithRSA(byte[] message) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, this.srvrPU);
        // Encrypting the message
        byte[] encryptedMSG = cipher.doFinal(message);
        
        return encryptedMSG;
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
    
    public void messageToServer(byte[][] fragments) throws Exception{
        Mac sha1 = Mac.getInstance("HmacSHA1");
        sha1.init(this.clientMACkey);
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
    
    public void messageFromServer(byte[] exact_msg, ByteArrayOutputStream outputStream) throws Exception{
        Mac sha1 = Mac.getInstance("HmacSHA1");
        sha1.init(this.serverMACkey);
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
    public static void main(String[] args) throws Exception{
        Client client = new Client("127.0.0.1", 5000);
    }
    
}
