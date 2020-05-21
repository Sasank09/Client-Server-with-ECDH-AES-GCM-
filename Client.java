import java.io.*;
import java.net.*;
import java.util.Scanner;
import java.math.BigInteger;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


class ECC 
{
//GENERATING EC KEYS//
        
    public static final int GCM_IV_LENGTH = 12;// 4 for counter
    public static final int GCM_TAG_LENGTH = 16;
    public static final byte[] aad = "1234abcd".getBytes();
    
    public static KeyPair generateECKeys(String secretekey)
    {

        KeyPair kpU = null;
        try {
            KeyPairGenerator kpg;
            kpg = KeyPairGenerator.getInstance("EC", "SunEC");
            ECGenParameterSpec ecsp;
            //String parameter = "sect113r2";
            ecsp = new ECGenParameterSpec(secretekey);
            kpg.initialize(ecsp);
            kpU = kpg.genKeyPair();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return kpU;

    }
//ENCRYPTION METHOD//
    public static String encryptString(SecretKey encryptionKey, String plainText, byte[] iv) throws Exception 
    {       
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            //Key encryptionKey = new SecretKeySpec(key.getEncoded(),key.getAlgorithm());
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH* 8,iv);
            byte[] plainTextBytes = plainText.getBytes("UTF-8");
            byte[] cipherText;

            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, gcmParameterSpec);
            cipher.updateAAD(aad);
            cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
            int encryptLength = cipher.update(plainTextBytes, 0,plainTextBytes.length, cipherText, 0);
            encryptLength += cipher.doFinal(cipherText, encryptLength);

            return bytesToHex(cipherText);
    }
//DECRYPTION METHOD//
    public static String decryptString(SecretKey decryptionKey, String cipherText,byte[] iv)throws Exception 
    {
    		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
           // Key decryptionKey = new SecretKeySpec(key.getEncoded(),key.getAlgorithm());            
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);            
            byte[] cipherTextBytes = hexToBytes(cipherText);
            byte[] plainText;

            cipher.init(Cipher.DECRYPT_MODE, decryptionKey, gcmParameterSpec);
            cipher.updateAAD(aad);
            plainText = new byte[cipher.getOutputSize(cipherTextBytes.length)];
            int decryptLength = cipher.update(cipherTextBytes, 0, cipherTextBytes.length, plainText, 0);
            decryptLength += cipher.doFinal(plainText, decryptLength);

            return new String(plainText,"UTF-8");
    }
//Conversions//
    public static String bytesToHex(byte[] data) 
    {
          int length =data.length;
        String digits = "0123456789ABCDEF";
        StringBuffer buffer = new StringBuffer();

        for (int i = 0; i != length; i++)
         {
            int v = data[i] & 0xff;

            buffer.append(digits.charAt(v >> 4));
            buffer.append(digits.charAt(v & 0xf));
         }

        return buffer.toString();
    }

    
    public static byte[] hexToBytes(String string) 
    {
        int length = string.length();
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) 
        {
            data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4) + Character
                    .digit(string.charAt(i + 1), 16));
        }
        return data;
    }

}

//Client Class
public class Client
{    
  public static final int AES_KEY_SIZE = 32;
  static int i=0;
  	public static void main(String[] args) throws Exception
 	{
  		try
  		{
     		Socket sock = new Socket("localhost", 3000);
                               // reading from keyboard (keyRead object)
  			BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
                              // sending to client (pwrite object)
    		OutputStream ostream = sock.getOutputStream(); 
     		PrintWriter pwrite = new PrintWriter(ostream, true);
                              // receiving from server ( receiveRead  object)
     		InputStream istream = sock.getInputStream();
     		BufferedReader receiveRead = new BufferedReader(new InputStreamReader(istream));

     		System.out.println("Enter Password: ");
     		String pwd = keyRead.readLine();
     		pwrite.println(pwd);
     		pwrite.flush();
     		String suc =receiveRead.readLine().trim();
     		if(suc.equals("Success"))
     		{   // ECC obj and getting keys
      			ECC ecc = new ECC();
      			KeyPair clientKey = ECC.generateECKeys("secp256k1");
      			PrivateKey clientPrivKey = clientKey.getPrivate();
     		 	PublicKey clientPubKey = clientKey.getPublic();
      			byte[] cpublicKeyBytes = clientPubKey.getEncoded();
      			String cpubKey=ECC.bytesToHex(cpublicKeyBytes);    //string form to send pub key
      			
      			System.out.println("_____________________________________________________________________________");
      			System.out.println("\n Client PrivateKey Generated  \n\n"+ECC.bytesToHex(clientPrivKey.getEncoded()));
      			System.out.println("_____________________________________________________________________________");
			    System.out.println("\n Client PublicKey Generated  \n\n"+clientPubKey);
			    System.out.println("_____________________________________________________________________________");
			    System.out.println("\n Client PublicKey String Form  \n\n"+cpubKey);
      			System.out.println("_____________________________________________________________________________");

// Sending Client Public Key
      			pwrite.println(cpubKey);
		        pwrite.flush();

//GETTING SERVER PUBKEY
		      	String spubKeyStr= receiveRead.readLine();		       
			    System.out.println("\n Recived Server PublicKey in String from \n\n" +spubKeyStr);
			    System.out.println("_____________________________________________________________________________");
// Convert the  server's public key bytes into a PublicKey object
			    byte[] spkBytes = ECC.hexToBytes(spubKeyStr);
			    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(spkBytes);
			    KeyFactory keyFactory = KeyFactory.getInstance("EC");
			    PublicKey servPubKey = keyFactory.generatePublic(x509KeySpec);   
			    System.out.println("\n server Public Key received in Key Object Form : \n\n"+servPubKey);
			    System.out.println("_____________________________________________________________________________");
//KEY AGREEMENT ECDH
	            KeyAgreement clientEcdh = KeyAgreement.getInstance("ECDH");
	            clientEcdh.init(clientPrivKey);
	            clientEcdh.doPhase(servPubKey,true);
	            
	            byte[] sbytes =  clientEcdh.generateSecret();            
	            SecretKey skey = new SecretKeySpec(sbytes, 0, AES_KEY_SIZE, "AES");
	            byte[] sh =skey.getEncoded();
	            String shared= ECC.bytesToHex(sh);
	            System.out.println("\n Genrated SecretKey \t"+shared);
	            System.out.println("_____________________________________________________________________________");

// To Transfer and recieve data  in Secured Channel Communication 
			    System.out.println("\nType and press Enter key to send Data\n");    
			    String receiveMessage, sendMessage;               
			    while(true)
			    {	
			     	i=i+1;
			     	String siv=receiveRead.readLine().trim();
			        byte[] iv = ECC.hexToBytes(siv);
			        System.out.println("\nIV  "+siv + "  For Communication Cycle: "+i+"\n______________________________________________________\n");
			        sendMessage = keyRead.readLine();  // keyboard reading
			        String encryptedmsg = ECC.encryptString(skey,sendMessage,iv);
			        System.out.println("encryptedmsg: "+encryptedmsg);
			        System.out.println("\n-------- Mesg Sent --------Wait For Reply from server -------- \n");  
			        
			        pwrite.println(encryptedmsg);       // sending to server
			        pwrite.flush();                    // flush the data
			        if((receiveMessage = receiveRead.readLine()) != null) //receive from server
			        {
			            System.out.println("Msg From Server(cipher):  "+receiveMessage); // displaying at DOS prompt
			            String decryptedmsg =ECC.decryptString(skey,receiveMessage,iv);
			            System.out.println("Original Msg:::   "+decryptedmsg);
			            System.out.println("\n-------- Type your Reply -------- or Ctrl+C To EXIT --------\n");
			        }         
			    }
   			} 
     		else
     		{
      			System.out.println("wrong Password Connection stopped");
      			sock.close();
      			System.exit(0);
      		}
    	}
   		catch(Exception e)
   		{
   			System.out.println("Socket Connection Error");
   		}            
    }                    
}    