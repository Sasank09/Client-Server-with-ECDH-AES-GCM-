import java.io.*;
import java.net.*;
import java.util.*;
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

// ELLIPTIC CURVE CLASS
class ECC 
{       
//Elliptic Curve KeyPair Generation//
	
    public static final int GCM_TAG_LENGTH = 16;
    public static final byte[] aad = "1234abcd".getBytes();

    public static KeyPair generateECKeys(String secretekey)
    {

        KeyPair kpU = null;
        try {
            KeyPairGenerator kpg;
            kpg = KeyPairGenerator.getInstance("EC", "SunEC");
            ECGenParameterSpec ecsp;
            ecsp = new ECGenParameterSpec(secretekey);
            kpg.initialize(ecsp);
            kpU = kpg.genKeyPair();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return kpU;

    }

//ENCRYPTION METHOD Using AES with Shared Secret Key(skey) and random nonce value
    public static String encryptString(SecretKey encryptionKey, String plainText,byte[] iv) throws Exception 
    {       
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            //Key encryptionKey = new SecretKeySpec(key.getEncoded(),key.getAlgorithm());
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8,iv);
            byte[] plainTextBytes = plainText.getBytes("UTF-8");
            byte[] cipherText;

            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, gcmParameterSpec);
            cipher.updateAAD(aad);
            cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
            int encryptLength = cipher.update(plainTextBytes, 0, plainTextBytes.length, cipherText, 0);
            encryptLength += cipher.doFinal(cipherText, encryptLength);

            return bytesToHex(cipherText);
    }
 //DECRYPTION METHOD Using AES with shared key and nonce value 
    public static String decryptString(SecretKey decryptionKey, String cipherText,byte[] iv)throws Exception 
    {
    		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    		//Key decryptionKey = new SecretKeySpec(key.getEncoded(),key.getAlgorithm());
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            byte[] cipherTextBytes = hexToBytes(cipherText);
            byte[] plainText;

            cipher.init(Cipher.DECRYPT_MODE, decryptionKey, gcmParameterSpec);
            cipher.updateAAD(aad);
            plainText = new byte[cipher.getOutputSize(cipherTextBytes.length)];
            int decryptLength = cipher.update(cipherTextBytes, 0, cipherTextBytes.length, plainText, 0);
            decryptLength += cipher.doFinal(plainText, decryptLength);

            return new String(plainText, "UTF-8");
    }
//Conversions// Byte array to String
    public static String bytesToHex(byte[] data, int length) 
    {

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
    public static String bytesToHex(byte[] data)
    {
        return bytesToHex(data, data.length);
    }
  // String to Byte Array
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

// SERVER CLASS FOR SOCKET PROGRMAMMING
public class Server
{	 
	 public static final int AES_KEY_SIZE = 32;
	 public static final int GCM_IV_LENGTH = 12;// 4 for counter
    static byte[] iv; // 12 bytes nonce value
    static int i=0;   
  	public static void main(String[] args) throws Exception
  	{   
  	 	try
  		{// creating ServerSocket
	      	ServerSocket sersock = new ServerSocket(3000);
	      	Socket sock = sersock.accept( );                          
	      	// To read input from keyboard (keyRead object)
	      	BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
	      	//To send data to client using (pwrite object)- characters
	      	OutputStream ostream = sock.getOutputStream(); 
	      	PrintWriter pwrite = new PrintWriter(ostream, true);
	      	// To receive data from server using (receiveRead  object)
	      	InputStream istream = sock.getInputStream();
	      	BufferedReader receiveRead = new BufferedReader(new InputStreamReader(istream));
	      
	      	String pwd = receiveRead.readLine().trim();
	      	if(pwd.equals("1234"))
	      	{	 
	      		pwrite.println("Success");
	      		pwrite.flush();
	      
	      		ECC ecc = new ECC();   // object for ECC class  
	      		KeyPair servKey = ECC.generateECKeys("secp256k1");  // Using Secp256k1 curve params
			    PrivateKey servPrivKey = servKey.getPrivate();
			    PublicKey servPubKey = servKey.getPublic();
			    //Displaying Keys
			    byte[] spublicKeyBytes = servPubKey.getEncoded();
			    String spubkey= ECC.bytesToHex(spublicKeyBytes);
			    System.out.println("_________________________________________________________________________");
			    System.out.println("\n Server PrivateKey Generated  \n\n"+ECC.bytesToHex(servPrivKey.getEncoded()));
			    System.out.println("_________________________________________________________________________");
			    System.out.println("\n Server PublicKey Generated  \n\n"+servPubKey);
			    System.out.println("_________________________________________________________________________");
	      		System.out.println("\n Server PublicKey String Form to send through OutStream : \n"+ spubkey);
	      		System.out.println("_________________________________________________________________________");

	//Sending Server Public Key to Client
	            pwrite.println(spubkey);
	            pwrite.flush(); // does nothing just to flush output stream

	//Getting Client Public Key in string form ..
	            String cpubKeyStr= receiveRead.readLine(); 
	            System.out.println("\n recieved Client pubKey in  String form \n\n"+cpubKeyStr);
	            System.out.println("_________________________________________________________________________");

	            byte[] cpkBytes = ECC.hexToBytes(cpubKeyStr);
	            //Convert the public key bytes into a PublicKey object
	            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(cpkBytes);
	            KeyFactory keyFactory = KeyFactory.getInstance("EC");
	            PublicKey clientPubKey = keyFactory.generatePublic(x509KeySpec);
	            System.out.println("\nClientPubKey \n\n"+clientPubKey);
	            System.out.println("_________________________________________________________________________");
            
	//Key Agreement Using ECDH of Server Private KEy and Client Public KEy
	            KeyAgreement servEcdh = KeyAgreement.getInstance("ECDH");
	            servEcdh.init(servPrivKey);
	            servEcdh.doPhase(clientPubKey,true);

	            byte[] sbytes =  servEcdh.generateSecret();            
	            SecretKey skey = new SecretKeySpec(sbytes, 0, AES_KEY_SIZE, "AES");  //secret Key
	            byte[] sh =skey.getEncoded();
	            String shared= ECC.bytesToHex(sh);
	            System.out.println("\nGenerated SecretKey \t"+shared);
	            System.out.println("_____________________________________________________________________________");

 				System.out.println("\nServer is ready for Secured Communication \n");
            
 // For Communication       
      			String receiveMessage, sendMessage; 
                    
		      	while(true)
		      	{
		      		i=i+1;
		      		iv= new SecureRandom().generateSeed(GCM_IV_LENGTH);
		      		pwrite.println(ECC.bytesToHex(iv));				// Generating IV for each Cyclic Communication
		        	pwrite.flush();
		        	System.out.println("\nIV  "+(ECC.bytesToHex(iv))+ "  For Communication Cycle: "+i+"\n_________________________________________________________");
		        	
		        	if((receiveMessage = receiveRead.readLine()) != null)  
		        	{
		           		System.out.println("\nMsg From CLient(Cipher): "+receiveMessage);
		           		String decryptedmsg =ECC.decryptString(skey,receiveMessage,iv);
		           		System.out.println("Original Msg:::   "+decryptedmsg);
		           		System.out.println("\n-------- Type your Reply -------- Ctrl+C To EXIT --------\n");
		        	}         
		        		sendMessage = keyRead.readLine();
		        		String encryptedmsg = ECC.encryptString(skey,sendMessage,iv); 
		        		System.out.println("encryptedmsg: "+encryptedmsg);
		        		System.out.println("\n-------- Msg Sent -------- Wait For Reply from client --------\n");  
		        		pwrite.println(encryptedmsg);             
		        		pwrite.flush();
		        }
		    }
		    else
		    {
		    	sock.close();
		     	System.out.println("Wrong password by client connection closed");
		     	System.exit(0);
		     }
	    }
    	catch(Exception e)
    	{
    		 System.out.println("Socket Connection Error");
    	}
    }                    
}                        