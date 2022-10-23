/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package RSASHA1_Server;

import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*; 
import java.net.*;
import java.util.Arrays;
/**
 *
 * @author gdocq
 */

class Keyz 
{
    PublicKey pk;
    PrivateKey pr;
        
    void generateRSAKey() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");//creating a pseudo random number generator
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");//creating a key pair generator instance
        kpg.initialize(1024,random);//initializing the key pair generator with key size and a pseudo random number generator
        KeyPair kp = kpg.genKeyPair(); ////generates a key pair
        pk = kp.getPublic(); //get the public key
        pr = kp.getPrivate(); //get the private key
    }
}

public class Server 
{
    
     public static byte[] rsaEncrypt(byte[] original, PublicKey key) throws Exception
    {
	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	cipher.init(Cipher.ENCRYPT_MODE, key); 
	return cipher.doFinal(original);
    }
    public static byte[] rsaDecrypt(byte[] encrypted, PrivateKey key) throws Exception
    {
	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	cipher.init(Cipher.DECRYPT_MODE, key);
	return cipher.doFinal(encrypted);
    }
    
    public static byte[] getSHA1(byte[] original) 
    {
        byte[] h = null;
        try 
        {
        System.out.println("Instanciation du digest");
        MessageDigest d = MessageDigest.getInstance("SHA-1");
        System.out.println("Hachage du message");
        d.update(original);
        System.out.println("Generation des bytes");
        h = d.digest();
        System.out.println("Termine : digest construit");
        System.out.println("digest = " + new String(h));
        System.out.println("Longueur du digest = " + h.length);
        }
        catch(Exception ex)
        {
            System.exit(1);
        }
        return h;
    }
    
    public static String verif_SHA1(byte[] hrecu, byte[] message) 
    {
        try
        {
            System.out.println("Debut de verification");
            // confection d'un digest local
            byte[] hlocalb = getSHA1(message);
            System.out.println("digest reçu = " + new String(hrecu));
            System.out.println("digest local = " + new String(hlocalb));
            String réponse = null;
            if (MessageDigest.isEqual(hrecu, hlocalb) )
            {
                réponse = new String("OK - intégrité vérifiée");
                System.out.println("Le messsage n'a pas été modifé");
                return réponse;
            }
            else
            {
                réponse = new String("KO - intégrité NON vérifiée");
                System.out.println("Le messsage a été modifié");
                return réponse;
            }
        } 
        catch (Exception e)
        {
            System.out.print("Erreur -> return false");
            String réponse = new String("Erreur -> return false");
            return réponse;
        }
    }
    
    public static void main(String[] args) 
    {
        PublicKey ClientPublicKey = null;
        DataOutputStream dos = null;
        Socket SerSocketCli = null;
        ServerSocket SerSocket = null;
        Keyz CleeServer = new Keyz();
        try 
        {
            CleeServer.generateRSAKey();
        } catch (Exception ex) 
        {
            ex.printStackTrace();
        }
        
        try
        {
        SerSocket = new ServerSocket(50000);
        } 
        catch (IOException e)
        { 
            System.err.println("Erreur de port d'écoute ! ? [" + e + "]"); System.exit(1);
        }
        System.out.println("Serveur en attente");
        try
        {
            SerSocketCli = SerSocket.accept();

            System.out.println("Connexion réussie");
            System.out.println("Clé publique: \n"+CleeServer.pk);
            System.out.println("Clé privé: \n"+CleeServer.pr);
            
            InputStream IS = SerSocketCli.getInputStream();
            OutputStream OS = SerSocketCli.getOutputStream();
            ObjectOutputStream OBOS = new ObjectOutputStream(OS);
            ObjectInputStream OBIS = new ObjectInputStream(IS);
            System.out.println("Envoie clé publique au client ...");
            OBOS.writeObject(CleeServer.pk);
            
            ClientPublicKey = (PublicKey)OBIS.readObject();
            System.out.println("Clé publique du client recu:\n" + ClientPublicKey);
            
            //test encrypt
            DataInputStream dis = null;
            //ByteArrayOutputStream baos = new ByteArrayOutputStream();

            byte[] texteCrypté = null;
            try
            {
                dis = new DataInputStream( new BufferedInputStream(SerSocketCli.getInputStream()));
                dos = new DataOutputStream(new BufferedOutputStream(SerSocketCli.getOutputStream()));
                if (dis==null || dos==null) System.exit(1);
                //msg crypt
                int BF_Length = dis.readInt();
                System.out.println("taille du message: " + BF_Length);
                byte[] buffer = new byte[BF_Length];
                dis.readFully(buffer);
                texteCrypté = buffer;
                System.out.println("buffer:\n ");
                System.out.println(Arrays.toString(buffer));
                System.out.println("Msg reçu = " + new String(texteCrypté));
                
                //digest
                int longueur = dis.readInt();
                System.out.println("Longueur du digest = " + longueur);
                byte[] hrecu = new byte[longueur];
                dis.readFully(hrecu); 
                System.out.println("digest recu:\n ");
                System.out.println(Arrays.toString(hrecu));

                
                byte[] texteDecrypté = rsaDecrypt(texteCrypté, CleeServer.pr);
                System.out.println("ByteDec:\n ");
                System.out.println(Arrays.toString(texteDecrypté));
                String txtDec = new String(texteDecrypté);
                System.out.println("Msg decrypt = " + txtDec);
                byte[] msgClair = txtDec.toString().getBytes();
                
                
                
                String verif = verif_SHA1(hrecu, msgClair);
                dos.writeUTF(verif); 
                dos.flush(); 
                System.out.println("Résultat envoyé au client"); 
            } 
            catch (EOFException ex)
            {
                System.err.println("Erreur ? [" + ex + "]");
            }
            finally
            {
            try
            {
                dis.close(); dos.close(); OBOS.close(); OBIS.close();OS.close();IS.close();
                SerSocketCli.close(); 
                SerSocket.close();
                System.out.println("Serveur deconnecte");
            }
            catch (IOException e)
            { System.err.println("Erreur ! ? [" + e + "]"); }
            } 
            
        }
        catch (IOException e)
        {
            System.err.println("Erreur d'accept ! ? [" + e + "]");
            System.exit(1);
        } 
        catch (Exception e)
        {
            System.err.println("Erreur: [" + e + "]");
            System.exit(1);
        }

    }
}
