import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("1: Encrypt\n2: Decrypt\n>>> ");
        String input  = scanner.nextLine();
        if(input.equals("1")){
            try {
                System.out.println("Input the text you would like to encrypt.\n>>> ");
                input = scanner.nextLine();
                encrypt(input);
            }
            catch (Exception e){

            }
        }
        else if(input.equals("2")){
            try {
                //decrypt(input);
            }
            catch (Exception e){

            }
        }

    }
    public static void encrypt(String usrinput) throws Exception{
        //Creating a Signature object
        Signature sign = Signature.getInstance("SHA256withRSA");

        //Creating KeyPair generator object
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");

        //Initializing the key pair generator
        keyPairGen.initialize(2048);

        //Generating the pair of keys
        KeyPair pair = keyPairGen.generateKeyPair();

        //Creating a Cipher object
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        //Initializing a Cipher object
        cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());

        //Adding data to the cipher
        byte[] input = usrinput.getBytes();
        cipher.update(input);

        //encrypting the data
        byte[] cipherText = cipher.doFinal();
        System.out.println(new String(cipherText, "UTF8"));

        cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
        byte[] plainText = cipher.doFinal();
        System.out.println(plainText);
    }
//    public static String decrypt(String usrinput, ){
//
//    }
}
