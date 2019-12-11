import java.io.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.Scanner;

import org.json.simple.*;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;


import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Main {

    private static Account acc = new Account();
    private static SecretKeySpec secretKey;
    private static byte[] key;

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("1: Create Account\n2: Login\n3: Delete All\n>>> ");
        String input  = scanner.nextLine();
        if(input.equals("1")){
                System.out.print("Username: ");
                String user = scanner.next();

                System.out.print("Password: ");
                String textPassword = scanner.next();

                System.out.print("Password (again): ");
                String passwordCheck = scanner.next();
                if(textPassword.equals(passwordCheck)){
                    createUser(user, textPassword);
                }
                else{

                }
            }
        else if(input.equals("2")){
            System.out.print("Username: ");
            String user = scanner.next();

            System.out.print("Password: ");
            String textPassword = scanner.next();

            login(user, textPassword);

        }
        else if(input.equals(3)){

        }

    }

    private static void createKey(){
        JSONObject keySave = new JSONObject();

        keySave.put("key",key);

        StringWriter out = new StringWriter();
        try {
            keySave.writeJSONString(out);
        } catch (IOException e) {
            e.printStackTrace();
        }

        String jsonText = out.toString();
        try (FileWriter file = new FileWriter("key.json")) {
            file.write(jsonText);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void login(String username, String password){
        JSONParser parser = new JSONParser();
        String user;
        String pass;

        try (Reader reader = new FileReader("users.json")) {
                setKey(password);
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                String userInput = Base64.getEncoder().encodeToString(cipher.doFinal(username.getBytes()));
                String passInput = Base64.getEncoder().encodeToString(cipher.doFinal(password.getBytes()));
            JSONObject[] jsonObject = (JSONObject[]) parser.parse(reader);
            System.out.println(jsonObject);
                for(int i = 0; i < jsonObject.length; i++){
                    user = (String) jsonObject[i].get("username");
                    pass = (String) jsonObject[i].get("password");

                    // loop array
                    JSONArray msg = (JSONArray) jsonObject[i].get("messages");
                    Iterator<String> iterator = msg.iterator();
                    while (iterator.hasNext()) {
                        System.out.println(iterator.next());
                    }
                if(userInput.equals(user) && passInput.equals(pass)) {
                    System.out.println("YOU DID IT! You logged in!");
                }
                }


        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (Exception e){
            System.out.print(e);
        }
    }
    // Creates user
    public static void createUser(String username, String password){
        try
        {
            setKey(password);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            acc.username = Base64.getEncoder().encodeToString(cipher.doFinal(username.getBytes()));
            acc.password = Base64.getEncoder().encodeToString(cipher.doFinal(password.getBytes()));
            JSONObject user = new JSONObject();

            user.put("username",acc.username);
            user.put("password",acc.password);

            StringWriter out = new StringWriter();
            try {
                user.writeJSONString(out);
                System.out.println("You have successfully created a new user!");
            }
            catch (IOException e) {
                e.printStackTrace();
            }

            String jsonText = out.toString();
            try (FileWriter file = new FileWriter("users.json")) {
                file.write(jsonText);
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
    }
    // Creates a credential entry
    public static void createCredential(){

    }
    public static void setKey(String myKey)
    {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String strToEncrypt)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt(String strToDecrypt, String secret)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e)
        {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
}


//    SecureRandom random = new SecureRandom();
//    byte[] salt = new byte[16];
//            random.nextBytes(salt);
//
//                    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256); // AES-256
//                    SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
//                    byte[] key = f.generateSecret(spec).getEncoded();
//                    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
//
//                    byte[] ivBytes = new byte[16];
//                    random.nextBytes(ivBytes);
//                    IvParameterSpec iv = new IvParameterSpec(ivBytes);
//
//                    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
//                    c.init(Cipher.ENCRYPT_MODE, keySpec, iv);
//                    byte[] encValue = c.doFinal(password.getBytes());
//
//                    byte[] finalCiphertext = new byte[encValue.length+2*16];
//                    System.arraycopy(ivBytes, 0, finalCiphertext, 0, 16);
//                    System.arraycopy(salt, 0, finalCiphertext, 16, 16);
//                    System.arraycopy(encValue, 0, finalCiphertext, 32, encValue.length);
//
//                    return finalCiphertext.toString();