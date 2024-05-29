import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;
import java.io.PrintStream;

public class Main {

    
    public static void main(String[] args) {
        App app = new App();
        String fileArg = "";
        if(args.length > 0) {
            fileArg = args[0]; 
        }
        Scanner input = new Scanner(System.in);
        boolean exit = false;
        
        while(!exit) {
            System.out.println("""
                Select an Service Type:
                    1. Symmetric 
                    2. Asymmetric (ECC)
                    3. Exit App
                """);
            int select = input.nextInt();
            input.nextLine(); //Without this line, scanner will skip getUserText() inputs.
            switch(select) {
                case 1: 
                    System.out.println("Entering Symmetric Service...\n");
                    runSymmetric(input, fileArg, app);
                case 2:
                    System.out.println("Entering Asymmetric Service...\n");
                    runAsymmetric(input, fileArg, app);
                    break;
                case 3: 
                    exit = true;
                    System.out.println("Exiting App...");
                    break;
                default:
                    System.out.println("Invalid Choice, please enter 1, 2, 3");
            }
        }
        input.close();
    }

    public static void runAsymmetric(Scanner input,  String fileArg, App app) {
        String m;
        String pw;
        String path;
        boolean exit = false;
        EccGram cache;
        Ed448pt key = null;
        
        while(!exit) {
            pw = "";
            System.out.println("""
                Select an App Service:
                    1. Generate an elliptic key pair
                    2. Encrypt a data file using a public key
                    3. Decrypt a elliptic-encrypted file with a password
                    4. Sign a given file from a given password
                    5. Verify a given data file and its signature under public key
                    6. Return to Service Selection.
                """);
            int select = input.nextInt();
            input.nextLine(); //Without this line, scanner will skip getUserText() inputs.
            switch(select) {
                case 1: 
                    pw = getUserText(input, "Please enter a passphrase:");
                    key = app.generateKeyPair(pw);
                    path = getUserText(input, "Please enter the file path to write the public key to: ");
                    writeToFile(key.toString(), path);
                    path = getUserText(input, "Please enter the file path to write the encrypted private key to: ");
                    writeToFile(app.getEncryptedPrivateKey().toString(), path);
                    System.out.println("\nSuccessfully produced a key pair under your passphrase!\n");
                    break;
                case 2:
                    m = getText(input, fileArg, "encryptInput.txt");
                    path = getUserText(input, "Please enter the file path to the public key: ");

                    //app.encrypt(m, publicKey);
            
                    break;
                case 3:
                    pw = getUserText(input, "Please enter the passphrase:");
                    //System.out.println(app.decrypt(pw));
                    break;
                case 4:
                    m = getText(input, fileArg, "encryptInput.txt");
                    pw = getUserText(input, "Please enter a passphrase:");
                    app.generateSignature(m, pw);
                    break;
                case 5:
                    m = getText(input, fileArg, "encryptInput.txt");
                    pw = getUserText(input, "Please enter a passphrase:");
                    //app.verifySignature(m);
                    break;
                case 6: 
                    exit = true;
                    System.out.println("Clearing Cache...");
                    System.out.println("Exiting Asymmetric Service...");
                    break;
                default:
                    System.out.println("Invalid Choice, please enter 1, 2, 3, 4, 5, or 6.");
            }
        }      
    }

    public static void runSymmetric(Scanner input, String fileArg, App app) {
        String m;
        String pw;
        boolean exit = false;
        byte[][] cachedCryptgram = null;
        
        while(!exit) {
            pw = "";
            System.out.println("""
                Select an App Service:
                    1. Compute a cryptographic hash
                    2. Compute an authentication tag (MAC)
                    3. Encrypt a given data file
                    4. Decrypt a cached symmetric cryptogram
                    5. Return to Service Selection.
                """);
            int select = input.nextInt();
            input.nextLine(); //Without this line, scanner will skip getUserText() inputs.
            switch(select) {
                case 1: 
                    m = getText(input, fileArg, "hashInput.txt");
                    byte[] temp = app.computeHash(m);
                    System.out.println("\nHash: ");
                    for(int i = 0; i < temp.length; i++) {
                        System.out.print(Integer.toHexString(temp[i] & 0xFF));
                        System.out.print(" ");
                    }
                    System.out.println("\n");
                    break;
                case 2:
                    m = getText(input, fileArg, "tagInput.txt");
                    pw = getUserText(input, "Please enter a passphrase:");
                    temp = app.computeAuthTag(m, pw);
                    System.out.println("\nTag: ");
                    for(int i = 0; i < temp.length; i++) {
                        System.out.print(Integer.toHexString(temp[i] & 0xFF));
                        System.out.print(" ");
                    }
                    System.out.println("\n");
                    break;
                case 3:
                    m = getText(input, fileArg, "encryptInput.txt");
                    pw = getUserText(input, "\nPlease enter a passphrase");
                    cachedCryptgram = app.encrypt(m, pw);
                    System.out.println("\nCryptogram is cached for remaining of runtime.\n");
                    break;
                case 4:
                    if(cachedCryptgram != null) {
                        pw = getUserText(input, "Please enter the passphrase: ");
                        System.out.println("\nDecrypted: " + app.decrypt(cachedCryptgram, pw) + "\n");
                    } else {
                        System.out.println("\nPlease cache a cryptogram first using Service 3.\n");
                    }
                    break;
                case 5: 
                    exit = true;
                    System.out.println("Clearing Cache...");
                    System.out.println("Exiting Symmetric Service...");
                    break;
                default:
                    System.out.println("Invalid Choice, please enter 1, 2, 3, 4, or 5.");
            }
        }
    }

    public static String[] parseKeyString(String keyStr) {
        //keyStr is in format of (x, y)
        String[] ret = new String[2]; //x at index 0, y at index 1.

        //( at index 0, ) at last index.

        keyStr = keyStr.substring(keyStr.indexOf('(') + 1, keyStr.indexOf(')'));

        //Find index of ", "
        int commaIndex = keyStr.indexOf(',');
        ret[0] = keyStr.substring(0, commaIndex);
        ret[1] = keyStr.substring(commaIndex + 2, keyStr.length());
        return ret;
    }
/* 
    public static String[] readFile(String path) {
        try {
            Scanner fileScan = new Scanner(new File(path));   
            String line;
            while(fileScan.hasNext()) {
                line = fileScan.nextLine();
                if(line.indexOf('(') != -1) {//Is it a point?

                }
            }

        } catch (Exception e) {
            System.out.println("Cryptogram File not found!");
        }
    }
*/
    public static void writeToFile(String contents, String path) {
        try {
            PrintStream p = new PrintStream(new File(path));
            p.println(contents);
            p.close();
        } catch (FileNotFoundException f) {
            System.out.println("Bad path entered, no file can be created.");
        }
    }

    /**
     * Prompts user in command line for message source and retrieves text from source.
     * 
     * @param input is the scanner linking to the command line interface.
     * @param argFileName is the file name arguement entered by CLI user on launch of app.
     * @param fileName is an hardcoded file name string for accessing pre-existing text files.
     * @return text from message source.
     */
    public static String getText(Scanner input, String argFileName, String fileName) {
        String ret;
        System.out.println("""
            Select an Text Source:
                1. File Path From command line arguments (Ensure that format is: "java Main /path/to/file").
                2. Pre-selected File Input
                3. User Input
            """);
        int select = input.nextInt();
        input.nextLine(); //Without this line, scanner will skip getUserText() inputs.

        switch(select) {
            case 1:
                ret = getFileText(argFileName);
                while(ret.equals("")) {
                    String path = getUserText(input, "Please enter the absolute path to the file:");
                    ret = getFileText(path);
                }
                break;
            case 2:
                ret = getFileText(fileName);
                while(ret.equals("")) {
                    String path = getUserText(input, "Please enter the absolute path to the file:");
                    ret = getFileText(path);
                }
                break;
            case 3:
                ret = getUserText(input, "Please enter your message below: ");
                break;
            default:
                System.out.println("Invalid Choice, please enter 1 or 2");
                ret = getText(input, argFileName, fileName); 
        }
        return ret;
    }

    /**
     * Retrieves text from a txt file.
     * 
     * @param fileName is the txt file name.
     * @return text from the txt file.
     */
    private static String getFileText(String fileName) {
        StringBuilder sb = new StringBuilder();
        try{
            Scanner fileScan = new Scanner(new File(fileName));
            while(fileScan.hasNext()) {
                sb.append(fileScan.nextLine());
            }
            fileScan.close();
        } catch (FileNotFoundException err) {
            System.out.println(fileName + " was not found!\n");
        }
        return sb.toString();
    }

    /**
     * Retrieves from text input from CLI user.
     * 
     * @param input is scanner link to the CLI.
     * @param promptText is the prompt displayed to the CLI user on what to enter.
     * @return text input from CLI user.
     */
    public static String getUserText(Scanner input, String promptText) {
        System.out.println(promptText);
        String ret = input.nextLine(); 
        return ret;
    }
}

