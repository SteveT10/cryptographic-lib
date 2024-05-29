import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class Main {

    
    public static void main(String[] args) {
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
                    runSymmetricApp(input, fileArg);
                case 2:
                    System.out.println("Entering Asymmetric Service...\n");
                    runAsymmetricApp(input, fileArg);
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

    public static void runAsymmetricApp(Scanner input,  String fileArg) {
        String m;
        String pw;
        boolean exit = false;
        Edwards448 eds = new Edwards448();
        
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
                    eds.generateKeyPair(pw);
                    break;
                case 2:
                    m = getText(input, fileArg, "encryptInput.txt");
                    eds.encrypt(m);
                    break;
                case 3:
                    pw = getUserText(input, "Please enter the passphrase:");
                    System.out.println(eds.decrypt(pw));
                    break;
                case 4:
                    m = getText(input, fileArg, "encryptInput.txt");
                    pw = getUserText(input, "Please enter a passphrase:");
                    eds.generateSignature(m, pw);
                    break;
                case 5:
                    m = getText(input, fileArg, "encryptInput.txt");
                    pw = getUserText(input, "Please enter a passphrase:");
                    eds.verifySignature(m);
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

    public static void runSymmetricApp(Scanner input, String fileArg) {
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
                    byte[] temp = Kmacxof256.computeHash(m);
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
                    temp = Kmacxof256.computeAuthTag(m, pw);
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
                    cachedCryptgram = Kmacxof256.encrypt(m, pw);
                    System.out.println("\nCryptogram is cached for remaining of runtime.\n");
                    break;
                case 4:
                    if(cachedCryptgram != null) {
                        pw = getUserText(input, "Please enter the passphrase: ");
                        System.out.println("\nDecrypted: " + Kmacxof256.decrypt(cachedCryptgram, pw) + "\n");
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
            Select an Message Source:
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

