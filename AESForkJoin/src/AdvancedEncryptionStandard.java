import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;
import java.util.concurrent.ForkJoinPool;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AdvancedEncryptionStandard {
    private byte[] key;
    private static final String ALGORITHM = "AES";
	private static Scanner user_input;
	private static int MAXTHREADS = Runtime.getRuntime().availableProcessors();

    public AdvancedEncryptionStandard(byte[] key) {
        this.key = key;
    }
    
    public static void encode() throws NoSuchAlgorithmException, FileNotFoundException, IOException {
    	
    	//Initialization Vector and IvParameterSpec for cipher
    	byte[] iv = new byte[128/8];
		SecureRandom srandom = new SecureRandom();
		srandom.nextBytes(iv);
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		
		//Generating key
    	KeyGenerator kgen = KeyGenerator.getInstance("AES");
	    kgen.init(128);
	    SecretKey aesKey = kgen.generateKey();
	    
	    //File name input and creation
    	System.out.println("Please enter the name of the file with .txt");
	    user_input = new Scanner( System.in );
	    String FileName = user_input.next();
	    File file = new File(FileName);
	    System.out.println("File length " + file.length() + " bytes.");
	    if(!file.exists()) {
	    	System.out.println("File " + file.getName() + " not found.");
	    	System.exit(-1);
	    }
	    
	    //Key file creation
	    String keyName = "Encoded" + FileName + ".key";
	    try (FileOutputStream out = new FileOutputStream(keyName)) {
	        byte[] keyb = aesKey.getEncoded();
	        out.write(keyb);
	        out.close();
	    }
	    
	    //IV file creation
	    String ivFile = "Encoded" + FileName + ".iv";
	    try (FileOutputStream out = new FileOutputStream(ivFile)) {
	        out.write(iv);
	        out.close();
	    }

	    //Read all bytes from the key file
		Path path = Paths.get(keyName);
		byte[] key = Files.readAllBytes(path);
	    
	    
		//Create AES Object
    	AdvancedEncryptionStandard advancedEncryptionStandard = new AdvancedEncryptionStandard(key);
    	
    	//Time Start
    	double time = 0;
    	double start = System.currentTimeMillis();
    	
    	//Encryption
    	advancedEncryptionStandard.encrypt(file, ivspec, FileName);
    	System.out.println("Done Encryption");
    	File encoded = new File("Encoded"+FileName);
	    if(!encoded.exists()) {
	    	System.out.println("File " + encoded.getName() + " not found.");
	    	System.exit(-1);
	    }
    	
	    //Time Stop
    	double stop = System.currentTimeMillis();
        time += (stop - start);
        System.out.print("Finished");
        System.out.println("\nParallel Version");
        System.out.println("Time: " + (time/1000) + "s");
    }
    
    public static void decode() throws NoSuchAlgorithmException, FileNotFoundException, IOException {
	    
	    //File name input and creation
    	System.out.println("Please enter the name of the Encoded file with .txt");
	    user_input = new Scanner( System.in );
	    String FileName = user_input.next();
	    File file = new File(FileName);
	    System.out.println("File length " + file.length() + " bytes.");
	    if(!file.exists()) {
	    	System.out.println("File " + file.getName() + " not found.");
	    	System.exit(-1);
	    }
	    
	    //Initialization Vector and IvParameterSpec for cipher
    	byte[] iv = new byte[128/8];
    	File fileiv = new File(FileName+".iv");
    	iv = Files.readAllBytes(fileiv.toPath());
		IvParameterSpec ivspec = new IvParameterSpec(iv);

	    //Read all bytes from the key file
		Path path = Paths.get(FileName+".key");
		byte[] key = Files.readAllBytes(path);
	    
	    
		//Create AES Object
    	AdvancedEncryptionStandard advancedEncryptionStandard = new AdvancedEncryptionStandard(key);
    	
    	//Time Start
    	double time = 0;
    	double start = System.currentTimeMillis();
    	
	    //Decryption
    	advancedEncryptionStandard.decrypt(file, ivspec, FileName);
    	System.out.println("Done Decryption");
    	File decoded = new File("Decoded"+FileName);
	    if(!file.exists()) {
	    	System.out.println("File " + decoded.getName() + " not found.");
	    	System.exit(-1);
	    }
    	
	    //Time Stop
    	double stop = System.currentTimeMillis();
        time += (stop - start);
        System.out.print("Finished");
        System.out.println("\nParallel Version");
        System.out.println("Time: " + (time/1000) + "s");
    	
    }

    public void encrypt(File file, IvParameterSpec ivspec, String FileName) throws IOException {
    	//Fork-Join
    	ForkJoinPool pool;
		pool = new ForkJoinPool(MAXTHREADS);
		
		//Secret key with AES
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
   
        //Read all bytes from file to an array of bytes
        byte[] fileContent = Files.readAllBytes(file.toPath());
        byte[] fileExit = new byte[fileContent.length];
        
        //Invoke pool Encryption
        pool.invoke(new Encrypt(secretKey, ivspec, fileContent, fileExit, 0, fileContent.length));
        
        //Write File
        Path path = Paths.get("Encoded"+FileName);
        Files.write(path, fileExit);
    }
    
    public void decrypt(File file, IvParameterSpec ivspec, String FileName) throws IOException {
    	//Fork-Join
    	ForkJoinPool pool;
		pool = new ForkJoinPool(MAXTHREADS);
		
		//Secret key with AES
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        
        //Read all bytes from file to an array of bytes
        byte[] fileContent = Files.readAllBytes(file.toPath());
        byte[] fileExit = new byte[fileContent.length];
        
        //Invoke pool Encryption
        pool.invoke(new Decrypt(secretKey, ivspec, fileContent, fileExit, 0, fileContent.length));
        
        //Write File
        Path path = Paths.get("Decoded"+FileName);
        Files.write(path, fileExit);
    }
    
    public static void main( String[] args ) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
	    
	    System.out.println("Welcome to the File encryption and decryption with AES and Fork-Join");
	    int input = 0;
		Scanner scan = new Scanner(System.in);
		
		do {
			System.out.println("Menu");
			System.out.println("1 Encode");
			System.out.println("2 Decode");
			System.out.println("3 Exit Program");
			input = scan.nextInt();
			
			switch (input) {
				case 1:
					System.out.println("Encode");
					encode();
					break;

				case 2:
					System.out.println("Decode");
					decode();
					break;
					
				case 3:
					System.out.println("Quitting.");
					return;

				default:
					System.out.println("Not an option, quitting.");
					return;
			}
		} while (input < 3);
		scan.close();
    }
}