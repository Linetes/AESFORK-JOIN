import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.RecursiveAction;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encrypt extends RecursiveAction {
	
	private static final long serialVersionUID = 1L;
	private static final long MIN = 128;
	private byte[] in;
	private byte[] out;
	private int start = 0, end;
	private static final String ALGORITHM = "AES/CTR/NOPADDING";
	private SecretKeySpec secretKey;
	private IvParameterSpec ivspec;
	
	Encrypt(SecretKeySpec secretKey, IvParameterSpec ivspec, byte[] in, byte[] out, int start, int end) {
		this.secretKey = secretKey;
		this.ivspec = ivspec;
		this.in = in;
		this.out = out;
		this.start = start;
		this.end = end;
		
	}
	
	private void encryption() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		//Initializing cipher
		Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);

        //Aux byte array gets the ciphering by block
	    byte[] obuf = cipher.update(in, start, end-start);
	    
	  //Fills the out array with the bytes in the aux array
	    for(int i = start; i < end; i++) {
	    	out[i] = obuf[i-start];
    	}
	}
	
	protected void compute() {
		// TODO Auto-generated method stub
		
		//Base Case, if block is less than 128
		if ((this.end - this.start <= Encrypt.MIN)) {
			try {
				encryption();
			} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
					| InvalidAlgorithmParameterException | ShortBufferException | IllegalBlockSizeException | BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        } else {
        	//If block is bigger it divides it into two more objects
            int mid = (end + start) / 2;
            invokeAll(new Encrypt(secretKey, ivspec, in, out, start, mid), new Encrypt(secretKey, ivspec, in, out, mid+1, end));
        }
		
	}
}
