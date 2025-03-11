package mondodc.crypto;

/*
 * Java port of the TEA (Tiny Encryption Algorithm) from C
 * David Wheeler, Roger Needham, Computer Laboratory, 
 * Cambridge University, England, November 1994
 * ref: https://www.cl.cam.ac.uk/ftp/papers/djw-rmn/djw-rmn-tea.html
 * *
 * TEA is a symmetric encryption algorithm & has known weaknesses 
 * but represents the fundamental structure of a symmetric block cipher.
 * Please use AES or other strong cipher to protect sensitive data.
 * 
 * note: to encrypt text would require additional functions added to the class 
 * to convert the text String to a byte array, then to an int array, 
 * then each int encrypted
 */

public class IcedTea 
{
	private final static int ROUNDS = 32;               // Number of rounds
	private final static int SHIFTVAL = 32;
	private final static int DELTA = 0x9e3779b9;        // DELTA Constant
	private final static int DELTA5 = 0xC6EF3720;       // Shift left << 5 of DELTA 
	private final static long MASK = (1L << 32) - 1;    // 32 bit mask
	
	private int [] mkey;
	
	protected IcedTea()
	{
	}
	
	public IcedTea(int [] key) {	
		if (key == null)
			throw new IllegalArgumentException("IcedTea: ERROR Key not set");
		
	    System.out.printf("IcedTea.IcedTea: Key set \n");
	    
		this.mkey=key;
	}

  
    public long encrypt(long clearv) {
    	System.out.printf("IcedTea.encrypt: Clear value in: %d%n", clearv);
    	
    	int v1 = (int) clearv;
        int v0 = (int) (clearv >>> SHIFTVAL);
        int sum = 0;
        for (int i=0; i<ROUNDS; i++) {
        	sum += DELTA;
            v0 += ((v1<<4) + this.mkey[0]) ^ (v1 + sum) ^ ((v1>>>5) + this.mkey[1]);
            v1 += ((v0<<4) + this.mkey[2]) ^ (v0 + sum) ^ ((v0>>>5) + this.mkey[3]);
        }

        long ret = (v0 & MASK) << SHIFTVAL | (v1 & MASK);
      	System.out.printf("IcedTea.encrypt: Cipher value out: %d%n", ret);
      	
        return ret;
    }
    
    public long decrypt(long cipherv) {
    	System.out.printf("IcedTea.decrypt: Cipher value in: %d%n", cipherv);
    	
    	int v1 = (int) cipherv;
        int v0 = (int) (cipherv >>> SHIFTVAL);
        int sum = DELTA5;
        for (int i=0; i<ROUNDS; i++) {
            v1 -= ((v0<<4) + this.mkey[2]) ^ (v0 + sum) ^ ((v0>>>5) + this.mkey[3]);
            v0 -= ((v1<<4) + this.mkey[0]) ^ (v1 + sum) ^ ((v1>>>5) + this.mkey[1]);
            sum -= DELTA;
        }
        
        long ret = (v0 & MASK) << SHIFTVAL | (v1 & MASK);       
    	System.out.printf("IcedTea.decrypt: Clear value out: %d%n", ret);
 
        return ret;
    }

}
