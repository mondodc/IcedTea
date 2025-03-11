package mondodc.crypto;


public class Test 
{
	public static void main(String[] args) 
	{
		System.out.printf("main.Test \n");
        System.out.printf("Tea Encryption Test Start \n");
        
        int [] key128 = {2,1,7,4,8,3,9,5,4,5,1,6,3,5,6,7};
        
        IcedTea tea = new IcedTea(key128);
        
        long origclear = 12345678;
    
        long cipher = tea.encrypt(origclear);    
        long newclear = tea.decrypt(cipher);
        
        if (newclear != origclear)
        	System.out.printf("Encrypt & Decrypt Failed \n"); 
        else
        	System.out.printf("Encrypt & Decrypt Success \n"); 
        
        
        System.out.printf("Tea Encryption Test End \n");
        
	}

}
