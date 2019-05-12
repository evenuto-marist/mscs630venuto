package cipher;

/**
* file: AEScipher.java
* author: Emily Venuto
* course: MSCS 630
* assignment: final project
* due date: May 12, 2019
* version: 1
* 
* This file contains the declaration of the 
* AEScipher class, and implements methods required
* to perform AES 128-bit encryption.
*/


/**
* AEScipher
* 
* This class performs AES encryption on an input
* hex string
*/
public class AEScipher extends CipherBasics {

  /**
  * AES
  *
  * This function takes in a plain text string and the system key,
  * and returns  the ciphertext string.
  *  
  * Parameters:
  *   pTextHex
  *   keyHex
  * 
  * Return value:
  *   cipherText.toString()
  *   
  */  
  public String AES(String plainText, String keyHex) {
    String cTextHex = null;
    //get round keys
    String [] k = aesRoundKeys(keyHex);
    String [][] roundKey = new String[4][4];
    
    String paddedPlainText = addPadding(plainText);
    String pTextHex = plainToHex(paddedPlainText);
    String [] blocks = toBlock(pTextHex);
    
    StringBuilder cipherText = new StringBuilder();
    
    for(int x=0; x<blocks.length; x++) {
      String [][] hexText = createFourByFour(blocks[x]);
      int round = 1;
      
      //initial round key
      roundKey = createFourByFour(k[0]);
    
      //initial add key
      String[][] out = AESStateXOR(hexText, roundKey);
    
      //temp arrays
      String[][] out2 = new String[4][4];
      String[][] out3 = new String[4][4];
    
      while(round < 11) {
        out2 = AESNibbleSub(out);
        out3 = AESShiftRow(out2);
        if(round ==10)
    	  break;
        String[][] out4 = AESMixColumn(out3);
      
        //set up next round key
        roundKey = createFourByFour(k[round]);
      
        out = AESStateXOR(out4, roundKey);
        round++;
      }
    
      //set up last round key
      roundKey = createFourByFour(k[round]);
    
      String[][] out5 = AESStateXOR(out3,roundKey);  
	
      //create output string
      StringBuilder sb = new StringBuilder();
      for(int i=0; i<4; i++) {
        for(int j=0; j<4; j++) { 
          sb.append(out5[j][i]);
        }
      }
      cTextHex = sb.toString();
      cipherText.append(cTextHex);
    }
    
    return cipherText.toString();
  }
  
  

  /**
   * AESNibbleSub
   *
   * This function receives a 4x4 hex matrix
   * and calls the method aesBox to perform the
   * sbox substitution
   *  
   * Parameters:
   *   inStateHex: input 4x4 two digit hex matrix
   * 
   * Return value:
   *   outStateHex: output 4x4 two digit hex matrix that is
   *     a result of the sbox sub
   *   
   */
  public static String[][] AESNibbleSub(String[][] inStateHex) {
    String [][] outStateHex = new String [4][4];  
    for(int i=0; i<4; i++) {
      for(int j=0; j<4; j++) {
        int sbox_ans = aesBox(inStateHex[i][j]);
        outStateHex[i][j] = String.format("%02X", sbox_ans);
      }
    }
    return outStateHex;	  
  }

  /**
   * AESShiftRow
   *
   * This function receives a 4x4 hex matrix
   * and performs the shift row operation
   * of the AES to transform the input state matrix
   * into the output state
   *  
   * Parameters:
   *   inStateHex: input 4x4 two digit hex matrix
   * 
   * Return value:
   *   outStateHex: output 4x4 two digit hex matrix that is
   *     a result of the left shift
   *   
   */
  public static String[][] AESShiftRow(String[][] inStateHex) {
    String [][] outStateHex = new String [4][4];  
    int i = 0;
    int shift = 0;
    while(i < 4) {	
      for (int j = shift; j < 4; j++) {
        outStateHex[i][j-shift] = inStateHex[i][j];
      }
      for (int j = 0; j < shift; j++) {
        outStateHex[i][j+4-shift] = inStateHex[i][j];
      }
      
      i++;
      shift++;
    }
    
    return outStateHex;	  
  }

  /**
   * AESMixColumn
   *
   * This function receives a 4x4 hex matrix
   * and performs the mix column operation of
   * AES
   *  
   * Parameters:
   *   inStateHex: input 4x4 two digit hex matrix
   * 
   * Return value:
   *   outStateHex: output 4x4 two digit hex matrix that is
   *     a result of the column mix
   *   
   */
  public static String[][] AESMixColumn(String[][] inStateHex) {
    String [][] outStateHex = new String [4][4];
    int [] temp = new int[4];
    byte x1B = (byte)Integer.parseUnsignedInt("1B", 16); //for xor when msb = 1
    for(int col = 0; col < 4; col++) {
      for(int i=0; i<4; i++) {
        for(int j=0; j<4; j++) {
          byte byte1 = (byte)Integer.parseInt(inStateHex[j][col], 16);  //get element from input array
          int galois = galoisFields[i][j];
          int msb = (byte1 & 0xff) >> 7;
          if (galois == 1) {
            temp[j] = byte1;
          } else if (galois == 2) {
            if(msb == 1)
              temp[j] = (byte) ((byte1 << 1) ^ x1B);
            else
              temp[j] = (byte) (byte1 << 1); 
          } else { //if int2 == 3
            if(msb == 1)
              temp[j] = (byte) ((byte1 << 1) ^ x1B ^ byte1);
            else
              temp[j] = (byte) ((byte1 << 1) ^ byte1); 	
          }
        }
        int xor = temp[0]^temp[1]^temp[2]^temp[3];
        outStateHex[i][col] = String.format("%02X", xor & 0xFF);  
      }	
    }
    return outStateHex;	 
  }
  
  /**
   * addPadding
   *
   * This function adds padding to plaintext so that
   * it can be encrypted in 128-bit blocks
   *  
   * Parameters:
   *   plainText
   * 
   * Return value:
   *   paddedText
   */
  public static String addPadding(String plainText) { 
    int mod = plainText.length()%16;
    int len = plainText.length();
    char padding = '~';
    String paddedText = null;
    
    //if string < 16 characters, pad up to 16
    if (len < 16) {
      int temp = 16 - len;
      StringBuilder s = new StringBuilder(plainText);
      for (int i = 0; i < temp; i++) {
        s.append(padding);
      }
      paddedText = s.toString();
    }
    
    //if string length % 16 == 0, add 16 characters of padding
    else if (mod == 0) {
      StringBuilder s = new StringBuilder(plainText);
      for (int i = 0; i < 16; i++) {
        s.append(padding);
      }
      paddedText = s.toString();
    }
    
    //if string > 16 characters and length % 16 != 0, fill in up to mod=0
     else {
      int temp = 16 - mod;
      StringBuilder s = new StringBuilder(plainText);
      for (int i = 0; i < temp; i++) {
        s.append(padding);
      }
      paddedText = s.toString();   
    }
    
    return paddedText;
  }
  
  /**
   * plainToHex
   *
   * This function receives a plaintext
   * string and converts it to a hexadecimal
   * string
   *  
   * Parameters:
   *   plainText
   * 
   * Return value:
   *   hexText
   */
  public static String plainToHex(String plainText) {
      char[] chars = plainText.toCharArray();
      StringBuffer h = new StringBuffer();
      for (int i = 0; i < chars.length; i++)
      {
        if ((int)chars[i] <= 10)
          h.append(String.format("%02X", (int)chars[i]));
        else
          h.append(Integer.toHexString((int) chars[i]));
      }
      
      String hexText = h.toString();
      return hexText;
    }
		
  public static final int[][] galoisFields = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}};
  
  
	
}
