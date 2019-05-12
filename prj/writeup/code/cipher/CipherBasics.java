package cipher;

/**
* file: CipherBasics.java
* author: Emily Venuto
* course: MSCS 630
* assignment: final project
* due date: May 12, 2019
* version: 1
* 
* This file contains the declaration of the 
* CipherBasics class, which includes methods/tables
* that will be implemented by both the AES
* encryption and decryption classes.
*/


/**
* CipherBasics
* 
* This class defines basic methods/tables
* that will be implemented by both the AES
* encryption and decryption operations.
*/
public class CipherBasics {

   /**
  * aesRoundKeys
  *
  * This function receives a hex String, and
  * produces 11 round keys. Each round key is
  * placed in one element of the return string array.
  *  
  * Parameters:
  *   KeyHex: input hex string of length 16
  * 
  * Return value:
  *   roundKeysHex: 11 row string array representation of all the round keys,
  *     where each element of roundKeysHex will contain a length 16 hex string
  *     corresponding to each round key
  */
  public static String [] aesRoundKeys(String KeyHex) {
    String [][] k = new String [4][4];
    String [][] w = new String[4][44];
    String[] roundKeysHex = new String[11];  //output array
	
    //put inString into hexDigits array (two hex digits in each array entry)
    k = createFourByFour(KeyHex);
    
    
    //step 2, create rows 0 - 3 of w
    for(int i = 0; i < 4; i++) {
      for(int j = 0; j < 4; j++) {
        w[i][j]=k[i][j];
      }
    }
	  
    int round = 1; //keep track of what round we're in
    //step 3, create rows 4 - 43 of w
    for(int i = 4; i < 45; i++) {
      //3a -- if column isn't a multiple of 4 -- don't start new round
      if(i%4 != 0) {
        for(int j = 0; j < 4; j++) {
          String hex1 = w[j][i-4];
          String hex2 = w[j][i-1];
          int int1 = Integer.parseInt(hex1, 16);
          int int2 = Integer.parseInt(hex2, 16);
          int res = int1 ^ int2;
          w[j][i] = String.format("%02X", res);
        }
      }
	    
      //3b -- if column is a multiple of 4 -- starting a new round
      else { 
        //add to output array
        String stringBuild = "";
        int iterate = 4;
        for(int i1 = 0; i1 < 4; i1++) { 
          for(int j1 = 0; j1 < 4; j1++) {
            stringBuild = stringBuild + w[j1][i-iterate]; 
          }
          iterate = iterate-1;
        }
        roundKeysHex[round-1] = stringBuild;
	      
        if(i==44)  //break out of loop if no more rounds
          continue;
	     
        round++;  //starting new round 

        //create temp vector
        String wnew[] = new String[4];
        for(int j = 0; j < 4; j++) {
          wnew[j] = w[j][i-1];
        }
	      
        //shift to left
        String temp = wnew[0];
        for(int x = 0; x < 3; x++) {
          wnew[x]=wnew[x+1];
        }
        wnew[3] = temp;
	      
        //sbox function
        for(int x = 0; x < 4; x++) {
          int sbox_ans = aesBox(wnew[x]);
          wnew[x] = String.format("%02X", sbox_ans);
        }
	      
        //rcon
        int int1 = Integer.parseInt(wnew[0], 16);
        int res = int1 ^ aesRcon(round);
        wnew[0] = String.format("%02X", res);
	      
        //last xor
        for(int j = 0; j < 4; j++) {
          String hex1 = w[j][i-4];
          int int3 = Integer.parseInt(hex1, 16);
          int int4 = Integer.parseInt(wnew[j], 16);
          int res1 = int3 ^ int4;
          w[j][i] = String.format("%02X", res1);
        }
      }    
	  
      //go to next column of w
    } 
    return roundKeysHex;
  }
  
    /**
   * aesBox
   *
   * This function receives a two-digit hex String
   * and uses it to read the S-box.
   *  
   * Parameters:
   *   inHex: input hex string of length 2
   * 
   * Return value:
   *   outHex: S-box result
   */
  public static int aesBox(String inHex) {
    String s1 = inHex.substring(0,1);
    String s2 = inHex.substring(1);
    int sbox1 = Integer.parseInt(s1, 16);
    int sbox2 = Integer.parseInt(s2, 16);
    int outHex = sbox[sbox1][sbox2];
    return outHex; 
  }

    
  /**
   * aesRcon
   *
   * This function receives the integer value of
   * what round key that will next be processed and
   * uses it to find the corresponding round constant
   * from the rcon table.
   *  
   * Parameters:
   *   round: round to next be processed
   * 
   * Return value:
   *   outHex: round constant
   */
  public static int aesRcon(int round) { 
    int outHex = rcon[round-1];
    return outHex; 
  }
  
    
  /**
   * AESStateXOR
   *
   * This function receives two 4x4 hex matrices
   * and performs the "add round key operation", thereby
   * returning the XOR of the two matrices
   *  
   * Parameters:
   *   sHex: 4x4 two digit hex matrix
   *   keyHex: 4x4 two digit hex matrix
   * 
   * Return value:
   *   outStateHex: XOR result of the input matrices
   *   
   */
  public static String[][] AESStateXOR(String[][] sHex, String[][] keyHex) {
    String [][] outStateHex = new String [4][4];
    for(int i=0; i<4; i++) {
      for(int j=0; j<4; j++) {
        int int1 = Integer.parseInt(sHex[i][j], 16);
        int int2 = Integer.parseInt(keyHex[i][j], 16);
        int res = int1 ^ int2;
        outStateHex[i][j] = String.format("%02X", res);   
      }
    }
    return outStateHex;	  
  }
  
    /**
   * createFourByFour
   *
   * This function receives an input hex string
   * and breaks it into subsets such that every
   * two hex digits will be put into a single array
   * entry
   * 
   * Parameters:
   *   inString
   * 
   * Return value:
   *   outString
   */
  public static String[][] createFourByFour(String inString) {
    String[][] outString = new String[4][4];
    int beginIndex = 0;
    int endIndex = 2;
    //two hex digits in each array entry
    for(int i = 0; i < 4; i++) { 
      for(int j = 0; j < 4; j++) {
        outString[j][i] = inString.substring(beginIndex, endIndex);
        beginIndex = beginIndex + 2;
        endIndex = endIndex + 2;
      } 
    }
    
    return outString;
  }
  
    /**
   * toBlock
   *
   * This function receives the full hexadecimal
   * string and breaks it into 128-bit blocks. It 
   * returns an array of 128-bit hex strings.
   * 
   * Parameters:
   *   fullString
   * 
   * Return value:
   *   outStrings array
   */
  public static String[] toBlock(String fullString) {
    int div = fullString.length()/32;
    String [] outStrings = new String[div];
    int beginIndex = 0;
    int endIndex = 32;
    
    //case that string is exactly 128 bits
    if (div == 1) {
      outStrings[0] = fullString;
    }
    //case that string is > 128 bites
    else {
      int count = 0;
      while(count < div) {
        outStrings[count] = fullString.substring(beginIndex, endIndex);   
        beginIndex = beginIndex + 32;
        endIndex = endIndex + 32;
        count++;
      }
    }
    
    return outStrings;    
  }
  
  public static final int[][] sbox = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, 
	{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, 
	{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, 
	{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, 
	{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, 
	{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, 
	{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, 
	{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, 
	{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, 
	{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, 
	{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, 
	{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, 
	{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, 
	{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, 
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, 
	{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};
  
  public static final int[] rcon = 
    {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
	0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
	0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
	0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
	0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
	0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
	0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
	0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
	0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
	0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
	0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
	0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
	0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
	0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb};   
  
}
