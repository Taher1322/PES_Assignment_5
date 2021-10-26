# PES_Assignment_5
Code for Assignment 5 for PES, ECEN-5813, Fall 2021 - Due Date >> 10/26/2021 @ 10:30 AM MDT

# Author: TAHER UJJAINWALA </br>

Contact me if you are facing issue in execution of the code @ tauj5361@colorado.edu

# Introduction </br>

This assignment will focus on optimizing for better performance and perhaps (at your choice) writing some ARM assembly. In addition, 
we will start to develop an under appreciated skill for professional engineers: the ability to come up to speed on someone else’s code.

In cryptography, a key derivation function is used to stretch a secret—usually a passphrase—into a longer binary key suitable for use in a cryptosystem. By their nature, key derivation functions must be expensive to compute, in order to protect the cryptosystem against brute force dictionary attacks. One popular key derivation function is known as PBKDF2, which is defined inRFC 8018. PBKDF2 is used in a number of applications, including WPA2-PSK—perhaps the most widespread authentication system used today in deployed Wi-Fi networks.

As used in WPA2-PSK, the PBKDF2 function relies on calling HMAC-SHA1 8192 times; each call to HMAC-SHA1 in turn results in two calls to the SHA-1 secure hashing algorithm


# Code Optimization </br>
Changes made to reduce the overall execution run time are as follows: </br>


# Function -->  void pbkdf2_hmac_isha(const uint8_t *pass, size_t pass_len, const uint8_t *salt, size_t salt_len, int iter, size_t dkLen, uint8_t *DK) </br>

Originally - </br>

void pbkdf2_hmac_isha(const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len, int iter, size_t dkLen, uint8_t *DK) </br>
{
  uint8_t accumulator[2560]; </br>
  assert(dkLen < sizeof(accumulator)); </br>

  int l = dkLen / ISHA_DIGESTLEN + 1; </br>
  for (int i=0; i<l; i++) { </br>
    F(pass, pass_len, salt, salt_len, iter, i+1, accumulator + i*ISHA_DIGESTLEN); </br>
  }</br>
  for (size_t i=0; i<dkLen; i++) { </br>
    DK[i] = accumulator[i]; </br>
  } </br>
} </br>

Updated - </br>

1. For loop to call F() function was removed and changed with While loop</br>
2. Accumulator copying to DK loop was removed and all changes were directly performed on DK </br>
3. Accumulator array and assert was removed to reduce code text size </br>

void pbkdf2_hmac_isha(const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len, int iter, size_t dkLen, uint8_t *DK) </br>
{ </br>

  register int l = dkLen / ISHA_DIGESTLEN + 1; </br>


  while(l--)  </br>
  { </br>
	  F(pass, pass_len, salt, salt_len, iter, l+1, DK + l*ISHA_DIGESTLEN); </br>
  } </br>

} </br>

********************************************************************************************************</br>


# Function --> static void F(const uint8_t *pass, size_t pass_len, const uint8_t *salt, size_t salt_len, int iter, unsigned int blkidx, uint8_t *result) </br>

Originally - </br>

static void F(const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len,
    int iter, unsigned int blkidx, uint8_t *result) </br>
{ </br>
  uint8_t temp[ISHA_DIGESTLEN];  </br>
  uint8_t saltplus[2048]; </br></br>
  size_t i; </br>
  assert(salt_len + 4 <= sizeof(saltplus)); </br>

  for (i=0; i<salt_len; i++) </br>
    saltplus[i] = salt[i]; </br>

  // append blkidx in 4 bytes big endian </br>
  saltplus[i] = (blkidx & 0xff000000) >> 24; </br>
  saltplus[i+1] = (blkidx & 0x00ff0000) >> 16; </br>
  saltplus[i+2] = (blkidx & 0x0000ff00) >> 8; </br>
  saltplus[i+3] = (blkidx & 0x000000ff); </br>

  hmac_isha(pass, pass_len, saltplus, salt_len+4, temp); </br>
  for (int i=0; i<ISHA_DIGESTLEN; i++) </br>
    result[i] = temp[i]; </br>

  for (int j=1; j<iter; j++) { </br>
    hmac_isha(pass, pass_len, temp, ISHA_DIGESTLEN, temp); </br>
    for (int i=0; i<ISHA_DIGESTLEN; i++) </br>
      result[i] ^= temp[i]; </br>
  }</br>
} </br>


Updates done for this functions are - </br>

 for (int i=0; i<ISHA_DIGESTLEN; i++) </br>
      result[i] ^= temp[i]; </br>

Changed to </br>

    result[0] ^= temp[0];
    result[1] ^= temp[1];
    result[2] ^= temp[2];
    result[3] ^= temp[3];
    result[4] ^= temp[4];
    result[5] ^= temp[5];
    result[6] ^= temp[6];
    result[7] ^= temp[7];
    result[8] ^= temp[8];
    result[9] ^= temp[9];
    result[10] ^= temp[10];
    result[11] ^= temp[11];
    result[12] ^= temp[12];
    result[13] ^= temp[13];
    result[14] ^= temp[14];
    result[15] ^= temp[15];
    result[16] ^= temp[16];
    result[17] ^= temp[17];
    result[18] ^= temp[18];
    result[19] ^= temp[19];
    
 
---------------------------------------------------------------------------------------------------------</br>

for (int j=1; j<iter; j++) { </br>
    hmac_isha(pass, pass_len, temp, ISHA_DIGESTLEN, temp); </br>
} </br>

Changed to </br>

 iter = iter-1; </br>
  while(iter--) </br>
  { </br>

    hmac_isha(pass, pass_len, temp, ISHA_DIGESTLEN,temp); </br>

  } </br>
  

---------------------------------------------------------------------------------------------------------</br>
  

  for (int i=0; i<ISHA_DIGESTLEN; i++) </br>
    result[i] = temp[i]; </br>

Changed to </br>

 __builtin_memcpy(result,temp,ISHA_DIGESTLEN); </br>

---------------------------------------------------------------------------------------------------------</br>


  for (i=0; i<salt_len; i++) </br>
    saltplus[i] = salt[i]; </br>

Changed to </br>

 __builtin_memcpy(saltplus,salt,salt_len); </br>
 
---------------------------------------------------------------------------------------------------------</br>


1. For loop running "iter" times was changed to While loop </br
2. For loop running "20" times was changed with direct adding the XOR of temp values to result array </br
3. For loop copying temp values to result array was changed by memcpy </br>
4. For loop copying salt values to saltplus array was changed by memcpy </br>


********************************************************************************************************</br>

# Function --> void hmac_isha(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t *digest)   </br>

Originally - </br>

void hmac_isha(const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t *digest) </br>
{ </br>
  uint8_t ipad[ISHA_BLOCKLEN]; </br>
  uint8_t opad[ISHA_BLOCKLEN]; </br>
  uint8_t keypad[ISHA_BLOCKLEN]; </br>
  uint8_t inner_digest[ISHA_DIGESTLEN];  </br>
  size_t i; </br>
  ISHAContext ctx; </br>

  if (key_len > ISHA_BLOCKLEN) { </br>
    // If key_len > ISHA_BLOCKLEN reset it to key=ISHA(key) </br>
    ISHAReset(&ctx); </br>
    ISHAInput(&ctx, key, key_len); </br>
    ISHAResult(&ctx, keypad); </br>

  } else { </br>
    // key_len <= ISHA_BLOCKLEN; copy key into keypad, zero pad the result </br>
    for (i=0; i<key_len; i++) </br>
      keypad[i] = key[i]; </br>
    for(i=key_len; i<ISHA_BLOCKLEN; i++) </br>
      keypad[i] = 0x00; </br>
  }</br> 

  // XOR key into ipad and opad </br>
  for (i=0; i<ISHA_BLOCKLEN; i++) { </br>
    ipad[i] = keypad[i] ^ 0x36; </br>
    opad[i] = keypad[i] ^ 0x5c; </br>
  }</br>

  // Perform inner ISHA </br>
  ISHAReset(&ctx); </br>
  ISHAInput(&ctx, ipad, ISHA_BLOCKLEN); </br>
  ISHAInput(&ctx, msg, msg_len); </br>
  ISHAResult(&ctx, inner_digest); </br>

  // perform outer ISHA </br>
  ISHAReset(&ctx); </br>
  ISHAInput(&ctx, opad, ISHA_BLOCKLEN); </br>
  ISHAInput(&ctx, inner_digest, ISHA_DIGESTLEN); </br>
  ISHAResult(&ctx, digest); </br>
}


Updates done for this functions are - </br>

 // XOR key into ipad and opad </br>
  for (i=0; i<ISHA_BLOCKLEN; i++) { </br>
    ipad[i] = keypad[i] ^ 0x36; </br>
    opad[i] = keypad[i] ^ 0x5c; </br>
  } </br>

Changed to </br

 while(i--)   </br>
  { </br>
	  *(ipad+i) = *(key+i) ^ 0x36;  </br>
	  *(opad+i) = *(key+i) ^ 0x5c;  </br>
  } </br>

  __builtin_memset(ipad+key_len,0x36,ISHA_BLOCKLEN-key_len); </br>
  __builtin_memset(opad+key_len,0x5c,ISHA_BLOCKLEN-key_len); </br>


---------------------------------------------------------------------------------------------------------</br>


1. Removed the if-else logic which included performing array copying and zero padding</br>
2. XOR logic for function was changed with while function with extra padding operation </br>


********************************************************************************************************</br>

# Function --> void ISHAReset(ISHAContext *ctx) </br>

Originally - </br>

void ISHAReset(ISHAContext *ctx) </br>
{
  ctx->Length_Low  = 0; </br>   
  ctx->Length_High = 0; </br>
  ctx->MB_Idx      = 0; </br>

  ctx->MD[0]       = 0x67452301; </br>
  ctx->MD[1]       = 0xEFCDAB89; </br>
  ctx->MD[2]       = 0x98BADCFE; </br>
  ctx->MD[3]       = 0x10325476; </br>
  ctx->MD[4]       = 0xC3D2E1F0; </br>

  ctx->Computed    = 0; </br>
  ctx->Corrupted   = 0; </br>
} </br>


Changed to </br>

void ISHAReset(ISHAContext *ctx) </br>
{ </br>

  ctx->Length_Buffer = 0; </br>
  ctx->MB_Idx      = 0; </br>

  ctx->MD[0]       = 0x67452301; </br>
  ctx->MD[1]       = 0xEFCDAB89; </br>
  ctx->MD[2]       = 0x98BADCFE; </br>
  ctx->MD[3]       = 0x10325476; </br>
  ctx->MD[4]       = 0xC3D2E1F0; </br>

  ctx->Computed    = 0; </br>
  ctx->Corrupted   = 0; </br>
} </br>

1. Processing time reduced by using since Buffer length instead of two buffer lengths in every function </br>

********************************************************************************************************</br>

# Function --> static void ISHAProcessMessageBlock(ISHAContext *ctx) </br>

Originally </br>

static void ISHAProcessMessageBlock(ISHAContext *ctx) </br>
{ </br>
  uint32_t temp;  </br>
  int t; </br>
  uint32_t W[16];  </br>
  uint32_t A, B, C, D, E; </br>

  A = ctx->MD[0]; </br>
  B = ctx->MD[1]; </br>
  C = ctx->MD[2]; </br>
  D = ctx->MD[3]; </br>
  E = ctx->MD[4]; </br>

  for(t = 0; t < 16; t++) </br>
  { </br>
    W[t] = ((uint32_t) ctx->MBlock[t * 4]) << 24; </br>
    W[t] |= ((uint32_t) ctx->MBlock[t * 4 + 1]) << 16; </br>
    W[t] |= ((uint32_t) ctx->MBlock[t * 4 + 2]) << 8; </br>
    W[t] |= ((uint32_t) ctx->MBlock[t * 4 + 3]); </br>
  } </br>

  for(t = 0; t < 16; t++) </br>
  { </br>
    temp = ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t]; </br>
    temp &= 0xFFFFFFFF; </br>
    E = D; </br>
    D = C; </br>
    C = ISHACircularShift(30,B); </br>
    B = A; </br>
    A = temp; </br>
  } </br>

  ctx->MD[0] = (ctx->MD[0] + A) & 0xFFFFFFFF; </br>
  ctx->MD[1] = (ctx->MD[1] + B) & 0xFFFFFFFF; </br>
  ctx->MD[2] = (ctx->MD[2] + C) & 0xFFFFFFFF; </br>
  ctx->MD[3] = (ctx->MD[3] + D) & 0xFFFFFFFF; </br>
  ctx->MD[4] = (ctx->MD[4] + E) & 0xFFFFFFFF; </br>

  ctx->MB_Idx = 0; </br>
} </br>

Changed to </br> 

static void ISHAProcessMessageBlock(ISHAContext *ctx) </br>
{
   register uint32_t temp; </br>
   register int t=0; </br>
   register uint32_t A, B, C, D, E; </br>

  A = ctx->MD[0]; </br>
  B = ctx->MD[1]; </br>
  C = ctx->MD[2]; </br>
  D = ctx->MD[3]; </br>
  E = ctx->MD[4]; </br>

  while(t<16) { </br>
	  temp = ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (((uint32_t) ctx->MBlock[t * 4]) << 24 | ((uint32_t) ctx->MBlock[t * 4 + 1]) << 16
	      		| ((uint32_t) ctx->MBlock[t * 4 + 2]) << 8 | ((uint32_t) ctx->MBlock[t * 4 + 3]) ); </br>
	  E = D; </br>
	  D = C; </br>
	  C = ISHACircularShift(30,B); </br>
	  B = A; </br>
	  A = temp; </br>
	  t++; </br>
  }


  ctx->MD[0] += A; </br>
  ctx->MD[1] += B; </br>
  ctx->MD[2] += C; </br>
  ctx->MD[3] += D; </br>
  ctx->MD[4] += E; </br>

  ctx->MB_Idx = 0;  </br>

}

1. Instead of using two for loops running for t = 0 till t <16 i.e 16 times merged it into single for loop </br> 
2. W(t) was combined into single while loop </br>


********************************************************************************************************</br>

# Function --> void ISHAResult(ISHAContext *ctx, uint8_t *digest_out) </br>

Originally </br> 

void ISHAResult(ISHAContext *ctx, uint8_t *digest_out)  </br>
{ </br>
  if (ctx->Corrupted) </br>
  { </br>
    return; </br>
  } </br>

  if (!ctx->Computed) </br>
  { </br>
    ISHAPadMessage(ctx); </br>
    ctx->Computed = 1; </br>
  } </br>

  for (int i=0; i<20; i+=4) { </br>
    digest_out[i]   = (ctx->MD[i/4] & 0xff000000) >> 24; </br>
    digest_out[i+1] = (ctx->MD[i/4] & 0x00ff0000) >> 16; </br>
    digest_out[i+2] = (ctx->MD[i/4] & 0x0000ff00) >> 8; </br>
    digest_out[i+3] = (ctx->MD[i/4] & 0x000000ff);  </br>
  } </br>

  return; </br>
} </br>


Updates done for this function are </br>

void ISHAResult(ISHAContext *ctx, uint8_t *digest_out) </br>
{ </br>
  if (ctx->Corrupted) </br>
  { </br>
    return; </br>
  } </br>
 
  if (!ctx->Computed) </br>
  {</br>
	  //in-lining the function ISHAPad </br>
	  if (ctx->MB_Idx > 55) </br>
	  { </br>

		  ctx->MBlock[ctx->MB_Idx++] = 0x80; </br>
		  __builtin_memset(ctx->MBlock + ctx->MB_Idx, 0, 64 - ctx->MB_Idx); </br>
 
		  ISHAProcessMessageBlock(ctx); </br>
		  __builtin_memset(ctx->MBlock + ctx->MB_Idx, 0, 56 - ctx->MB_Idx); </br>
	  } </br>

	  else </br>
	  { </br>
		  ctx->MBlock[ctx->MB_Idx++] = 0x80; </br>
		  __builtin_memset(ctx->MBlock + ctx->MB_Idx, 0, 56 - ctx->MB_Idx); </br>
	  } </br>


	  	  ctx->MBlock[56] = 0; </br>
	  	  ctx->MBlock[57] = 0; </br>
		  ctx->MBlock[58] = 0; </br>
		  ctx->MBlock[59] = 0; </br>
		  ctx->MBlock[60] = (ctx->Length_Buffer >> 24); </br>
		  ctx->MBlock[61] = (ctx->Length_Buffer >> 16); </br>
		  ctx->MBlock[62] = (ctx->Length_Buffer >> 8); </br>
		  ctx->MBlock[63] = (ctx->Length_Buffer); </br>

		  ISHAProcessMessageBlock(ctx);  </br>
		  //in-lining the function ISHAPad </br>
		  ctx->Computed = 1; </br>

  } </br>
 
  *((uint32_t *)(digest_out))=__builtin_bswap32(ctx->MD[0]); </br>
  *((uint32_t *)(digest_out + 4))=__builtin_bswap32(ctx->MD[1]); </br>
  *((uint32_t *)(digest_out + 8))=__builtin_bswap32(ctx->MD[2]); </br>
  *((uint32_t *)(digest_out + 12))=__builtin_bswap32(ctx->MD[3]); </br>
  *((uint32_t *)(digest_out + 16))=__builtin_bswap32(ctx->MD[4]); </br>

  return; </br>
}

1. Merged void ISHAPadMessage(ctx) function in the if loop of ISHAResult(ISHAContext *ctx, uint8_t *digest_out) function </br>
2. To pad zero memset was used for faster execution </br>
3. To change the byte into big endian - bswap function was used </br>
4. Instead of using 2 lengths i.e Low and High - One Lenght_Buffer was used </br> 


********************************************************************************************************</br>

# Function --> void ISHAInput(ISHAContext *ctx, const uint8_t *message_array, size_t length) </br>

Originally - </br> 

void ISHAInput(ISHAContext *ctx, const uint8_t *message_array, size_t length)
{
  if (!length)
  {
    return;
  }

  if (ctx->Computed || ctx->Corrupted)
  {
    ctx->Corrupted = 1;
    return;
  }

  while(length-- && !ctx->Corrupted)
  {
    ctx->MBlock[ctx->MB_Idx++] = (*message_array & 0xFF);

    ctx->Length_Low += 8;
    /* Force it to 32 bits */
    ctx->Length_Low &= 0xFFFFFFFF;
    if (ctx->Length_Low == 0)
    {
      ctx->Length_High++;
      /* Force it to 32 bits */
      ctx->Length_High &= 0xFFFFFFFF;
      if (ctx->Length_High == 0)
      {
        /* Message is too long */
        ctx->Corrupted = 1;
      }
    }

    if (ctx->MB_Idx == 64)
    {
      ISHAProcessMessageBlock(ctx);
    }

    message_array++;
  }
}


Reference to update the if (length == 64) function was taken from Gaurang Rane </br> 
Updates done on this function are - </br> 

void ISHAInput(ISHAContext *ctx, const uint8_t *message_array, size_t length)
{

  if (!length)
  {
    return;
  }

  if(length == 64)
  {

	  ctx->Length_Buffer = 512;
	  __builtin_memcpy(ctx->MBlock,message_array,64);
	  ctx->MB_Idx+=64;
	  ISHAProcessMessageBlock(ctx);
  }

  else
  {
	  ctx->Length_Buffer += 8*length;

  	  while(length--)
  	  {
  		  ctx->MBlock[ctx->MB_Idx++] = (*message_array++);

  		  if (ctx->MB_Idx == 64 )
  		  {
  			  ISHAProcessMessageBlock(ctx);
  		  }
  	  }
  }

}

1. Logic implementing forcing to 32 bits is not required - because all definitions are in uint32_t </br>
2. Copying the data using memcpy into the MBlock if the length is 64 </br>
3. Incrementing the message_array pointer in the same code line 


********************************************************************************************************</br>

# Size Text Analysis </br>

Originally - </br> 



Updated - </br> 

Memory region         Used Size  Region Size  %age Used    </br> 
   PROGRAM_FLASH:       20488 B       128 KB     15.63%    </br> 
            SRAM:        9732 B        16 KB     59.40%    </br> 
Finished building target: PBKDF2.axf                       </br> 
 
make --no-print-directory post-build                       </br> 
Performing post-build steps								   </br> 
arm-none-eabi-size "PBKDF2.axf"; # arm-none-eabi-objcopy -v -O binary "PBKDF2.axf" "PBKDF2.bin" ; # checksum -p MKL25Z128xxx4 -d "PBKDF2.bin";  </br> 
   text	   data	    bss	    dec	    hex	filename  		   </br> 
  20480	      8	   9724	  30212	   7604	PBKDF2.axf 		   </br> 
  
20488 bytes </br> 


********************************************************************************************************</br>

# Run Time Analysis </br> 
 
Originally - </br> 

Updated - </br> 

2262 mseconds

********************************************************************************************************</br>





# Development Details </br>
Software used Developed using MCUExpresso IDE 7.2.0 on Windows 10. </br>
DEBUG Mode - Prints DEBUG Messages to UART terminal at Baud Rate of 115200 and 8N1. </br>
To see the console messages in UART mode change to UART in quick settings and open a new Terminal with 115200 Baud Rate and 8N1 settings </br>
