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
  uint8_t accumulator[2560];
  assert(dkLen < sizeof(accumulator));

  int l = dkLen / ISHA_DIGESTLEN + 1;
  for (int i=0; i<l; i++) {
    F(pass, pass_len, salt, salt_len, iter, i+1, accumulator + i*ISHA_DIGESTLEN);
  }
  for (size_t i=0; i<dkLen; i++) {
    DK[i] = accumulator[i];
  }
}

Updated - </br>

1. For loop to call F() function was removed and changed with While loop</br>
2. Accumulator copying to DK loop was removed and all changes were directly performed on DK </br>
3. Accumulator array and assert was removed to reduce code text size </br>

void pbkdf2_hmac_isha(const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len, int iter, size_t dkLen, uint8_t *DK)
{

  register int l = dkLen / ISHA_DIGESTLEN + 1;


  while(l--)
  {
	  F(pass, pass_len, salt, salt_len, iter, l+1, DK + l*ISHA_DIGESTLEN);
  }

}

********************************************************************************************************</br>


# Function --> static void F(const uint8_t *pass, size_t pass_len, const uint8_t *salt, size_t salt_len, int iter, unsigned int blkidx, uint8_t *result) </br>

Originally - </br>

static void F(const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len,
    int iter, unsigned int blkidx, uint8_t *result)
{
  uint8_t temp[ISHA_DIGESTLEN];
  uint8_t saltplus[2048];
  size_t i;
  assert(salt_len + 4 <= sizeof(saltplus));

  for (i=0; i<salt_len; i++)
    saltplus[i] = salt[i];

  // append blkidx in 4 bytes big endian 
  saltplus[i] = (blkidx & 0xff000000) >> 24;
  saltplus[i+1] = (blkidx & 0x00ff0000) >> 16;
  saltplus[i+2] = (blkidx & 0x0000ff00) >> 8;
  saltplus[i+3] = (blkidx & 0x000000ff);

  hmac_isha(pass, pass_len, saltplus, salt_len+4, temp);
  for (int i=0; i<ISHA_DIGESTLEN; i++)
    result[i] = temp[i];

  for (int j=1; j<iter; j++) {
    hmac_isha(pass, pass_len, temp, ISHA_DIGESTLEN, temp);
    for (int i=0; i<ISHA_DIGESTLEN; i++)
      result[i] ^= temp[i];
  }
}


Updates done for this functions are - </br>

 for (int i=0; i<ISHA_DIGESTLEN; i++)
      result[i] ^= temp[i];

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
    
 
----------------------------------</br>

for (int j=1; j<iter; j++) {
    hmac_isha(pass, pass_len, temp, ISHA_DIGESTLEN, temp);
}

Changed to </br>

 iter = iter-1;
  while(iter--)
  {

    hmac_isha(pass, pass_len, temp, ISHA_DIGESTLEN,temp);

  }
  
  
-----------------------------------</br>

  for (int i=0; i<ISHA_DIGESTLEN; i++)
    result[i] = temp[i];

Changed to </br>

 __builtin_memcpy(result,temp,ISHA_DIGESTLEN);
 
-----------------------------------</br>

  for (i=0; i<salt_len; i++)
    saltplus[i] = salt[i];

Changed to </br>

 __builtin_memcpy(saltplus,salt,salt_len);
 
-----------------------------------</br>


1. For loop running "iter" times was changed to While loop </br
2. For loop running "20" times was changed with direct adding the XOR of temp values to result array </br
3. For loop copying temp values to result array was changed by memcpy </br>
4. For loop copying salt values to saltplus array was changed by memcpy </br>


********************************************************************************************************</br>

# Function --> void hmac_isha(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t *digest)   </br>

Originally - </br>

void hmac_isha(const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t *digest)
{
  uint8_t ipad[ISHA_BLOCKLEN];
  uint8_t opad[ISHA_BLOCKLEN];
  uint8_t keypad[ISHA_BLOCKLEN];
  uint8_t inner_digest[ISHA_DIGESTLEN];
  size_t i;
  ISHAContext ctx;

  if (key_len > ISHA_BLOCKLEN) {
    // If key_len > ISHA_BLOCKLEN reset it to key=ISHA(key)
    ISHAReset(&ctx);
    ISHAInput(&ctx, key, key_len);
    ISHAResult(&ctx, keypad);

  } else {
    // key_len <= ISHA_BLOCKLEN; copy key into keypad, zero pad the result
    for (i=0; i<key_len; i++)
      keypad[i] = key[i];
    for(i=key_len; i<ISHA_BLOCKLEN; i++)
      keypad[i] = 0x00;
  }

  // XOR key into ipad and opad
  for (i=0; i<ISHA_BLOCKLEN; i++) {
    ipad[i] = keypad[i] ^ 0x36;
    opad[i] = keypad[i] ^ 0x5c;
  }

  // Perform inner ISHA
  ISHAReset(&ctx);
  ISHAInput(&ctx, ipad, ISHA_BLOCKLEN);
  ISHAInput(&ctx, msg, msg_len);
  ISHAResult(&ctx, inner_digest);

  // perform outer ISHA
  ISHAReset(&ctx);
  ISHAInput(&ctx, opad, ISHA_BLOCKLEN);
  ISHAInput(&ctx, inner_digest, ISHA_DIGESTLEN);
  ISHAResult(&ctx, digest);
}


Updates done for this functions are - </br>

 // XOR key into ipad and opad
  for (i=0; i<ISHA_BLOCKLEN; i++) {
    ipad[i] = keypad[i] ^ 0x36;
    opad[i] = keypad[i] ^ 0x5c;
  }

Changed to </br

 while(i--)
  {
	  *(ipad+i) = *(key+i) ^ 0x36;
	  *(opad+i) = *(key+i) ^ 0x5c;
  }

  __builtin_memset(ipad+key_len,0x36,ISHA_BLOCKLEN-key_len);
  __builtin_memset(opad+key_len,0x5c,ISHA_BLOCKLEN-key_len);


----------------------------------------------------------</br>

1. Removed the if-else logic which included performing array copying and zero padding</br>
2. XOR logic for function was changed with while function with extra padding operation </br>


********************************************************************************************************</br>

# Function --> void ISHAReset(ISHAContext *ctx) </br>

Originally - 

void ISHAReset(ISHAContext *ctx)
{
  ctx->Length_Low  = 0;
  ctx->Length_High = 0;
  ctx->MB_Idx      = 0;

  ctx->MD[0]       = 0x67452301;
  ctx->MD[1]       = 0xEFCDAB89;
  ctx->MD[2]       = 0x98BADCFE;
  ctx->MD[3]       = 0x10325476;
  ctx->MD[4]       = 0xC3D2E1F0;

  ctx->Computed    = 0;
  ctx->Corrupted   = 0;
}


Changed to </br>

void ISHAReset(ISHAContext *ctx)
{

  ctx->Length_Buffer = 0;
  ctx->MB_Idx      = 0;

  ctx->MD[0]       = 0x67452301;
  ctx->MD[1]       = 0xEFCDAB89;
  ctx->MD[2]       = 0x98BADCFE;
  ctx->MD[3]       = 0x10325476;
  ctx->MD[4]       = 0xC3D2E1F0;

  ctx->Computed    = 0;
  ctx->Corrupted   = 0;
}

1. Processing time reduced by using since Buffer length instead of two buffer lengths in every function </br>

********************************************************************************************************</br>

# Function --> static void ISHAProcessMessageBlock(ISHAContext *ctx) </br>

Originally </br>

static void ISHAProcessMessageBlock(ISHAContext *ctx)
{
  uint32_t temp; 
  int t;
  uint32_t W[16];
  uint32_t A, B, C, D, E;

  A = ctx->MD[0];
  B = ctx->MD[1];
  C = ctx->MD[2];
  D = ctx->MD[3];
  E = ctx->MD[4];

  for(t = 0; t < 16; t++)
  {
    W[t] = ((uint32_t) ctx->MBlock[t * 4]) << 24;
    W[t] |= ((uint32_t) ctx->MBlock[t * 4 + 1]) << 16;
    W[t] |= ((uint32_t) ctx->MBlock[t * 4 + 2]) << 8;
    W[t] |= ((uint32_t) ctx->MBlock[t * 4 + 3]);
  }

  for(t = 0; t < 16; t++)
  {
    temp = ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t];
    temp &= 0xFFFFFFFF;
    E = D;
    D = C;
    C = ISHACircularShift(30,B);
    B = A;
    A = temp;
  }

  ctx->MD[0] = (ctx->MD[0] + A) & 0xFFFFFFFF;
  ctx->MD[1] = (ctx->MD[1] + B) & 0xFFFFFFFF;
  ctx->MD[2] = (ctx->MD[2] + C) & 0xFFFFFFFF;
  ctx->MD[3] = (ctx->MD[3] + D) & 0xFFFFFFFF;
  ctx->MD[4] = (ctx->MD[4] + E) & 0xFFFFFFFF;

  ctx->MB_Idx = 0;
}

Changed to </br> 

static void ISHAProcessMessageBlock(ISHAContext *ctx)
{
   register uint32_t temp;
   register int t=0;
   register uint32_t A, B, C, D, E;

  A = ctx->MD[0];
  B = ctx->MD[1];
  C = ctx->MD[2];
  D = ctx->MD[3];
  E = ctx->MD[4];

  while(t<16) {
	  temp = ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (((uint32_t) ctx->MBlock[t * 4]) << 24 | ((uint32_t) ctx->MBlock[t * 4 + 1]) << 16
	      		| ((uint32_t) ctx->MBlock[t * 4 + 2]) << 8 | ((uint32_t) ctx->MBlock[t * 4 + 3]) );
	  E = D;
	  D = C;
	  C = ISHACircularShift(30,B);
	  B = A;
	  A = temp;
	  t++;
  }


  ctx->MD[0] += A;
  ctx->MD[1] += B;
  ctx->MD[2] += C;
  ctx->MD[3] += D;
  ctx->MD[4] += E;

  ctx->MB_Idx = 0;

}

1. Instead of using two for loops running for t = 0 till t <16 i.e 16 times merged it into single for loop </br> 
2. W(t) was combined into single while loop </br>


********************************************************************************************************</br>

# Function --> void ISHAResult(ISHAContext *ctx, uint8_t *digest_out) </br>

Originally </br> 

void ISHAResult(ISHAContext *ctx, uint8_t *digest_out)
{
  if (ctx->Corrupted)
  {
    return;
  }

  if (!ctx->Computed)
  {
    ISHAPadMessage(ctx);
    ctx->Computed = 1;
  }

  for (int i=0; i<20; i+=4) {
    digest_out[i]   = (ctx->MD[i/4] & 0xff000000) >> 24;
    digest_out[i+1] = (ctx->MD[i/4] & 0x00ff0000) >> 16;
    digest_out[i+2] = (ctx->MD[i/4] & 0x0000ff00) >> 8;
    digest_out[i+3] = (ctx->MD[i/4] & 0x000000ff);
  }

  return;
}


Updated to </br>











# Development Details </br>
Software used Developed using MCUExpresso IDE 7.2.0 on Windows 10. </br>
DEBUG Mode - Prints DEBUG Messages to UART terminal at Baud Rate of 115200 and 8N1. </br>
To see the console messages in UART mode change to UART in quick settings and open a new Terminal with 115200 Baud Rate and 8N1 settings </br>
