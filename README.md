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

Previously - </br>

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

Previously - </br>

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






# Development Details </br>
Software used Developed using MCUExpresso IDE 7.2.0 on Windows 10. </br>
DEBUG Mode - Prints DEBUG Messages to UART terminal at Baud Rate of 115200 and 8N1. </br>
To see the console messages in UART mode change to UART in quick settings and open a new Terminal with 115200 Baud Rate and 8N1 settings </br>
