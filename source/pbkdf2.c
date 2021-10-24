/*
 * pbkdf2.c
 *
 * A perfectly legitimate implementation of HMAC and PBKDF2, but based
 * on the "ISHA" insecure and bad hashing algorithm.
 * 
 * Author: Howdy Pierce, howdy.pierce@colorado.edu
 */

#include <assert.h>

#include "pbkdf2.h"

#include "ticktime.h"

#include "string.h"

#include <stdio.h>
uint32_t counter = 0;
/*
 * See function description in pbkdf2.h
 */
void hmac_isha(const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t *digest)
{
//	counter++;
//	ticktime_t duration = 0;
//	reset_timer();
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
//    for (i=0; i<key_len; i++)
//      keypad[i] = key[i];
    memcpy(keypad, key, key_len);

   // for(i=key_len; i<ISHA_BLOCKLEN; i++)
   //   keypad[i] = 0x00;
    memset(keypad + key_len, 0, (ISHA_BLOCKLEN - key_len));

  }

  // XOR key into ipad and opad
  i = key_len;
  while(i--){ // < ISHA_BLOCKLEN){
  //for (i=0; i<ISHA_BLOCKLEN; i++) {
//    ipad[i] = keypad[i] ^ 0x36;
//    opad[i] = keypad[i] ^ 0x5c;

	 *(ipad+i) = *(key+i) ^ 0x36;
    *(opad+i) = *(key+i) ^ 0x5c;
    //i++;
  }

  memset(ipad+key_len,0x36,ISHA_BLOCKLEN-key_len);
  memset(opad+key_len,0x5c,ISHA_BLOCKLEN-key_len);

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

//  if (counter == 13330)
//  {
//  duration = get_timer();
//  printf("hmac_isha run time is %d\r\n", duration);
//}
}



/*
 * Implements the F function as defined in RFC 8018 section 5.2
 *
 * Parameters:
 *   pass      The password
 *   pass_len  length of pass
 *   salt      The salt
 *   salt_len  length of salt
 *   iter      The iteration count ("c" in RFC 8018)
 *   blkidx    the block index ("i" in RFC 8018)
 *   result    The result, which is ISHA_DIGESTLEN bytes long
 * 
 * Returns:
 *   The result of computing the F function, in result
 */
static void F(const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len,
    int iter, unsigned int blkidx, uint8_t *result)
{
  //ticktime_t duration = 0;
  //reset_timer();
  uint8_t temp[ISHA_DIGESTLEN];
  uint8_t saltplus[16];

  //size_t i;
  assert(salt_len + 4 <= sizeof(saltplus));

//  for (i=0; i<salt_len; i++)
//    saltplus[i] = salt[i];
  memcpy(saltplus, salt, salt_len);

  // append blkidx in 4 bytes big endian 
  saltplus[salt_len] = (blkidx & 0xff000000) >> 24;
  saltplus[salt_len+1] = (blkidx & 0x00ff0000) >> 16;
  saltplus[salt_len+2] = (blkidx & 0x0000ff00) >> 8;
  saltplus[salt_len+3] = (blkidx & 0x000000ff);

  hmac_isha(pass, pass_len, saltplus, salt_len+4, temp);

//  for (int i=0; i<ISHA_DIGESTLEN; i++)
//    result[i] = temp[i];
  memcpy(result, temp, ISHA_DIGESTLEN);

  //int j = 1;
  iter = iter-1;
  while (iter--){
  //for (int j=1; j<iter; j++) {


    hmac_isha(pass, pass_len, temp, ISHA_DIGESTLEN, temp);
    //int i=0;
    //while (i<ISHA_DIGESTLEN){
    //for (int i=0; i<ISHA_DIGESTLEN; i++)
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
    //  i++;

  //}
  //  j++;
  //duration = get_timer();
  //printf("F run time is %d\r\n", duration);
}
}


/*
 * See function description in pbkdf2.h
 */
void pbkdf2_hmac_isha(const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len, int iter, size_t dkLen, uint8_t *DK)
{

  uint8_t accumulator[256];
  assert(dkLen < sizeof(accumulator));

  int l = dkLen / ISHA_DIGESTLEN + 1;
  //int i = 0;
  while (l--){
  //for (int i=0; i<l; i++) {
    F(pass, pass_len, salt, salt_len, iter, l+1, accumulator + l*ISHA_DIGESTLEN);
  //i++;
  }

  memcpy(DK, accumulator, dkLen);
//  for (size_t i=0; i<dkLen; i++) {
//    DK[i] = accumulator[i];
//  }
}



