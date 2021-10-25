/*
 * isha.c
 *
 * A completely insecure and bad hashing algorithm, based loosely on
 * SHA-1 (which is itself no longer considered a good hashing
 * algorithm)
 *
 * Based on code for sha1 processing from Paul E. Jones, available at
 * https://www.packetizer.com/security/sha1/
 */

#include "isha.h"
#include <stdio.h>
/*
 * circular shift macro
 */
#define ISHACircularShift(bits,word) \
  ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32-(bits))))


/*  
 * Processes the next 512 bits of the message stored in the MBlock
 * array.
 *
 * Parameters:
 *   ctx         The ISHAContext (in/out)
 */


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


void ISHAResult(ISHAContext *ctx, uint8_t *digest_out)
{
  if (ctx->Corrupted)
  {
    return;
  }

  if (!ctx->Computed)
  {
	  //in-lining the function ISHAPad
	  if (ctx->MB_Idx > 55)
	  {

		  ctx->MBlock[ctx->MB_Idx++] = 0x80;
		  __builtin_memset(ctx->MBlock + ctx->MB_Idx, 0, 64 - ctx->MB_Idx);

		  ISHAProcessMessageBlock(ctx);
		  __builtin_memset(ctx->MBlock + ctx->MB_Idx, 0, 56 - ctx->MB_Idx);
	  }

	  else
	  {
		  ctx->MBlock[ctx->MB_Idx++] = 0x80;
		  __builtin_memset(ctx->MBlock + ctx->MB_Idx, 0, 56 - ctx->MB_Idx);
	  }


	  	  ctx->MBlock[56] = 0;
	  	  ctx->MBlock[57] = 0;
		  ctx->MBlock[58] = 0;
		  ctx->MBlock[59] = 0;
		  ctx->MBlock[60] = (ctx->Length_Buffer >> 24);
		  ctx->MBlock[61] = (ctx->Length_Buffer >> 16);
		  ctx->MBlock[62] = (ctx->Length_Buffer >> 8);
		  ctx->MBlock[63] = (ctx->Length_Buffer);

		  ISHAProcessMessageBlock(ctx);
		  //in-lining the function ISHAPad
		  ctx->Computed = 1;

  }

  *((uint32_t *)(digest_out))=__builtin_bswap32(ctx->MD[0]);
  *((uint32_t *)(digest_out + 4))=__builtin_bswap32(ctx->MD[1]);
  *((uint32_t *)(digest_out + 8))=__builtin_bswap32(ctx->MD[2]);
  *((uint32_t *)(digest_out + 12))=__builtin_bswap32(ctx->MD[3]);
  *((uint32_t *)(digest_out + 16))=__builtin_bswap32(ctx->MD[4]);

  return;
}



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


