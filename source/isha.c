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
	//Adding register storage class to reduce run time and improve performance
	register uint32_t temp;
	register int t=0;
	register uint32_t A, B, C, D, E;

	A = ctx->MD[0];
	B = ctx->MD[1];
	C = ctx->MD[2];
	D = ctx->MD[3];
	E = ctx->MD[4];

	//Combined 2 for loops which were running from  t = 0 to t<16 into single while loop
	while(t<16) {

		//Combined the temp value with the other loop w(t) values and swapped the bytes using in built swap function
		temp = ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + __builtin_bswap32(*((uint32_t*)(ctx->MBlock + (t<<2)) ));
		E = D;
		D = C;
		C = ISHACircularShift(30,B);
		B = A;
		A = temp;
		t++;
	}

	//Removed the (& 0xFFFFFFFF) operation and assigned the next iteration directly
	ctx->MD[0] += A;
	ctx->MD[1] += B;
	ctx->MD[2] += C;
	ctx->MD[3] += D;
	ctx->MD[4] += E;

	ctx->MB_Idx = 0;

}


void ISHAReset(ISHAContext *ctx)
{

	//Combining the Low and High length buffer into single Length_Buffer which improves the performance
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
			//Removed while loop and using in build memset to pad the values
			__builtin_memset(ctx->MBlock + ctx->MB_Idx, 0, 64 - ctx->MB_Idx);

			ISHAProcessMessageBlock(ctx);
			//Removed while loop and using in build memset to pad the values
			__builtin_memset(ctx->MBlock + ctx->MB_Idx, 0, 56 - ctx->MB_Idx);
		}

		else
		{
			ctx->MBlock[ctx->MB_Idx++] = 0x80;
			//Removed while loop and using in build memset to pad the values
			__builtin_memset(ctx->MBlock + ctx->MB_Idx, 0, 56 - ctx->MB_Idx);
		}


	  	  	  //Storing the message length as last 8 octets as per RFC 8018
	  	  	  //Combining the Low and High length buffer into single Length_Buffer which improves the performance
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

	//Using build in swap function to reverse the byte
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

	//Removed ctx->Computed || ctx->Corrupted) comparison

	//Checking the condition if length == 64 then perform built in memcpy and run the function ISHAProcessMessageBlock()
	if(length == ISHA_BLOCKLEN)
	{
		//Length_Buffer = 8*ISHA_BLOCKLEN = 8*64 = 512 -- Constant value assignment to reduce run time
		ctx->Length_Buffer = 512;
		__builtin_memcpy(ctx->MBlock,message_array,64);
		ctx->MB_Idx+=64;
		ISHAProcessMessageBlock(ctx);
	}

	else
	{
		ctx->Length_Buffer += 8*length;

		//Removed Length_Low and Length_High if conditions which would never be true and was decoy code (not performing any task)
		while(length--)
		{
			//Single operation on pointer to store and increment
			ctx->MBlock[ctx->MB_Idx++] = (*message_array++);

			if (ctx->MB_Idx == 64 )
			{
				ISHAProcessMessageBlock(ctx);
			}
		}
	}

}


