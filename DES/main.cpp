//Author: Marcus Schmitz
//Computer Security: DES Project

#include <windows.h>
#include <sys/stat.h>
#include "DES.h"

using namespace std;

// DES <–action> <key> <mode> <infile> <outfile>

uint64_t keys[17] = { 0 }; //having the keys as global variables so they can be accessed anywhere

						   //HERE ARE THE 8 S-BOXES USED IN THE 16 ROUNDS
const unsigned char S1[64] =
{
	0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7,
	0x0, 0xF, 0x7, 0x4, 0xE, 0x2, 0xD, 0x1, 0xA, 0x6, 0xC, 0xB, 0x9, 0x5, 0x3, 0x8,
	0x4, 0x1, 0xE, 0x8, 0xD, 0x6, 0x2, 0xB, 0xF, 0xC, 0x9, 0x7, 0x3, 0xA, 0x5, 0x0,
	0xF, 0xC, 0x8, 0x2, 0x4, 0x9, 0x1, 0x7, 0x5, 0xB, 0x3, 0xE, 0xA, 0x0, 0x6, 0xD
};

const unsigned char S2[64] =
{
	0xF, 0x1, 0x8, 0xE, 0x6, 0xB, 0x3, 0x4, 0x9, 0x7, 0x2, 0xD, 0xC, 0x0, 0x5, 0xA,
	0x3, 0xD, 0x4, 0x7, 0xF, 0x2, 0x8, 0xE, 0xC, 0x0, 0x1, 0xA, 0x6, 0x9, 0xB, 0x5,
	0x0, 0xE, 0x7, 0xB, 0xA, 0x4, 0xD, 0x1, 0x5, 0x8, 0xC, 0x6, 0x9, 0x3, 0x2, 0xF,
	0xD, 0x8, 0xA, 0x1, 0x3, 0xF, 0x4, 0x2, 0xB, 0x6, 0x7, 0xC, 0x0, 0x5, 0xE, 0x9
};

const unsigned char S3[64] =
{
	0xA, 0x0, 0x9, 0xE, 0x6, 0x3, 0xF, 0x5, 0x1, 0xD, 0xC, 0x7, 0xB, 0x4, 0x2, 0x8,
	0xD, 0x7, 0x0, 0x9, 0x3, 0x4, 0x6, 0xA, 0x2, 0x8, 0x5, 0xE, 0xC, 0xB, 0xF, 0x1,
	0xD, 0x6, 0x4, 0x9, 0x8, 0xF, 0x3, 0x0, 0xB, 0x1, 0x2, 0xC, 0x5, 0xA, 0xE, 0x7,
	0x1, 0xA, 0xD, 0x0, 0x6, 0x9, 0x8, 0x7, 0x4, 0xF, 0xE, 0x3, 0xB, 0x5, 0x2, 0xC
};

const unsigned char S4[64] =
{
	0x7, 0xD, 0xE, 0x3, 0x0, 0x6, 0x9, 0xA, 0x1, 0x2, 0x8, 0x5, 0xB, 0xC, 0x4, 0xF,
	0xD, 0x8, 0xB, 0x5, 0x6, 0xF, 0x0, 0x3, 0x4, 0x7, 0x2, 0xC, 0x1, 0xA, 0xE, 0x9,
	0xA, 0x6, 0x9, 0x0, 0xC, 0xB, 0x7, 0xD, 0xF, 0x1, 0x3, 0xE, 0x5, 0x2, 0x8, 0x4,
	0x3, 0xF, 0x0, 0x6, 0xA, 0x1, 0xD, 0x8, 0x9, 0x4, 0x5, 0xB, 0xC, 0x7, 0x2, 0xE
};

const unsigned char S5[64] =
{
	0x2, 0xC, 0x4, 0x1, 0x7, 0xA, 0xB, 0x6, 0x8, 0x5, 0x3, 0xF, 0xD, 0x0, 0xE, 0x9,
	0xE, 0xB, 0x2, 0xC, 0x4, 0x7, 0xD, 0x1, 0x5, 0x0, 0xF, 0xA, 0x3, 0x9, 0x8, 0x6,
	0x4, 0x2, 0x1, 0xB, 0xA, 0xD, 0x7, 0x8, 0xF, 0x9, 0xC, 0x5, 0x6, 0x3, 0x0, 0xE,
	0xB, 0x8, 0xC, 0x7, 0x1, 0xE, 0x2, 0xD, 0x6, 0xF, 0x0, 0x9, 0xA, 0x4, 0x5, 0x3
};

const unsigned char S6[64] =
{
	0xC, 0x1, 0xA, 0xF, 0x9, 0x2, 0x6, 0x8, 0x0, 0xD, 0x3, 0x4, 0xE, 0x7, 0x5, 0xB,
	0xA, 0xF, 0x4, 0x2, 0x7, 0xC, 0x9, 0x5, 0x6, 0x1, 0xD, 0xE, 0x0, 0xB, 0x3, 0x8,
	0x9, 0xE, 0xF, 0x5, 0x2, 0x8, 0xC, 0x3, 0x7, 0x0, 0x4, 0xA, 0x1, 0xD, 0xB, 0x6,
	0x4, 0x3, 0x2, 0xC, 0x9, 0x5, 0xF, 0xA, 0xB, 0xE, 0x1, 0x7, 0x6, 0x0, 0x8, 0xD
};

const unsigned char S7[64] =
{
	0x4, 0xB, 0x2, 0xE, 0xF, 0x0, 0x8, 0xD, 0x3, 0xC, 0x9, 0x7, 0x5, 0xA, 0x6, 0x1,
	0xD, 0x0, 0xB, 0x7, 0x4, 0x9, 0x1, 0xA, 0xE, 0x3, 0x5, 0xC, 0x2, 0xF, 0x8, 0x6,
	0x1, 0x4, 0xB, 0xD, 0xC, 0x3, 0x7, 0xE, 0xA, 0xF, 0x6, 0x8, 0x0, 0x5, 0x9, 0x2,
	0x6, 0xB, 0xD, 0x8, 0x1, 0x4, 0xA, 0x7, 0x9, 0x5, 0x0, 0xF, 0xE, 0x2, 0x3, 0xC
};

const unsigned char S8[64] =
{
	0xD, 0x2, 0x8, 0x4, 0x6, 0xF, 0xB, 0x1, 0xA, 0x9, 0x3, 0xE, 0x5, 0x0, 0xC, 0x7,
	0x1, 0xF, 0xD, 0x8, 0xA, 0x3, 0x7, 0x4, 0xC, 0x5, 0x6, 0xB, 0x0, 0xE, 0x9, 0x2,
	0x7, 0xB, 0x4, 0x1, 0x9, 0xC, 0xE, 0x2, 0x0, 0x6, 0xA, 0xD, 0xF, 0x3, 0x5, 0x8,
	0x2, 0x1, 0xE, 0x7, 0x4, 0xA, 0x8, 0xD, 0xF, 0xC, 0x9, 0x0, 0x3, 0x5, 0x6, 0xB
};

void errorWithMessage(char *err)
{
	cout << "ERROR. " << err << endl;
	Sleep(2000);
	exit(0);
}

void init(int argc, char *argv[])
{
	if (argc != 6)
	{
		errorWithMessage("Incorrect number of arguments.");
	}

	if (!(strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "-D") == 0 || strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-E") == 0)) //action check
	{
		errorWithMessage("Incorrect action.");
	}

	if (!(strlen(argv[2]) == 10 || strlen(argv[2]) == 16)) //key check
	{
		errorWithMessage("Bad key.");
	}

	if (strlen(argv[3]) != 3) errorWithMessage("Incorrect Mode"); //needs to be 3 bytes long

	if (!(((argv[3][0] == 'e') || (argv[3][0] == 'E')) &&
		((argv[3][1] == 'c') || (argv[3][1] == 'C')) &&
		((argv[3][2] == 'b') || (argv[3][2] == 'B')))) //mode check
	{
		errorWithMessage("Incorrect Mode");
	}
}

void convertToChar(uint64_t value, char output[9])
{
	output[0] = ((char)(value >> 56));
	output[1] = ((char)(value >> 48));
	output[2] = ((char)(value >> 40));
	output[3] = ((char)(value >> 32));
	output[4] = ((char)(value >> 24));
	output[5] = ((char)(value >> 16));
	output[6] = ((char)(value >> 8));
	output[7] = ((char)(value));
}

uint64_t rotateBits(uint64_t key, int round)
{
	uint32_t c, d = 0;
	d = (uint32_t)(key & 0x0FFFFFFF); //and the right half of the 56 input bits here
	c = (uint32_t)(key >> 28); //we want the left half of the 56 input bits here

	uint8_t lowestC, lowestD = 0;
	//ROUNDS 1,2,9,16 rotate 1 bit
	if (round == 1 || round == 2 || round == 9 || round == 16)
	{
		lowestC = (c >> 27); //get the leftmost bit of the c value
		c = (c << 1); //shift the bits left 1 spot
		if (lowestC > 0)
		{
			c |= 0x1; //put a 1 in the rightmost spot
			c &= 0x0FFFFFFF; //this is to make sure the 29th bit is cleared
		}//else it already has a 0 in the lowest spot

		lowestD = (d >> 27); //get the leftmost bit of the d value
		d = (d << 1);
		if (lowestD > 0)
		{
			d |= 0x1; //put a 1 in the rightmost spot
			d &= 0x0FFFFFFF; //this is to make sure the 29th bit is cleared
		}
	}
	else //ROUNDS 3,4,5,6,7,8,10,11,12,13,14,15 all rotate 2 bits
	{
		lowestC = (c >> 26); //get the 2 leftmost bits of the c value
		c = (c << 2); //shift left 2 bits
		if (lowestC > 0)
		{
			c |= lowestC; //slide the 2 bits over to complete the rotation
			c &= 0x0FFFFFFF; //this is to make sure the 29th & 30th bits are cleared
		}
		lowestD = (d >> 26); //get the 2 leftmost bits of the d value
		d = (d << 2); //shift left 2 bits
		if (lowestD > 0)
		{
			d |= lowestD; //slide the 2 bits over to complete the rotation
			d &= 0x0FFFFFFF; //this is to make sure the 29th & 30th bits are cleared
		}
	}

	key = 0; //clear out everything in the key
	key |= ((uint64_t)c << 28) //put the new c back in the left 28bits
		| (uint64_t)d; //and the new d back in the right 28bits;

	return key;
}

uint64_t compressPermuteKey(uint64_t key)
{
	//This part compresses the input key into Permuted 48 bit Key
	uint64_t permKey = 0ULL;

	if (key & (1ULL << 55)) permKey |= (1ULL << (48 - 5));
	if (key & (1ULL << 54)) permKey |= (1ULL << (48 - 24));
	if (key & (1ULL << 53)) permKey |= (1ULL << (48 - 7));
	if (key & (1ULL << 52)) permKey |= (1ULL << (48 - 16));
	if (key & (1ULL << 51)) permKey |= (1ULL << (48 - 6));
	if (key & (1ULL << 50)) permKey |= (1ULL << (48 - 10));
	if (key & (1ULL << 49)) permKey |= (1ULL << (48 - 20)); //7
	if (key & (1ULL << 48)) permKey |= (1ULL << (48 - 18));
	//skip bit 9
	if (key & (1ULL << 46)) permKey |= (1ULL << (48 - 12));
	if (key & (1ULL << 45)) permKey |= (1ULL << (48 - 3));
	if (key & (1ULL << 44)) permKey |= (1ULL << (48 - 15));
	if (key & (1ULL << 43)) permKey |= (1ULL << (48 - 23));
	if (key & (1ULL << 42)) permKey |= (1ULL << (48 - 1)); //14
	if (key & (1ULL << 41)) permKey |= (1ULL << (48 - 9));
	if (key & (1ULL << 40)) permKey |= (1ULL << (48 - 19));
	if (key & (1ULL << 39)) permKey |= (1ULL << (48 - 2));
	//bit 18 skip
	if (key & (1ULL << 37)) permKey |= (1ULL << (48 - 14));
	if (key & (1ULL << 36)) permKey |= (1ULL << (48 - 22));
	if (key & (1ULL << 35)) permKey |= (1ULL << (48 - 11)); //21
															//bit 22 skip
	if (key & (1ULL << 33)) permKey |= (1ULL << (48 - 13));
	if (key & (1ULL << 32)) permKey |= (1ULL << (48 - 4));
	//bit 25 skip
	if (key & (1ULL << 30)) permKey |= (1ULL << (48 - 17));
	if (key & (1ULL << 29)) permKey |= (1ULL << (48 - 21));
	if (key & (1ULL << 28)) permKey |= (1ULL << (48 - 8)); //28
	if (key & (1ULL << 27)) permKey |= (1ULL << (48 - 47));
	if (key & (1ULL << 26)) permKey |= (1ULL << (48 - 31));
	if (key & (1ULL << 25)) permKey |= (1ULL << (48 - 27));
	if (key & (1ULL << 24)) permKey |= (1ULL << (48 - 48));
	if (key & (1ULL << 23)) permKey |= (1ULL << (48 - 35));
	if (key & (1ULL << 22)) permKey |= (1ULL << (48 - 41));
	//bit 35 skip											//35
	if (key & (1ULL << 20)) permKey |= (1ULL << (48 - 46));
	if (key & (1ULL << 19)) permKey |= (1ULL << (48 - 28));
	//bit 38 skip
	if (key & (1ULL << 17)) permKey |= (1ULL << (48 - 39));
	if (key & (1ULL << 16)) permKey |= (1ULL << (48 - 32));
	if (key & (1ULL << 15)) permKey |= (1ULL << (48 - 25));
	if (key & (1ULL << 14)) permKey |= (1ULL << (48 - 44)); //42
															//bit 43 skip
	if (key & (1ULL << 12)) permKey |= (1ULL << (48 - 37));
	if (key & (1ULL << 11)) permKey |= (1ULL << (48 - 34));
	if (key & (1ULL << 10)) permKey |= (1ULL << (48 - 43));
	if (key & (1ULL << 9))  permKey |= (1ULL << (48 - 29));
	if (key & (1ULL << 8))  permKey |= (1ULL << (48 - 36));
	if (key & (1ULL << 7))  permKey |= (1ULL << (48 - 38));	//49
	if (key & (1ULL << 6))  permKey |= (1ULL << (48 - 45));
	if (key & (1ULL << 5))  permKey |= (1ULL << (48 - 33));
	if (key & (1ULL << 4))  permKey |= (1ULL << (48 - 26));
	if (key & (1ULL << 3))  permKey |= (1ULL << (48 - 42));
	//bit 54 skip
	if (key & (1ULL << 1))  permKey |= (1ULL << (48 - 30));
	if (key & (1ULL << 0))  permKey |= (1ULL << (48 - 40)); //56

	return permKey;
}

uint64_t permutation1(uint64_t y)
{
	uint64_t output = 0;
	if (y & (1ULL << 63)) output |= (1ULL << (64 - 40)); //bit 1
	if (y & (1ULL << 62)) output |= (1ULL << (64 - 8));  //bit 2
	if (y & (1ULL << 61)) output |= (1ULL << (64 - 48)); //bit 3
	if (y & (1ULL << 60)) output |= (1ULL << (64 - 16)); //bit 4
	if (y & (1ULL << 59)) output |= (1ULL << (64 - 56)); //bit 5
	if (y & (1ULL << 58)) output |= (1ULL << (64 - 24)); //bit 6
	if (y & (1ULL << 57)) output |= (1ULL << (64 - 64)); //bit 7
	if (y & (1ULL << 56)) output |= (1ULL << (64 - 32)); //bit 8
	if (y & (1ULL << 55)) output |= (1ULL << (64 - 39)); //bit 9
	if (y & (1ULL << 54)) output |= (1ULL << (64 - 7));  //bit 10
	if (y & (1ULL << 53)) output |= (1ULL << (64 - 47)); //bit 11
	if (y & (1ULL << 52)) output |= (1ULL << (64 - 15)); //bit 12
	if (y & (1ULL << 51)) output |= (1ULL << (64 - 55)); //bit 13
	if (y & (1ULL << 50)) output |= (1ULL << (64 - 23)); //bit 14
	if (y & (1ULL << 49)) output |= (1ULL << (64 - 63)); //bit 15
	if (y & (1ULL << 48)) output |= (1ULL << (64 - 31)); //bit 16

	if (y & (1ULL << 47)) output |= (1ULL << (64 - 38)); //bit 17
	if (y & (1ULL << 46)) output |= (1ULL << (64 - 6));  //bit 18
	if (y & (1ULL << 45)) output |= (1ULL << (64 - 46)); //bit 19
	if (y & (1ULL << 44)) output |= (1ULL << (64 - 14)); //bit 20
	if (y & (1ULL << 43)) output |= (1ULL << (64 - 54)); //bit 21
	if (y & (1ULL << 42)) output |= (1ULL << (64 - 22)); //bit 22
	if (y & (1ULL << 41)) output |= (1ULL << (64 - 62)); //bit 23
	if (y & (1ULL << 40)) output |= (1ULL << (64 - 30)); //bit 24
	if (y & (1ULL << 39)) output |= (1ULL << (64 - 37)); //bit 25
	if (y & (1ULL << 38)) output |= (1ULL << (64 - 5));  //bit 26
	if (y & (1ULL << 37)) output |= (1ULL << (64 - 45)); //bit 27
	if (y & (1ULL << 36)) output |= (1ULL << (64 - 13)); //bit 28
	if (y & (1ULL << 35)) output |= (1ULL << (64 - 53)); //bit 29
	if (y & (1ULL << 34)) output |= (1ULL << (64 - 21)); //bit 30
	if (y & (1ULL << 33)) output |= (1ULL << (64 - 61)); //bit 31
	if (y & (1ULL << 32)) output |= (1ULL << (64 - 29)); //bit 32

	if (y & (1ULL << 31)) output |= (1ULL << (64 - 36)); //bit 33
	if (y & (1ULL << 30)) output |= (1ULL << (64 - 4));  //bit 34
	if (y & (1ULL << 29)) output |= (1ULL << (64 - 44)); //bit 35
	if (y & (1ULL << 28)) output |= (1ULL << (64 - 12)); //bit 36
	if (y & (1ULL << 27)) output |= (1ULL << (64 - 52)); //bit 37
	if (y & (1ULL << 26)) output |= (1ULL << (64 - 20)); //bit 38
	if (y & (1ULL << 25)) output |= (1ULL << (64 - 60)); //bit 39
	if (y & (1ULL << 24)) output |= (1ULL << (64 - 28)); //bit 40
	if (y & (1ULL << 23)) output |= (1ULL << (64 - 35)); //bit 41
	if (y & (1ULL << 22)) output |= (1ULL << (64 - 3));  //bit 42
	if (y & (1ULL << 21)) output |= (1ULL << (64 - 43)); //bit 43
	if (y & (1ULL << 20)) output |= (1ULL << (64 - 11)); //bit 44
	if (y & (1ULL << 19)) output |= (1ULL << (64 - 51)); //bit 45
	if (y & (1ULL << 18)) output |= (1ULL << (64 - 19)); //bit 46
	if (y & (1ULL << 17)) output |= (1ULL << (64 - 59)); //bit 47
	if (y & (1ULL << 16)) output |= (1ULL << (64 - 27)); //bit 48

	if (y & (1ULL << 15)) output |= (1ULL << (64 - 34)); //bit 49
	if (y & (1ULL << 14)) output |= (1ULL << (64 - 2));  //bit 50
	if (y & (1ULL << 13)) output |= (1ULL << (64 - 42)); //bit 51
	if (y & (1ULL << 12)) output |= (1ULL << (64 - 10)); //bit 52
	if (y & (1ULL << 11)) output |= (1ULL << (64 - 50)); //bit 53
	if (y & (1ULL << 10)) output |= (1ULL << (64 - 18)); //bit 54
	if (y & (1ULL << 9))  output |= (1ULL << (64 - 58)); //bit 55
	if (y & (1ULL << 8))  output |= (1ULL << (64 - 26)); //bit 56
	if (y & (1ULL << 7))  output |= (1ULL << (64 - 33)); //bit 57
	if (y & (1ULL << 6))  output |= (1ULL << (64 - 1));  //bit 58
	if (y & (1ULL << 5))  output |= (1ULL << (64 - 41)); //bit 59
	if (y & (1ULL << 4))  output |= (1ULL << (64 - 9));  //bit 60
	if (y & (1ULL << 3))  output |= (1ULL << (64 - 49)); //bit 61
	if (y & (1ULL << 2))  output |= (1ULL << (64 - 17)); //bit 62
	if (y & (1ULL << 1))  output |= (1ULL << (64 - 57)); //bit 63
	if (y & (1ULL << 0))  output |= (1ULL << (64 - 25)); //bit 64

	return output;
	// end of initial permutation
}

uint64_t finalPermutation(uint64_t y)
{
	uint64_t output = 0;

	if (y & (1ULL << 63)) output |= (1ULL << (64 - 58)); //bit 1
	if (y & (1ULL << 62)) output |= (1ULL << (64 - 50)); //bit 2
	if (y & (1ULL << 61)) output |= (1ULL << (64 - 42)); //bit 3
	if (y & (1ULL << 60)) output |= (1ULL << (64 - 34)); //bit 4
	if (y & (1ULL << 59)) output |= (1ULL << (64 - 26)); //bit 5
	if (y & (1ULL << 58)) output |= (1ULL << (64 - 18)); //bit 6
	if (y & (1ULL << 57)) output |= (1ULL << (64 - 10)); //bit 7
	if (y & (1ULL << 56)) output |= (1ULL << (64 - 2));  //bit 8
	if (y & (1ULL << 55)) output |= (1ULL << (64 - 60)); //bit 9
	if (y & (1ULL << 54)) output |= (1ULL << (64 - 52)); //bit 10
	if (y & (1ULL << 53)) output |= (1ULL << (64 - 44)); //bit 11
	if (y & (1ULL << 52)) output |= (1ULL << (64 - 36)); //bit 12
	if (y & (1ULL << 51)) output |= (1ULL << (64 - 28)); //bit 13
	if (y & (1ULL << 50)) output |= (1ULL << (64 - 20)); //bit 14
	if (y & (1ULL << 49)) output |= (1ULL << (64 - 12)); //bit 15
	if (y & (1ULL << 48)) output |= (1ULL << (64 - 4));  //bit 16

	if (y & (1ULL << 47)) output |= (1ULL << (64 - 62)); //bit 17
	if (y & (1ULL << 46)) output |= (1ULL << (64 - 54)); //bit 18
	if (y & (1ULL << 45)) output |= (1ULL << (64 - 46)); //bit 19
	if (y & (1ULL << 44)) output |= (1ULL << (64 - 38)); //bit 20
	if (y & (1ULL << 43)) output |= (1ULL << (64 - 30)); //bit 21
	if (y & (1ULL << 42)) output |= (1ULL << (64 - 22)); //bit 22
	if (y & (1ULL << 41)) output |= (1ULL << (64 - 14)); //bit 23
	if (y & (1ULL << 40)) output |= (1ULL << (64 - 6));  //bit 24
	if (y & (1ULL << 39)) output |= (1ULL << (64 - 64)); //bit 25
	if (y & (1ULL << 38)) output |= (1ULL << (64 - 56)); //bit 26
	if (y & (1ULL << 37)) output |= (1ULL << (64 - 48)); //bit 27
	if (y & (1ULL << 36)) output |= (1ULL << (64 - 40)); //bit 28
	if (y & (1ULL << 35)) output |= (1ULL << (64 - 32)); //bit 29
	if (y & (1ULL << 34)) output |= (1ULL << (64 - 24)); //bit 30
	if (y & (1ULL << 33)) output |= (1ULL << (64 - 16)); //bit 31
	if (y & (1ULL << 32)) output |= (1ULL << (64 - 8));  //bit 32

	if (y & (1ULL << 31)) output |= (1ULL << (64 - 57)); //bit 33
	if (y & (1ULL << 30)) output |= (1ULL << (64 - 49)); //bit 34
	if (y & (1ULL << 29)) output |= (1ULL << (64 - 41)); //bit 35
	if (y & (1ULL << 28)) output |= (1ULL << (64 - 33)); //bit 36
	if (y & (1ULL << 27)) output |= (1ULL << (64 - 25)); //bit 37
	if (y & (1ULL << 26)) output |= (1ULL << (64 - 17)); //bit 38
	if (y & (1ULL << 25)) output |= (1ULL << (64 - 9));  //bit 39
	if (y & (1ULL << 24)) output |= (1ULL << (64 - 1));  //bit 40
	if (y & (1ULL << 23)) output |= (1ULL << (64 - 59)); //bit 41
	if (y & (1ULL << 22)) output |= (1ULL << (64 - 51)); //bit 42
	if (y & (1ULL << 21)) output |= (1ULL << (64 - 43)); //bit 43
	if (y & (1ULL << 20)) output |= (1ULL << (64 - 35)); //bit 44
	if (y & (1ULL << 19)) output |= (1ULL << (64 - 27)); //bit 45
	if (y & (1ULL << 18)) output |= (1ULL << (64 - 19)); //bit 46
	if (y & (1ULL << 17)) output |= (1ULL << (64 - 11)); //bit 47
	if (y & (1ULL << 16)) output |= (1ULL << (64 - 3));  //bit 48

	if (y & (1ULL << 15)) output |= (1ULL << (64 - 61)); //bit 49
	if (y & (1ULL << 14)) output |= (1ULL << (64 - 53)); //bit 50
	if (y & (1ULL << 13)) output |= (1ULL << (64 - 45)); //bit 51
	if (y & (1ULL << 12)) output |= (1ULL << (64 - 37)); //bit 52
	if (y & (1ULL << 11)) output |= (1ULL << (64 - 29)); //bit 53
	if (y & (1ULL << 10)) output |= (1ULL << (64 - 21)); //bit 54
	if (y & (1ULL << 9))  output |= (1ULL << (64 - 13)); //bit 55
	if (y & (1ULL << 8))  output |= (1ULL << (64 - 5));  //bit 56
	if (y & (1ULL << 7))  output |= (1ULL << (64 - 63)); //bit 57
	if (y & (1ULL << 6))  output |= (1ULL << (64 - 55)); //bit 58
	if (y & (1ULL << 5))  output |= (1ULL << (64 - 47)); //bit 59
	if (y & (1ULL << 4))  output |= (1ULL << (64 - 39)); //bit 60
	if (y & (1ULL << 3))  output |= (1ULL << (64 - 31)); //bit 61
	if (y & (1ULL << 2))  output |= (1ULL << (64 - 23)); //bit 62
	if (y & (1ULL << 1))  output |= (1ULL << (64 - 15)); //bit 63
	if (y & (1ULL << 0))  output |= (1ULL << (64 - 7));  //bit 64

	return output;
}

uint64_t runIt(uint64_t y, int roundKey)
{
	uint64_t right = y & 0xFFFFFFFF;
	uint64_t left = (y >> 32);
	uint64_t nextLeft = right;

	uint64_t expandedRight = 0;
	//expansion permutation of right side
	if (right & (1ULL << 31))//bit 1
	{
		expandedRight |= (1ULL << (48 - 2));
		expandedRight |= (1ULL << (48 - 48));
	}
	if (right & (1ULL << 30)) expandedRight |= (1ULL << (48 - 3)); //bit 2
	if (right & (1ULL << 29)) expandedRight |= (1ULL << (48 - 4)); //bit 3
	if (right & (1ULL << 28)) //bit 4
	{
		expandedRight |= (1ULL << (48 - 5));
		expandedRight |= (1ULL << (48 - 7));
	}
	if (right & (1ULL << 27)) //bit 5
	{
		expandedRight |= (1ULL << (48 - 6));
		expandedRight |= (1ULL << (48 - 8));
	}
	if (right & (1ULL << 26)) expandedRight |= (1ULL << (48 - 9)); //bit 6
	if (right & (1ULL << 25)) expandedRight |= (1ULL << (48 - 10)); //bit 7
	if (right & (1ULL << 24)) //bit 8
	{
		expandedRight |= (1ULL << (48 - 11));
		expandedRight |= (1ULL << (48 - 13));
	}
	if (right & (1ULL << 23)) //bit 9
	{
		expandedRight |= (1ULL << (48 - 12));
		expandedRight |= (1ULL << (48 - 14));
	}
	if (right & (1ULL << 22)) expandedRight |= (1ULL << (48 - 15)); //bit 10
	if (right & (1ULL << 21)) expandedRight |= (1ULL << (48 - 16)); //bit 11
	if (right & (1ULL << 20)) //bit 12
	{
		expandedRight |= (1ULL << (48 - 17));
		expandedRight |= (1ULL << (48 - 19));
	}
	if (right & (1ULL << 19)) //bit 13
	{
		expandedRight |= (1ULL << (48 - 18));
		expandedRight |= (1ULL << (48 - 20));
	}
	if (right & (1ULL << 18)) expandedRight |= (1ULL << (48 - 21)); //bit 14
	if (right & (1ULL << 17)) expandedRight |= (1ULL << (48 - 22)); //bit 15
	if (right & (1ULL << 16)) //bit 16
	{
		expandedRight |= (1ULL << (48 - 23));
		expandedRight |= (1ULL << (48 - 25));
	}
	if (right & (1ULL << 15)) //bit 17
	{
		expandedRight |= (1ULL << (48 - 24));
		expandedRight |= (1ULL << (48 - 26));
	}
	if (right & (1ULL << 14)) expandedRight |= (1ULL << (48 - 27)); //bit 18
	if (right & (1ULL << 13)) expandedRight |= (1ULL << (48 - 28)); //bit 19
	if (right & (1ULL << 12)) //bit 20
	{
		expandedRight |= (1ULL << (48 - 29));
		expandedRight |= (1ULL << (48 - 31));
	}
	if (right & (1ULL << 11)) //bit 21
	{
		expandedRight |= (1ULL << (48 - 30));
		expandedRight |= (1ULL << (48 - 32));
	}
	if (right & (1ULL << 10)) expandedRight |= (1ULL << (48 - 33)); //bit 22
	if (right & (1ULL << 9)) expandedRight |= (1ULL << (48 - 34)); //bit 23
	if (right & (1ULL << 8))  //bit 24
	{
		expandedRight |= (1ULL << (48 - 35));
		expandedRight |= (1ULL << (48 - 37));
	}
	if (right & (1ULL << 7))  //bit 25
	{
		expandedRight |= (1ULL << (48 - 36));
		expandedRight |= (1ULL << (48 - 38));
	}
	if (right & (1ULL << 6))  expandedRight |= (1ULL << (48 - 39)); //bit 26
	if (right & (1ULL << 5))  expandedRight |= (1ULL << (48 - 40)); //bit 27
	if (right & (1ULL << 4))  //bit 28
	{
		expandedRight |= (1ULL << (48 - 41));
		expandedRight |= (1ULL << (48 - 43));
	}
	if (right & (1ULL << 3))  //bit 29
	{
		expandedRight |= (1ULL << (48 - 42));
		expandedRight |= (1ULL << (48 - 44));
	}
	if (right & (1ULL << 2))  expandedRight |= (1ULL << (48 - 45)); //bit 30
	if (right & (1ULL << 1))  expandedRight |= (1ULL << (48 - 46)); //bit 31
	if (right & (1ULL << 0))  //bit 32
	{
		expandedRight |= (1ULL << (48 - 47));
		expandedRight |= (1ULL << (48 - 1));
	}

	//Now we want to take the expandedRight and keys[roundKey] and xor them
	uint64_t rk = (expandedRight ^ keys[roundKey]);

	//to get each 6-bit value we shift the bits and clear any unwanted bits
	uint8_t s1 = (uint8_t)(rk >> 42);
	uint8_t s2 = (uint8_t)(rk >> 36) & 0x3F;
	uint8_t	s3 = (uint8_t)(rk >> 30) & 0x3F;
	uint8_t s4 = (uint8_t)(rk >> 24) & 0x3F;
	uint8_t s5 = (uint8_t)(rk >> 18) & 0x3F;
	uint8_t s6 = (uint8_t)(rk >> 12) & 0x3F;
	uint8_t s7 = (uint8_t)(rk >> 6) & 0x3F;
	uint8_t s8 = (uint8_t)(rk) & 0x3F;

	//I know this looks crazy but in short, the first part is selecting which row
	//of the Sbox to select from (0-3) then multiply that by 16 to get to the right
	//part of the array.  To select the right column we need to add the value of the 4 inner 
	//bits of the s values set above. This total will give us the array index that we need to select.
	//Finally we & it with F to make sure we only get the 4 bits and nothing more.
	s1 = 0xF & S1[16 * ((((s1 >> 4) & 0x02) | (s1 & 1)) & 0x03) + (((s1 >> 1)) & 0x0F)];
	s2 = 0xF & S2[16 * ((((s2 >> 4) & 0x02) | (s2 & 1)) & 0x03) + (((s2 >> 1)) & 0x0F)];
	s3 = 0xF & S3[16 * ((((s3 >> 4) & 0x02) | (s3 & 1)) & 0x03) + (((s3 >> 1)) & 0x0F)];
	s4 = 0xF & S4[16 * ((((s4 >> 4) & 0x02) | (s4 & 1)) & 0x03) + (((s4 >> 1)) & 0x0F)];
	s5 = 0xF & S5[16 * ((((s5 >> 4) & 0x02) | (s5 & 1)) & 0x03) + (((s5 >> 1)) & 0x0F)];
	s6 = 0xF & S6[16 * ((((s6 >> 4) & 0x02) | (s6 & 1)) & 0x03) + (((s6 >> 1)) & 0x0F)];
	s7 = 0xF & S7[16 * ((((s7 >> 4) & 0x02) | (s7 & 1)) & 0x03) + (((s7 >> 1)) & 0x0F)];
	s8 = 0xF & S8[16 * ((((s8 >> 4) & 0x02) | (s8 & 1)) & 0x03) + (((s8 >> 1)) & 0x0F)];

	right = (((uint64_t)s1 << 28)
		| ((uint64_t)s2 << 24)
		| ((uint64_t)s3 << 20)
		| ((uint64_t)s4 << 16)
		| ((uint64_t)s5 << 12)
		| ((uint64_t)s6 << 8)
		| ((uint64_t)s7 << 4)
		| ((uint64_t)s8))
		& 0x00000000FFFFFFFF;

	uint64_t permRight = 0;
	//Straight Permutation of the right block
	if (right & (1ULL << 31)) permRight |= (1ULL << (32 - 9));
	if (right & (1ULL << 30)) permRight |= (1ULL << (32 - 17));
	if (right & (1ULL << 29)) permRight |= (1ULL << (32 - 23));
	if (right & (1ULL << 28)) permRight |= (1ULL << (32 - 31));
	if (right & (1ULL << 27)) permRight |= (1ULL << (32 - 13));
	if (right & (1ULL << 26)) permRight |= (1ULL << (32 - 28));
	if (right & (1ULL << 25)) permRight |= (1ULL << (32 - 2));
	if (right & (1ULL << 24)) permRight |= (1ULL << (32 - 18));
	if (right & (1ULL << 23)) permRight |= (1ULL << (32 - 24));
	if (right & (1ULL << 22)) permRight |= (1ULL << (32 - 16));
	if (right & (1ULL << 21)) permRight |= (1ULL << (32 - 30));
	if (right & (1ULL << 20)) permRight |= (1ULL << (32 - 6));
	if (right & (1ULL << 19)) permRight |= (1ULL << (32 - 26));
	if (right & (1ULL << 18)) permRight |= (1ULL << (32 - 20));
	if (right & (1ULL << 17)) permRight |= (1ULL << (32 - 10));
	if (right & (1ULL << 16)) permRight |= (1ULL << (32 - 1));

	if (right & (1ULL << 15)) permRight |= (1ULL << (32 - 8));
	if (right & (1ULL << 14)) permRight |= (1ULL << (32 - 14));
	if (right & (1ULL << 13)) permRight |= (1ULL << (32 - 25));
	if (right & (1ULL << 12)) permRight |= (1ULL << (32 - 3));
	if (right & (1ULL << 11)) permRight |= (1ULL << (32 - 4));
	if (right & (1ULL << 10)) permRight |= (1ULL << (32 - 29));
	if (right & (1ULL << 9))  permRight |= (1ULL << (32 - 11));
	if (right & (1ULL << 8))  permRight |= (1ULL << (32 - 19));
	if (right & (1ULL << 7))  permRight |= (1ULL << (32 - 32));
	if (right & (1ULL << 6))  permRight |= (1ULL << (32 - 12));
	if (right & (1ULL << 5))  permRight |= (1ULL << (32 - 22));
	if (right & (1ULL << 4))  permRight |= (1ULL << (32 - 7));
	if (right & (1ULL << 3))  permRight |= (1ULL << (32 - 5));
	if (right & (1ULL << 2))  permRight |= (1ULL << (32 - 27));
	if (right & (1ULL << 1))  permRight |= (1ULL << (32 - 15));
	if (right & (1ULL << 0))  permRight |= (1ULL << (32 - 21));

	right = (permRight ^ left);

	y = (nextLeft << 32) | right;


	return y;
}

int main(int argc, char *argv[])
{
	//start timer here
	clock_t start;
	double duration;
	start = clock();

	//checks all the arguments (except the in and out files) and exits if there are any issues
	init(argc, argv);

	//opening the input file and initializing or opening the output file
	char *inFileName = argv[4];
	fstream inFile;

	inFile.open(inFileName, fstream::in | fstream::binary);

	if (!inFile) //infile check -> open
	{
		errorWithMessage("File does not exist.");
	}

	char *outFileName = argv[5];
	fstream outFile;
	outFile.open(outFileName, fstream::out | fstream::binary | fstream::trunc);

	//should start by computing all 16 keys and store them in an array
	//if we are decoding, we need to run through the keys in reverse.
	//argv[2] is the key
	//When we compress and permutate the key from 64bits down to 56 scrambled bits,
	//We skip every 8th bit which is what does the compressing.

	uint64_t key = 0;

	//If the key comes in as '{key value}' or "'{key value}'"
	if (strlen(argv[2]) == 10)
	{
		key |= (((uint64_t)argv[2][1] << 56) & 0xFF00000000000000U)
			| (((uint64_t)argv[2][2] << 48) & 0x00FF000000000000U)
			| (((uint64_t)argv[2][3] << 40) & 0x0000FF0000000000U)
			| (((uint64_t)argv[2][4] << 32) & 0x000000FF00000000U)
			| (((uint64_t)argv[2][5] << 24) & 0x00000000FF000000U)
			| (((uint64_t)argv[2][6] << 16) & 0x0000000000FF0000U)
			| (((uint64_t)argv[2][7] << 8) & 0x000000000000FF00U)
			| (((uint64_t)argv[2][8]) & 0x00000000000000FFU);
	}
	//if the key comes in as 16 Hex values
	else {
		//check to make sure each value is valid hex
		if (argv[2][0] >= 48 && argv[2][0] <= 57)
		{
			argv[2][0] -= 48;
		}
		else if (argv[2][0] >= 65 && argv[2][0] <= 70)
		{
			argv[2][0] -= 55;
		}
		else if (argv[2][0] >= 97 && argv[2][0] <= 102)
		{
			argv[2][0] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		if (argv[2][1] >= 48 && argv[2][1] <= 57)
		{
			argv[2][1] -= 48;
		}
		else if (argv[2][1] >= 65 && argv[2][1] <= 70)
		{
			argv[2][1] -= 55;
		}
		else if (argv[2][1] >= 97 && argv[2][1] <= 102)
		{
			argv[2][1] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		if (argv[2][2] >= 48 && argv[2][2] <= 57)
		{
			argv[2][2] -= 48;
		}
		else if (argv[2][2] >= 65 && argv[2][2] <= 70)
		{
			argv[2][2] -= 55;
		}
		else if (argv[2][2] >= 97 && argv[2][2] <= 102)
		{
			argv[2][2] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		if (argv[2][3] >= 48 && argv[2][3] <= 57)
		{
			argv[2][3] -= 48;
		}
		else if (argv[2][3] >= 65 && argv[2][3] <= 70)
		{
			argv[2][3] -= 55;
		}
		else if (argv[2][3] >= 97 && argv[2][3] <= 102)
		{
			argv[2][3] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		if (argv[2][4] >= 48 && argv[2][4] <= 57)
		{
			argv[2][4] -= 48;
		}
		else if (argv[2][4] >= 65 && argv[2][4] <= 70)
		{
			argv[2][4] -= 55;
		}
		else if (argv[2][4] >= 97 && argv[2][4] <= 102)
		{
			argv[2][4] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		if (argv[2][5] >= 48 && argv[2][5] <= 57)
		{
			argv[2][5] -= 48;
		}
		else if (argv[2][5] >= 65 && argv[2][5] <= 70)
		{
			argv[2][5] -= 55;
		}
		else if (argv[2][5] >= 97 && argv[2][5] <= 102)
		{
			argv[2][5] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		if (argv[2][6] >= 48 && argv[2][6] <= 57)
		{
			argv[2][6] -= 48;
		}
		else if (argv[2][6] >= 65 && argv[2][6] <= 70)
		{
			argv[2][6] -= 55;
		}
		else if (argv[2][6] >= 97 && argv[2][6] <= 102)
		{
			argv[2][6] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		if (argv[2][7] >= 48 && argv[2][7] <= 57)
		{
			argv[2][7] -= 48;
		}
		else if (argv[2][7] >= 65 && argv[2][7] <= 70)
		{
			argv[2][7] -= 55;
		}
		else if (argv[2][7] >= 97 && argv[2][7] <= 102)
		{
			argv[2][7] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		if (argv[2][8] >= 48 && argv[2][8] <= 57)
		{
			argv[2][8] -= 48;
		}
		else if (argv[2][8] >= 65 && argv[2][8] <= 70)
		{
			argv[2][8] -= 55;
		}
		else if (argv[2][8] >= 97 && argv[2][8] <= 102)
		{
			argv[2][8] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		if (argv[2][9] >= 48 && argv[2][9] <= 57)
		{
			argv[2][9] -= 48;
		}
		else if (argv[2][9] >= 65 && argv[2][9] <= 70)
		{
			argv[2][9] -= 55;
		}
		else if (argv[2][9] >= 97 && argv[2][9] <= 102)
		{
			argv[2][9] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		if (argv[2][10] >= 48 && argv[2][10] <= 57)
		{
			argv[2][10] -= 48;
		}
		else if (argv[2][10] >= 65 && argv[2][10] <= 70)
		{
			argv[2][10] -= 55;
		}
		else if (argv[2][10] >= 97 && argv[2][10] <= 102)
		{
			argv[2][10] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		if (argv[2][11] >= 48 && argv[2][11] <= 57)
		{
			argv[2][11] -= 48;
		}
		else if (argv[2][11] >= 65 && argv[2][11] <= 70)
		{
			argv[2][11] -= 55;
		}
		else if (argv[2][11] >= 97 && argv[2][11] <= 102)
		{
			argv[2][11] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		if (argv[2][12] >= 48 && argv[2][12] <= 57)
		{
			argv[2][12] -= 48;
		}
		else if (argv[2][12] >= 65 && argv[2][12] <= 70)
		{
			argv[2][12] -= 55;
		}
		else if (argv[2][12] >= 97 && argv[2][12] <= 102)
		{
			argv[2][12] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		if (argv[2][13] >= 48 && argv[2][13] <= 57)
		{
			argv[2][13] -= 48;
		}
		else if (argv[2][13] >= 65 && argv[2][13] <= 70)
		{
			argv[2][13] -= 55;
		}
		else if (argv[2][13] >= 97 && argv[2][13] <= 102)
		{
			argv[2][13] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		if (argv[2][14] >= 48 && argv[2][14] <= 57)
		{
			argv[2][14] -= 48;
		}
		else if (argv[2][14] >= 65 && argv[2][14] <= 70)
		{
			argv[2][14] -= 55;
		}
		else if (argv[2][14] >= 97 && argv[2][14] <= 102)
		{
			argv[2][14] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		if (argv[2][15] >= 48 && argv[2][15] <= 57)
		{
			argv[2][15] -= 48;
		}
		else if (argv[2][15] >= 65 && argv[2][15] <= 70)
		{
			argv[2][15] -= 55;
		}
		else if (argv[2][15] >= 97 && argv[2][15] <= 102)
		{
			argv[2][15] -= 87;
		}
		else errorWithMessage("Not a valid char value.");

		//now that we have them all in hex values we will put them into the key
		key |= (((uint64_t)argv[2][0] << 60) & 0xF000000000000000)
			| (((uint64_t)argv[2][1] << 56) & 0x0F00000000000000)
			| (((uint64_t)argv[2][2] << 52) & 0x00F0000000000000)
			| (((uint64_t)argv[2][3] << 48) & 0x000F000000000000)
			| (((uint64_t)argv[2][4] << 44) & 0x0000F00000000000)
			| (((uint64_t)argv[2][5] << 40) & 0x00000F0000000000)
			| (((uint64_t)argv[2][6] << 36) & 0x000000F000000000)
			| (((uint64_t)argv[2][7] << 32) & 0x0000000F00000000)
			| (((uint64_t)argv[2][8] << 28) & 0x00000000F0000000)
			| (((uint64_t)argv[2][9] << 24) & 0x000000000F000000)
			| (((uint64_t)argv[2][10] << 20) & 0x0000000000F00000)
			| (((uint64_t)argv[2][11] << 16) & 0x00000000000F0000)
			| (((uint64_t)argv[2][12] << 12) & 0x000000000000F000)
			| (((uint64_t)argv[2][13] << 8) & 0x0000000000000F00)
			| (((uint64_t)argv[2][14] << 4) & 0x00000000000000F0)
			| (((uint64_t)argv[2][15]) & 0x000000000000000F);
	}

	//Weak keys and checking against them
	uint64_t weakKey1 = 0x0000000000000000;
	uint64_t weakKey2 = 0xFFFFFFFFFFFFFFFF;
	uint64_t weakKey3 = 0xFFFFFFFF00000000;
	uint64_t weakKey4 = 0x00000000FFFFFFFF;
	if (key == weakKey1 || key == weakKey2 || key == weakKey3 || key == weakKey4)
	{
		errorWithMessage("This is a weak key. Try again");
	}

	//17 because k_0 is the first permuted key from the original
	// the remaining 16 are for the 16 rounds

	//This part compresses the key into k_0
	if (key & (1ULL << 63)) keys[0] |= (1ULL << (56 - 8)); //bit 1
	if (key & (1ULL << 62)) keys[0] |= (1ULL << (56 - 16));  //bit 2
	if (key & (1ULL << 61)) keys[0] |= (1ULL << (56 - 24)); //bit 3
	if (key & (1ULL << 60)) keys[0] |= (1ULL << (56 - 56)); //bit 4
	if (key & (1ULL << 59)) keys[0] |= (1ULL << (56 - 52)); //bit 5
	if (key & (1ULL << 58)) keys[0] |= (1ULL << (56 - 44)); //bit 6
	if (key & (1ULL << 57)) keys[0] |= (1ULL << (56 - 36)); //bit 7
															//if (key & (1ULL << 56)) key |= (1ULL << (56 - 32)); //bit 8
	if (key & (1ULL << 55)) keys[0] |= (1ULL << (56 - 7)); //bit 9
	if (key & (1ULL << 54)) keys[0] |= (1ULL << (56 - 15)); //bit 10
	if (key & (1ULL << 53)) keys[0] |= (1ULL << (56 - 23)); //bit 11
	if (key & (1ULL << 52)) keys[0] |= (1ULL << (56 - 55)); //bit 12
	if (key & (1ULL << 51)) keys[0] |= (1ULL << (56 - 51)); //bit 13
	if (key & (1ULL << 50)) keys[0] |= (1ULL << (56 - 43)); //bit 14
	if (key & (1ULL << 49)) keys[0] |= (1ULL << (56 - 35)); //bit 15
															//if (key & (1ULL << 48)) key |= (1ULL << (56 - 31)); //bit 16
	if (key & (1ULL << 47)) keys[0] |= (1ULL << (56 - 6)); //bit 17
	if (key & (1ULL << 46)) keys[0] |= (1ULL << (56 - 14)); //bit 18
	if (key & (1ULL << 45)) keys[0] |= (1ULL << (56 - 22)); //bit 19
	if (key & (1ULL << 44)) keys[0] |= (1ULL << (56 - 54)); //bit 20
	if (key & (1ULL << 43)) keys[0] |= (1ULL << (56 - 50)); //bit 21
	if (key & (1ULL << 42)) keys[0] |= (1ULL << (56 - 42)); //bit 22
	if (key & (1ULL << 41)) keys[0] |= (1ULL << (56 - 34)); //bit 23
															//if (key & (1ULL << 40)) key |= (1ULL << (56 - 30)); //bit 24
	if (key & (1ULL << 39)) keys[0] |= (1ULL << (56 - 5)); //bit 25
	if (key & (1ULL << 38)) keys[0] |= (1ULL << (56 - 13)); //bit 26
	if (key & (1ULL << 37)) keys[0] |= (1ULL << (56 - 21)); //bit 27
	if (key & (1ULL << 36)) keys[0] |= (1ULL << (56 - 53)); //bit 28
	if (key & (1ULL << 35)) keys[0] |= (1ULL << (56 - 49)); //bit 29
	if (key & (1ULL << 34)) keys[0] |= (1ULL << (56 - 41)); //bit 30
	if (key & (1ULL << 33)) keys[0] |= (1ULL << (56 - 33)); //bit 31
															//if (key & (1ULL << 32)) key |= (1ULL << (56 - 29)); //bit 32
	if (key & (1ULL << 31)) keys[0] |= (1ULL << (56 - 4)); //bit 33
	if (key & (1ULL << 30)) keys[0] |= (1ULL << (56 - 12)); //bit 34
	if (key & (1ULL << 29)) keys[0] |= (1ULL << (56 - 20)); //bit 35
	if (key & (1ULL << 28)) keys[0] |= (1ULL << (56 - 28)); //bit 36
	if (key & (1ULL << 27)) keys[0] |= (1ULL << (56 - 48)); //bit 37
	if (key & (1ULL << 26)) keys[0] |= (1ULL << (56 - 40)); //bit 38
	if (key & (1ULL << 25)) keys[0] |= (1ULL << (56 - 32)); //bit 39
															//if (key & (1ULL << 24)) key |= (1ULL << (56 - 28)); //bit 40
	if (key & (1ULL << 23)) keys[0] |= (1ULL << (56 - 3)); //bit 41
	if (key & (1ULL << 22)) keys[0] |= (1ULL << (56 - 11)); //bit 42
	if (key & (1ULL << 21)) keys[0] |= (1ULL << (56 - 19)); //bit 43
	if (key & (1ULL << 20)) keys[0] |= (1ULL << (56 - 27)); //bit 44
	if (key & (1ULL << 19)) keys[0] |= (1ULL << (56 - 47)); //bit 45
	if (key & (1ULL << 18)) keys[0] |= (1ULL << (56 - 39)); //bit 46
	if (key & (1ULL << 17)) keys[0] |= (1ULL << (56 - 31)); //bit 47
															//if (key & (1ULL << 16)) key |= (1ULL << (56 - 27)); //bit 48
	if (key & (1ULL << 15)) keys[0] |= (1ULL << (56 - 2)); //bit 49
	if (key & (1ULL << 14)) keys[0] |= (1ULL << (56 - 10)); //bit 50
	if (key & (1ULL << 13)) keys[0] |= (1ULL << (56 - 18)); //bit 51
	if (key & (1ULL << 12)) keys[0] |= (1ULL << (56 - 26)); //bit 52
	if (key & (1ULL << 11)) keys[0] |= (1ULL << (56 - 46)); //bit 53
	if (key & (1ULL << 10)) keys[0] |= (1ULL << (56 - 38)); //bit 54
	if (key & (1ULL << 9))  keys[0] |= (1ULL << (56 - 30)); //bit 55
															//if (key & (1ULL << 8))  key |= (1ULL << (56 - 26)); //bit 56
	if (key & (1ULL << 7))  keys[0] |= (1ULL << (56 - 1)); //bit 57
	if (key & (1ULL << 6))  keys[0] |= (1ULL << (56 - 9));  //bit 58
	if (key & (1ULL << 5))  keys[0] |= (1ULL << (56 - 17)); //bit 59
	if (key & (1ULL << 4))  keys[0] |= (1ULL << (56 - 25)); //bit 60
	if (key & (1ULL << 3))  keys[0] |= (1ULL << (56 - 45)); //bit 61
	if (key & (1ULL << 2))  keys[0] |= (1ULL << (56 - 37)); //bit 62
	if (key & (1ULL << 1))  keys[0] |= (1ULL << (56 - 29)); //bit 63
															//if (key & (1ULL << 0))  key |= (1ULL << (56 - 25)); //bit 64

	//We want to compute the 16 keys that we will use for encrypting/decrypting
	//ROUNDS 1,2,9,16 rotate 1 bit
	//ROUNDS 3,4,5,6,7,8,10,11,12,13,14,15 all rotate 2 bits
	keys[1] = rotateBits(keys[0], 1);
	keys[2] = rotateBits(keys[1], 2);
	keys[3] = rotateBits(keys[2], 3);
	keys[4] = rotateBits(keys[3], 4);
	keys[5] = rotateBits(keys[4], 5);
	keys[6] = rotateBits(keys[5], 6);
	keys[7] = rotateBits(keys[6], 7);
	keys[8] = rotateBits(keys[7], 8);
	keys[9] = rotateBits(keys[8], 9);
	keys[10] = rotateBits(keys[9], 10);
	keys[11] = rotateBits(keys[10], 11);
	keys[12] = rotateBits(keys[11], 12);
	keys[13] = rotateBits(keys[12], 13);
	keys[14] = rotateBits(keys[13], 14);
	keys[15] = rotateBits(keys[14], 15);
	keys[16] = rotateBits(keys[15], 16);

	//After getting the 16 keys, we need to convert them into the permuted 48 bit keys
	// that we actually use in the rounds. Just overwriting the 56bit keys and making sure
	// the top 16 bits are cleared.
	keys[1] = compressPermuteKey(keys[1]) & 0x0000FFFFFFFFFFFF;
	keys[2] = compressPermuteKey(keys[2]) & 0x0000FFFFFFFFFFFF;
	keys[3] = compressPermuteKey(keys[3]) & 0x0000FFFFFFFFFFFF;
	keys[4] = compressPermuteKey(keys[4]) & 0x0000FFFFFFFFFFFF;
	keys[5] = compressPermuteKey(keys[5]) & 0x0000FFFFFFFFFFFF;
	keys[6] = compressPermuteKey(keys[6]) & 0x0000FFFFFFFFFFFF;
	keys[7] = compressPermuteKey(keys[7]) & 0x0000FFFFFFFFFFFF;
	keys[8] = compressPermuteKey(keys[8]) & 0x0000FFFFFFFFFFFF;
	keys[9] = compressPermuteKey(keys[9]) & 0x0000FFFFFFFFFFFF;
	keys[10] = compressPermuteKey(keys[10]) & 0x0000FFFFFFFFFFFF;
	keys[11] = compressPermuteKey(keys[11]) & 0x0000FFFFFFFFFFFF;
	keys[12] = compressPermuteKey(keys[12]) & 0x0000FFFFFFFFFFFF;
	keys[13] = compressPermuteKey(keys[13]) & 0x0000FFFFFFFFFFFF;
	keys[14] = compressPermuteKey(keys[14]) & 0x0000FFFFFFFFFFFF;
	keys[15] = compressPermuteKey(keys[15]) & 0x0000FFFFFFFFFFFF;
	keys[16] = compressPermuteKey(keys[16]) & 0x0000FFFFFFFFFFFF;

	//get the filesize before going into working on the files



	uint32_t fileSize = (uint32_t)inFile.tellg(); //starting position
	int bytesToPad = 0;
	inFile.seekg(0, ios::end); //put pointer at end of file
	fileSize = (uint32_t)inFile.tellg() - fileSize; //use the difference for file size
	inFile.seekg(0, ios::beg);//move the pointer back to the beggining of the file

	if (fileSize % 8 != 0)
	{
		//we will need to pad bytes on if the length is not a perfect multiple of 8
		bytesToPad = 8 - (fileSize % 8);
	}

	//now that we have our keys and file size, we need to see if we're encoding or decoding 
	//essentially everything else will happen inside one of these cases
	if (strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-E") == 0)
	{
		//Here we need to push the first part of the message through (the length)
		//The first 33 bits will be random garbage followed by the final 31 'good' bits
		srand((unsigned)time(0));
		uint64_t randomGarb = (uint16_t)rand();		//casting to 16 bits so the max is 
		randomGarb = randomGarb * (uint16_t)rand(); //less than 32 bits after the mul
		randomGarb = (randomGarb << 32); //clearing out the space for the filesize
		randomGarb += (uint64_t)fileSize;

		//now we have the first 8bytes of the output file that we need to encrypt
		// initial permutation
		randomGarb = permutation1(randomGarb);

		//The 16 Feistel rounds
		randomGarb = runIt(randomGarb, 1);
		randomGarb = runIt(randomGarb, 2);
		randomGarb = runIt(randomGarb, 3);
		randomGarb = runIt(randomGarb, 4);
		randomGarb = runIt(randomGarb, 5);
		randomGarb = runIt(randomGarb, 6);
		randomGarb = runIt(randomGarb, 7);
		randomGarb = runIt(randomGarb, 8);
		randomGarb = runIt(randomGarb, 9);
		randomGarb = runIt(randomGarb, 10);
		randomGarb = runIt(randomGarb, 11);
		randomGarb = runIt(randomGarb, 12);
		randomGarb = runIt(randomGarb, 13);
		randomGarb = runIt(randomGarb, 14);
		randomGarb = runIt(randomGarb, 15);
		randomGarb = runIt(randomGarb, 16);

		uint64_t right = randomGarb & 0x00000000FFFFFFFF;

		//the last swap after the 16th round
		randomGarb = (randomGarb >> 32) | (right << 32);
		//final permutation before putting it in the output file
		randomGarb = finalPermutation(randomGarb);

		char fSizeOut[9] = { 0 };
		convertToChar(randomGarb, fSizeOut);

		outFile.write(fSizeOut, 8);
		outFile.flush();

		int bytesRead = 0;
		char in[9] = { 0 };

		while ((fileSize - bytesRead) >= 8)
		{
			inFile.read(in, 8);
			bytesRead += 8;

			uint64_t y = 0;
			y |= (((uint64_t)in[0] << 56) & 0xFF00000000000000)
				| (((uint64_t)in[1] << 48) & 0x00FF000000000000)
				| (((uint64_t)in[2] << 40) & 0x0000FF0000000000)
				| (((uint64_t)in[3] << 32) & 0x000000FF00000000)
				| (((uint64_t)in[4] << 24) & 0x00000000FF000000)
				| (((uint64_t)in[5] << 16) & 0x0000000000FF0000)
				| (((uint64_t)in[6] << 8) & 0x000000000000FF00)
				| (((uint64_t)in[7]) & 0x00000000000000FF);

			y = permutation1(y);

			//The 16 Feistel rounds
			y = runIt(y, 1);
			y = runIt(y, 2);
			y = runIt(y, 3);
			y = runIt(y, 4);
			y = runIt(y, 5);
			y = runIt(y, 6);
			y = runIt(y, 7);
			y = runIt(y, 8);
			y = runIt(y, 9);
			y = runIt(y, 10);
			y = runIt(y, 11);
			y = runIt(y, 12);
			y = runIt(y, 13);
			y = runIt(y, 14);
			y = runIt(y, 15);
			y = runIt(y, 16);

			right = y & 0x00000000FFFFFFFF;

			//the last swap after the 16th round
			y = (y >> 32) | (right << 32);

			y = finalPermutation(y);
			char a[9] = { 0 };
			convertToChar(y, a);
			outFile.write(a, 8);
			outFile.flush();
		}
		if ((fileSize - bytesRead) > 0)
		{
			int bytesToFill = (fileSize % 8);
			inFile.read(in, fileSize - bytesRead);
			while (bytesToFill < 8)
			{
				in[bytesToFill++] = (rand() % 256); //trying to get a random character to finish out the last string
			}

			uint64_t y = 0;
			y |= (((uint64_t)in[0] << 56) & 0xFF00000000000000)
				| (((uint64_t)in[1] << 48) & 0x00FF000000000000)
				| (((uint64_t)in[2] << 40) & 0x0000FF0000000000)
				| (((uint64_t)in[3] << 32) & 0x000000FF00000000)
				| (((uint64_t)in[4] << 24) & 0x00000000FF000000)
				| (((uint64_t)in[5] << 16) & 0x0000000000FF0000)
				| (((uint64_t)in[6] << 8) & 0x000000000000FF00)
				| (((uint64_t)in[7]) & 0x00000000000000FF);

			y = permutation1(y);

			//The 16 Feistel rounds
			y = runIt(y, 1);
			y = runIt(y, 2);
			y = runIt(y, 3);
			y = runIt(y, 4);
			y = runIt(y, 5);
			y = runIt(y, 6);
			y = runIt(y, 7);
			y = runIt(y, 8);
			y = runIt(y, 9);
			y = runIt(y, 10);
			y = runIt(y, 11);
			y = runIt(y, 12);
			y = runIt(y, 13);
			y = runIt(y, 14);
			y = runIt(y, 15);
			y = runIt(y, 16);

			uint64_t right = y & 0x00000000FFFFFFFF;

			//the last swap after the 16th round
			y = (y >> 32) | (right << 32);

			y = finalPermutation(y);
			char a[9] = { 0 };
			convertToChar(y, a);
			outFile.write(a, 8);
			outFile.flush();
		}
	}
	else //decoding
	{
		int bytesRead = 0;
		char in[9] = { 0 };
		char a[9] = { 0 };
		inFile.read(in, 8);
		bytesRead += 8;

		//convert the characters to a uint64_t
		uint64_t y = 0;
		y |= (((uint64_t)in[0] << 56) & 0xFF00000000000000)
			| (((uint64_t)in[1] << 48) & 0x00FF000000000000)
			| (((uint64_t)in[2] << 40) & 0x0000FF0000000000)
			| (((uint64_t)in[3] << 32) & 0x000000FF00000000)
			| (((uint64_t)in[4] << 24) & 0x00000000FF000000)
			| (((uint64_t)in[5] << 16) & 0x0000000000FF0000)
			| (((uint64_t)in[6] << 8) & 0x000000000000FF00)
			| (((uint64_t)in[7]) & 0x00000000000000FF);


		y = permutation1(y);

		//The 16 Feistel rounds
		y = runIt(y, 16);
		y = runIt(y, 15);
		y = runIt(y, 14);
		y = runIt(y, 13);
		y = runIt(y, 12);
		y = runIt(y, 11);
		y = runIt(y, 10);
		y = runIt(y, 9);
		y = runIt(y, 8);
		y = runIt(y, 7);
		y = runIt(y, 6);
		y = runIt(y, 5);
		y = runIt(y, 4);
		y = runIt(y, 3);
		y = runIt(y, 2);
		y = runIt(y, 1);

		uint64_t right = y & 0x00000000FFFFFFFF;

		//the last swap after the last round
		y = (y >> 32) | (right << 32);

		y = finalPermutation(y);

		uint64_t realFileSize = y & 0x000000007FFFFFFF;

		cout << realFileSize << " is the decrypted filesize" << endl;

		//Here we have a file that was originally 0-8 bytes long
		if (fileSize == 16)
		{
			inFile.read(in, 8);
			bytesRead += 8;

			uint64_t y = 0;
			y |= (((uint64_t)in[0] << 56) & 0xFF00000000000000)
				| (((uint64_t)in[1] << 48) & 0x00FF000000000000)
				| (((uint64_t)in[2] << 40) & 0x0000FF0000000000)
				| (((uint64_t)in[3] << 32) & 0x000000FF00000000)
				| (((uint64_t)in[4] << 24) & 0x00000000FF000000)
				| (((uint64_t)in[5] << 16) & 0x0000000000FF0000)
				| (((uint64_t)in[6] << 8) & 0x000000000000FF00)
				| (((uint64_t)in[7]) & 0x00000000000000FF);

			y = permutation1(y);

			//The 16 Feistel rounds
			y = runIt(y, 16);
			y = runIt(y, 15);
			y = runIt(y, 14);
			y = runIt(y, 13);
			y = runIt(y, 12);
			y = runIt(y, 11);
			y = runIt(y, 10);
			y = runIt(y, 9);
			y = runIt(y, 8);
			y = runIt(y, 7);
			y = runIt(y, 6);
			y = runIt(y, 5);
			y = runIt(y, 4);
			y = runIt(y, 3);
			y = runIt(y, 2);
			y = runIt(y, 1);

			uint64_t right = y & 0x00000000FFFFFFFF;

			//the last swap after the last round
			y = (y >> 32) | (right << 32);

			y = finalPermutation(y);

			convertToChar(y, a);

			outFile.write(a, realFileSize);
			outFile.flush();
		}
		else
		{
			while (((int32_t)fileSize - bytesRead - (realFileSize%8)) >= 8)
			{
				inFile.read(in, 8);
				bytesRead += 8;

				uint64_t y = 0;
				y |= (((uint64_t)in[0] << 56) & 0xFF00000000000000)
					| (((uint64_t)in[1] << 48) & 0x00FF000000000000)
					| (((uint64_t)in[2] << 40) & 0x0000FF0000000000)
					| (((uint64_t)in[3] << 32) & 0x000000FF00000000)
					| (((uint64_t)in[4] << 24) & 0x00000000FF000000)
					| (((uint64_t)in[5] << 16) & 0x0000000000FF0000)
					| (((uint64_t)in[6] << 8) & 0x000000000000FF00)
					| (((uint64_t)in[7]) & 0x00000000000000FF);

				y = permutation1(y);

				//The 16 Feistel rounds
				y = runIt(y, 16);
				y = runIt(y, 15);
				y = runIt(y, 14);
				y = runIt(y, 13);
				y = runIt(y, 12);
				y = runIt(y, 11);
				y = runIt(y, 10);
				y = runIt(y, 9);
				y = runIt(y, 8);
				y = runIt(y, 7);
				y = runIt(y, 6);
				y = runIt(y, 5);
				y = runIt(y, 4);
				y = runIt(y, 3);
				y = runIt(y, 2);
				y = runIt(y, 1);

				uint64_t right = y & 0x00000000FFFFFFFF;

				//the last swap after the last round
				y = (y >> 32) | (right << 32);

				y = finalPermutation(y);

				convertToChar(y, a);
				outFile.write(a, 8);
				outFile.flush();
			}
			if (realFileSize % 8 != 0) //we still have another block to read in with only partially important data
			{
				inFile.read(in, 8);
				bytesRead += 8;

				uint64_t y = 0;
				y |= (((uint64_t)in[0] << 56) & 0xFF00000000000000)
					| (((uint64_t)in[1] << 48) & 0x00FF000000000000)
					| (((uint64_t)in[2] << 40) & 0x0000FF0000000000)
					| (((uint64_t)in[3] << 32) & 0x000000FF00000000)
					| (((uint64_t)in[4] << 24) & 0x00000000FF000000)
					| (((uint64_t)in[5] << 16) & 0x0000000000FF0000)
					| (((uint64_t)in[6] << 8) & 0x000000000000FF00)
					| (((uint64_t)in[7]) & 0x00000000000000FF);

				y = permutation1(y);

				//The 16 Feistel rounds
				y = runIt(y, 16);
				y = runIt(y, 15);
				y = runIt(y, 14);
				y = runIt(y, 13);
				y = runIt(y, 12);
				y = runIt(y, 11);
				y = runIt(y, 10);
				y = runIt(y, 9);
				y = runIt(y, 8);
				y = runIt(y, 7);
				y = runIt(y, 6);
				y = runIt(y, 5);
				y = runIt(y, 4);
				y = runIt(y, 3);
				y = runIt(y, 2);
				y = runIt(y, 1);

				uint64_t right = y & 0x00000000FFFFFFFF;

				//the last swap after the last round
				y = (y >> 32) | (right << 32);

				y = finalPermutation(y);

				convertToChar(y, a);
				outFile.write(a, (realFileSize%8));
				outFile.flush();
			}
		}
	}

	inFile.close();
	outFile.close();

	//end timer
	duration = (clock() - start) / (double)CLOCKS_PER_SEC;
	cout << "Total time: " << duration << "s" << endl;
	return 0;
}