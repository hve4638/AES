#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "aes.h"
#define timeron TimeStart = clock();
#define timeroff TimeFinish = clock(); \
	printf("time : %x\n", (double)(TimeFinish - TimeStart) / CLOCKS_PER_SEC);

clock_t TimeStart, TimeFinish;
void XOR16Bytes(u8[16], u8[16]);

void ECB_Encryption(char*, char*, u32[]);
void CBC_Encryption(char*, char*, u32[]);
void ECB_Decryption(char*, char*, u32[]);
void CBC_Decryption(char*, char*, u32[]);


void XOR16Bytes(u8 S[16], u8 RK[16])
{
	S[0] ^= RK[0];
	S[1] ^= RK[1];
	S[2] ^= RK[2];
	S[3] ^= RK[3];
	S[4] ^= RK[4];
	S[5] ^= RK[5];
	S[6] ^= RK[6];
	S[7] ^= RK[7];
	S[8] ^= RK[8];
	S[9] ^= RK[9];
	S[10] ^= RK[10];
	S[11] ^= RK[11];
	S[12] ^= RK[12];
	S[13] ^= RK[13];
	S[14] ^= RK[14];
	S[15] ^= RK[15];
}

void ECB_Encryption(char* inputfile, char* outputfile, u32 W[])
{
	FILE* rfp, * wfp;
	u8* inputbuf, * outputbuf, r;
	u32 DataLen;
	int i;

	fopen_s(&rfp, inputfile, "rb");
	if (rfp == NULL)
		perror("fopen_s 실패! (input)\n");
	fseek(rfp, 0, SEEK_END);
	DataLen = ftell(rfp);
	fseek(rfp, 0, SEEK_SET);

	r = 16 - DataLen % 16; //PKCS #7 Padding

	inputbuf = calloc(DataLen + r, sizeof(u8));
	outputbuf = calloc(DataLen + r, sizeof(u8));
	fread(inputbuf, 1, DataLen, rfp);
	fclose(rfp);

	memset(inputbuf + DataLen, r, r);

	for (i = 0; i < (DataLen + r) / 16; i++)
	{
		AES_ENC_Optimization(inputbuf + 16 * i, W, outputbuf + 16 * i, 128);
	}

	fopen_s(&wfp, outputfile, "wb");
	if (wfp == NULL)
		perror("fopen_s 실패! (output)\n");
	fwrite(outputbuf, 1, DataLen + r, wfp);

	fclose(wfp);
	
}
void CBC_Encryption(char* inputfile, char* outputfile, u32 W[])
{
	FILE* rfp, * wfp;
	u8* inputbuf, * outputbuf, r;
	u32 DataLen;
	u8 IV[16] = { 0x00 };
	int i;

	fopen_s(&rfp, inputfile, "rb");
	if (rfp == NULL)
		perror("fopen_s 실패! (input)\n");
	fseek(rfp, 0, SEEK_END);
	DataLen = ftell(rfp);
	fseek(rfp, 0, SEEK_SET); 

	r = 16 - DataLen % 16; //PKCS #7 Padding

	inputbuf = calloc(DataLen + r, sizeof(u8));
	outputbuf = calloc(DataLen + r, sizeof(u8));
	fread(inputbuf, 1, DataLen, rfp);
	fclose(rfp);

	memset(inputbuf + DataLen, r, r);

	XOR16Bytes(inputbuf, IV);
	AES_ENC_Optimization(inputbuf, W, outputbuf, 128);

	for (i = 1; i < (DataLen + r) / 16; i++)
	{
		XOR16Bytes(inputbuf + 16 * i, outputbuf + 16 * (i-1));
		AES_ENC_Optimization(inputbuf + 16 * i, W, outputbuf + 16 * i, 128);
	}

	fopen_s(&wfp, outputfile, "wb");
	if (wfp == NULL)
		perror("fopen_s 실패! (output)\n");
	fwrite(outputbuf, 1, DataLen + r, wfp);

	fclose(wfp);
}

void ECB_Decryption(char* inputfile, char* outputfile, u32 W[])
{
	FILE* rfp, * wfp;
	u8* inputbuf, * outputbuf, r;
	u32 DataLen;
	int i, bpd;

	fopen_s(&rfp, inputfile, "rb");
	if (rfp == NULL)
		perror("fopen_s 실패! (input)\n");
	fseek(rfp, 0, SEEK_END);
	DataLen = ftell(rfp);
	fseek(rfp, 0, SEEK_SET);

	inputbuf = calloc(DataLen, sizeof(u8));
	outputbuf = calloc(DataLen, sizeof(u8));
	fread(inputbuf, 1, DataLen, rfp);
	fclose(rfp);

	for(i = 0; i < DataLen / 16; i++)
		AES_DEC_Optimization(inputbuf + 16 * i, W, outputbuf + 16 * i, 128);
	
	bpd = 1;
	r = outputbuf[DataLen - 1];
	for(i = DataLen - 2; DataLen - r <= i; i--)
	{
		if (outputbuf[i] != r)
		{
			bpd = 0;
			break;
		}
	}
	fopen_s(&wfp, outputfile, "wb");
	if (wfp == NULL)
		perror("fopen_s 실패! (output)\n");
	
	if (bpd)
		fwrite(outputbuf, 1, DataLen - r, wfp);
	else
		fwrite(outputbuf, 1, DataLen, wfp);
	
	fclose(wfp);
	
}
void CBC_Decryption(char* inputfile, char* outputfile, u32 W[])
{
	FILE* rfp, * wfp;
	u8* inputbuf, * outputbuf, r;
	u32 DataLen;
	u8 IV[16] = { 0x00 };
	int i, bpd;

	fopen_s(&rfp, inputfile, "rb");
	if (rfp == NULL)
		perror("fopen_s 실패! (input)\n");
	fseek(rfp, 0, SEEK_END);
	DataLen = ftell(rfp);
	fseek(rfp, 0, SEEK_SET);

	inputbuf = calloc(DataLen, sizeof(u8));
	outputbuf = calloc(DataLen, sizeof(u8));
	fread(inputbuf, 1, DataLen, rfp);
	fclose(rfp);

	AES_DEC_Optimization(inputbuf, W, outputbuf, 128);
	XOR16Bytes(outputbuf, IV);

	for (i = 1; i < (DataLen) / 16; i++)
	{
		AES_DEC_Optimization(inputbuf + 16 * i, W, outputbuf + 16 * i, 128);
		XOR16Bytes(outputbuf + 16 * i, inputbuf + 16 * (i - 1));
	}

	bpd = 1;
	r = outputbuf[DataLen - 1];
	for (i = DataLen - 2; DataLen - r <= i; i--)
	{
		if (outputbuf[i] != r)
		{
			bpd = 0;
			break;
		}
	}
	fopen_s(&wfp, outputfile, "wb");
	if (wfp == NULL)
		perror("fopen_s 실패! (output)\n");

	if (bpd)
		fwrite(outputbuf, 1, DataLen - r, wfp);
	else
		fwrite(outputbuf, 1, DataLen, wfp);

	fclose(wfp);
}

int main(int argc, char* argv[])
{
	u8 ENCKEY[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	int keysize = 128;
	u32 W[60];

	if (strcmp(argv[1], "ecb") == 0)
	{
		printf("AES Encryption progress...\n");
		AES_KeySchedule_Optimization(ENCKEY, W, keysize);
		ECB_Encryption(argv[2], argv[3], W);
	}
	else if (strcmp(argv[1], "cbc") == 0)
	{
		printf("AES Encryption progress...\n");
		AES_KeySchedule_Optimization(ENCKEY, W, keysize);
		CBC_Encryption(argv[2], argv[3], W);
	}
	else if (strcmp(argv[1], "decb") == 0)
	{
		printf("AES Decryption progress...\n");
		AES_KeySchedule_Optimization(ENCKEY, W, keysize);
		ECB_Decryption(argv[2], argv[3], W);
	}
	else if (strcmp(argv[1], "dcbc") == 0)
	{
		printf("AES Decryption progress...\n");
		AES_KeySchedule_Optimization(ENCKEY, W, keysize);
		CBC_Decryption(argv[2], argv[3], W);
	}
	return 0;
}



/*
AES_DEC(CT, RK, DT, keysize);
AES_DEC_Optimization(CT, W, DT2, keysize);

printf("PT : "); print16(PT, 16); printf("\n");
printf("CT : "); print16(CT, 16); printf("\n");
printf("DEC: "); print16(DT, 16); printf("\n");
printf("DEC: "); print16(DT2, 16); printf("\n");


st = clock();
for (i = 0; i < 10000; i++)
	AES_DEC(CT, RK, CT, keysize);
fn = clock();
printf("DES    : %f\n", (double)(fn - st) / CLOCKS_PER_SEC);

st = clock();
for (i = 0; i < 10000; i++)
	AES_DEC_Optimization(CT, W, CT, keysize);
fn = clock();
printf("DES_Op : %f", (double)(fn - st) / CLOCKS_PER_SEC);


*/