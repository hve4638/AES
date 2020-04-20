#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "aes.h"
#define EncCalculateT(i) \
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[i];	\
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[i+1];	\
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[i+2];	\
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[i+3];
#define EncCalculateS(i) \
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[i];	\
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[i+1];	\
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[i+2];	\
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[i+3];
#define EncCalculateLast(i) \
	s0 = (Te2[(t0 >> 24)] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t3 & 0xff] & 0x000000ff) ^ W[i];		\
	s1 = (Te2[(t1 >> 24)] & 0xff000000) ^ (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t0 & 0xff] & 0x000000ff) ^ W[i+1];	\
	s2 = (Te2[(t2 >> 24)] & 0xff000000) ^ (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t1 & 0xff] & 0x000000ff) ^ W[i+2];	\
	s3 = (Te2[(t3 >> 24)] & 0xff000000) ^ (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t2 & 0xff] & 0x000000ff) ^ W[i+3];

#define DecCalculateT(i) \
	t0 = Td0[s0 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ W[i];		\
	t1 = Td0[s3 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ W[i + 1];	\
	t2 = Td0[s2 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ W[i + 2];	\
	t3 = Td0[s1 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ W[i + 3];
#define DecCalculateS(i) \
	s0 = Td0[t0 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ W[i];		\
	s1 = Td0[t3 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ W[i + 1];	\
	s2 = Td0[t2 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ W[i + 2];	\
	s3 = Td0[t1 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ W[i + 3];
#pragma region
void RoundKeyGeneration128(u8[], u8[]);
void AES_KeySchedule(u8[], u8[], int);

void AES_ENC(u8[16], u8[], u8[], int);
void AES_ENC_Optimization(u8[16], u32[], u8[16], int);
void RoundKeyGeneration128_Optimization(u8[], u32[]);
void AES_KeySchedule_Optimization(u8[], u32[], int);

void AES_DEC(u8[16], u8[], u8[], int);
void AES_DNC_Optimization(u8[16], u32[], u8[16], int);

void print16(u8*, int);
void print32(u32*, int);
void print16(u8* arr, int size)
{
	int i;
	for (i = 0; i < size; i++)
		printf("%02x ", arr[i]);
}
void print32(u32* arr, int size)
{
	int i;
	u8 x[4];

	for (i = 0; i < size; i++)
	{
		u4byte_out(x, arr[i]);
		printf("%02x%02x%02x%02x ", x[0], x[1], x[2], x[3]);
	}
}
#pragma endregion 

#pragma region
void AES_KeyWordToByte(u32 W[], u8 RK[])
{
	int i;
	for (i = 0; i < 44; i++)
		u4byte_out(RK + 4 * i, W[i]);
}
void AES_KeySchedule(u8 MK[], u8 RK[], int keysize)
{
	if (keysize == 128)
		RoundKeyGeneration128(MK, RK);
}
void RoundKeyGeneration128(u8 MK[], u8 RK[])
{
	int i;
	u32 W[44];
	u32 T;

	W[0] = u4byte_in(MK);
	W[1] = u4byte_in(MK + 4);
	W[2] = u4byte_in(MK + 8);
	W[3] = u4byte_in(MK + 12);

	for (i = 0; i < 10; i++)
	{
		T = W[4 * i + 3];
		T = RotWord(T);
		T = SubWord(T);
		T ^= Rcons[i];

		W[4 * i + 4] = W[4 * i] ^ T;
		W[4 * i + 5] = W[4 * i + 1] ^ W[4 * i + 4];
		W[4 * i + 6] = W[4 * i + 2] ^ W[4 * i + 5];
		W[4 * i + 7] = W[4 * i + 3] ^ W[4 * i + 6];
	}
	AES_KeyWordToByte(W, RK);
}
void AES_ENC(u8 PT[16], u8 RK[], u8 CT[], int keysize)
{
	int i;
	int Nr = keysize / 32 + 6;
	u8 temp[16];
	copyarray(temp, PT);

	AddRoundKey(temp, RK);

	for (i = 0; i < Nr - 1; i++)
	{
		SubBytes(temp);
		ShiftRows(temp);
		MixColumns(temp);
		AddRoundKey(temp, RK + 16 * (i + 1));
	}

	SubBytes(temp);
	ShiftRows(temp);
	AddRoundKey(temp, RK + 16 * (i + 1));

	copyarray(CT, temp);
}
void AES_DEC(u8 CT[16], u8 RK[], u8 PT[], int keysize)
{
	int i;
	int Nr = keysize / 32 + 6;
	u8 temp[16];
	copyarray(temp, CT);

	AddRoundKey(temp, RK + 16 * Nr);

	for (i = Nr - 1; i > 0; i--)
	{
		ShiftRows_inv(temp);
		SubBytes_inv(temp);
		AddRoundKey(temp, RK + 16 * i);
		MixColumns_inv(temp);
	}

	ShiftRows_inv(temp);
	SubBytes_inv(temp);
	AddRoundKey(temp, RK);

	copyarray(PT, temp);
}

void AES_KeySchedule_Optimization(u8 MK[], u32 W[], int keysize)
{
	if (keysize == 128)
		RoundKeyGeneration128_Optimization(MK, W);
}
void RoundKeyGeneration128_Optimization(u8 MK[], u32 W[])
{
	int i;
	u32 T;

	W[0] = u4byte_in(MK);
	W[1] = u4byte_in(MK + 4);
	W[2] = u4byte_in(MK + 8);
	W[3] = u4byte_in(MK + 12);

	for (i = 0; i < 10; i++)
	{
		T = W[4 * i + 3];
		T = RotWord(T);
		T = SubWord(T);
		T ^= Rcons[i];

		W[4 * i + 4] = W[4 * i] ^ T;
		W[4 * i + 5] = W[4 * i + 1] ^ W[4 * i + 4];
		W[4 * i + 6] = W[4 * i + 2] ^ W[4 * i + 5];
		W[4 * i + 7] = W[4 * i + 3] ^ W[4 * i + 6];
	}
}
void AES_ENC_Optimization(u8 PT[16], u32 W[], u8 CT[16], int keysize)
{
	int Nr = keysize / 32 + 6;
	u32 s0, s1, s2, s3, t0, t1, t2, t3;

	//0round
	s0 = u4byte_in(PT) ^ W[0];
	s1 = u4byte_in(PT + 4) ^ W[1];
	s2 = u4byte_in(PT + 8) ^ W[2];
	s3 = u4byte_in(PT + 12) ^ W[3];

	int i = 4;
	EncCalculateT(i);	i += 4; //1 round
	EncCalculateS(i);	i += 4; //2 round
	EncCalculateT(i);	i += 4; //3 round
	EncCalculateS(i);	i += 4; //4 round
	EncCalculateT(i);	i += 4; //5 round
	EncCalculateS(i);	i += 4; //6 round
	EncCalculateT(i);	i += 4; //7 round
	EncCalculateS(i);	i += 4; //8 round

	if (Nr == 10)
	{
		EncCalculateT(i);	i += 4; //9 round
		EncCalculateLast(i);  //10 round
	}
	else if (Nr == 12)
	{
		EncCalculateT(i);	i += 4; //9 round
		EncCalculateS(i);	i += 4; //10 round
		EncCalculateT(i);	i += 4; //11 round
		EncCalculateLast(i);  //12 round
	}
	else if (Nr == 14)
	{
		EncCalculateT(i);	i += 4; //9 round
		EncCalculateS(i);	i += 4; //10 round
		EncCalculateT(i);	i += 4; //11 round
		EncCalculateS(i);	i += 4; //12 round
		EncCalculateT(i);	i += 4; //13 round
		EncCalculateLast(i);  //14 round
	}

	u4byte_out(CT, s0);
	u4byte_out(CT + 4, s1);
	u4byte_out(CT + 8, s2);
	u4byte_out(CT + 12, s3);
}
void AES_DEC_Optimization(u8 CT[16], u32 W[], u8 PT[16], int keysize)
{
	//죄송합니다 최적화 구현을 못했습니다
	int Nr = keysize / 32 + 6;
	u8 temp[16];
	u32 s0, s1, s2, s3, t0, t1, t2, t3;
	int i;
	copyarray(temp, CT);

	i = Nr * 4;
	AddRoundKey32(temp, W + i); i -= 4;
	ShiftRows_inv(temp);
	SubBytes_inv(temp);
	AddRoundKey(temp, W + i); i -= 4;

	s0 = u4byte_in(temp) ^ W[i];
	s1 = u4byte_in(temp + 4) ^ W[i + 1];
	s2 = u4byte_in(temp + 8) ^ W[i + 2];
	s3 = u4byte_in(temp + 12) ^ W[i + 3];

	DecCalculateT(i); i -= 4;
	DecCalculateS(i); i -= 4;
	DecCalculateT(i); i -= 4;
	DecCalculateS(i); i -= 4;
	DecCalculateT(i); i -= 4;
	DecCalculateS(i); i -= 4;
	DecCalculateT(i); i -= 4;
	DecCalculateS(i); i -= 4;
	
	u4byte_out(temp, s0);
	u4byte_out(temp + 4, s1);
	u4byte_out(temp + 8, s2);
	u4byte_out(temp + 12, s3);

	ShiftRows_inv(temp);
	SubBytes_inv(temp);
	AddRoundKey(temp, W + i);

	copyarray(PT, temp);
}
#pragma endregion

int main()
{
	u8 PT[16] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
	u8 PT2[16] = { 0xa6, 0xa6, 0x64, 0xa4, 0x84, 0x4a, 0x4e, 0x7b, 0xa1, 0x87, 0x3b, 0x87, 0xc6, 0xd1, 0x82, 0x1e };
	u8 ENCKEY[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	u8 RK[240], CT[16], DT[16];
	u32 W[60] = { 0x00 };
	int i;
	int keysize = 128;

	AES_KeySchedule(ENCKEY, RK, keysize);
	AES_KeySchedule_Optimization(ENCKEY, W, keysize);
	AES_ENC_Optimization(PT, W, CT, keysize);
	AES_DEC(CT, RK, DT, keysize);
	//AES_DEC_Optimization(CT, W, DT, keysize);
	printf("ORG: "); print16(PT, 16); printf("\n");
	printf("ENC: "); print16(CT, 16); printf("\n");
	printf("DEC: "); print16(DT, 16); printf("\n");

	return 0;
}