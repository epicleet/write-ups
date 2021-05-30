#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#define tt 16
#define CRYPTO_SECRETKEYBYTES 2100736
#define CRYPTO_PUBLICKEYBYTES 268288
#define CRYPTO_CIPHERTEXT_SIZE 512
#define MLEN 24
#define RANDOMCOVER 400

int bit(unsigned char *c,int pos){
	return 1 & (c[pos / 8] >> (pos & 7));
}

void xor(unsigned char *c1,const unsigned char *c2){
	int i;
	for (i = 0;i < 512;++i) c1[i] ^= c2[i];
}

void swap(unsigned char *c1,unsigned char *c2){
	int i;
	for (i = 0;i < 512;++i) {
		unsigned char u = c1[i];
		c1[i] = c2[i];
		c2[i] = u;
	}
}

unsigned long long clen;
int cdiffpivotlen, cbitspivotlen;
unsigned char pk[CRYPTO_PUBLICKEYBYTES];
unsigned char sk[CRYPTO_SECRETKEYBYTES];
unsigned char mzero[MLEN];
unsigned char czero[CRYPTO_CIPHERTEXT_SIZE];
unsigned char cdiff[RANDOMCOVER][CRYPTO_CIPHERTEXT_SIZE];
int cdiffpivot[RANDOMCOVER];
unsigned char mbits[MLEN * 8][CRYPTO_CIPHERTEXT_SIZE];
unsigned char cbits[MLEN * 8][CRYPTO_CIPHERTEXT_SIZE];
int cbitspivot[RANDOMCOVER];
unsigned char c[CRYPTO_CIPHERTEXT_SIZE];
unsigned char c2[CRYPTO_CIPHERTEXT_SIZE];
unsigned char c3[CRYPTO_CIPHERTEXT_SIZE];
unsigned char e[CRYPTO_CIPHERTEXT_SIZE];
unsigned char e2[CRYPTO_CIPHERTEXT_SIZE];
unsigned char e3[CRYPTO_CIPHERTEXT_SIZE];

unsigned char parity[] = { 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00 };

typedef struct {
	unsigned int column;
	unsigned int acolumn;
	unsigned int row;
	unsigned char* matrix;
}matrix;

void Delete(matrix* m) {
	free(m->matrix);
	m->matrix = NULL;
}

void Set(matrix* m, const unsigned int r, const unsigned int c) {
	m->row = r;
	m->acolumn = c;
	m->column = c/8;
	m->matrix = malloc(m->row*m->column + 1);
	memset(m->matrix, 0, m->row*m->column);
}

matrix INVALIDMAT;

matrix transpose(const matrix* a) {
	matrix T;
	Set(&T, a->acolumn, a->row);
	unsigned char *pa, *pt;
	unsigned long long x, t;
	int i, r, c;
	for (r = 0; r < T.column; r++)
	{
		for (c = 0; c < a->column; c++)
		{
			pa = a->matrix + a->column*r * 8 + c;
			for (i = 0; i <= 7; i++) {
				x = x << 8 | *(pa);
				pa += a->column;
			}

			t = (x ^ (x >> 7)) & 0x00AA00AA00AA00AALL;
			x = x ^ t ^ (t << 7);
			t = (x ^ (x >> 14)) & 0x0000CCCC0000CCCCLL;
			x = x ^ t ^ (t << 14);
			t = (x ^ (x >> 28)) & 0x00000000F0F0F0F0LL;
			x = x ^ t ^ (t << 28);
			pt = T.matrix + T.column*(c * 8 + 7) + r;
			for (i = 7; i >= 0; i--) {
				*pt = x;
				pt -= T.column;
				x = x >> 8;
			}
		}
	}

	return T;
}

matrix mat(matrix* v, const int r, const int c){
	matrix a;
	v->row = c;
	v->column = r/8;
	v->acolumn = r;
	a = transpose(v);
	return a;
}

matrix Add(const matrix* a, const matrix* b) {
	if (a->row != b->row || a->column != b->column)return INVALIDMAT;
	matrix c;
	int i;
	unsigned char *pc, *pa, *pb;
	Set(&c, a->row, a->acolumn);
	pc = c.matrix;
	pa = a->matrix;
	pb = b->matrix;
	for (i = 0; i < a->row*a->column; i++)
		*(pc++) = *(pa++) ^ *(pb++);
	return c;
}

matrix Mult(const matrix* a, const matrix* b) {
	if(a->acolumn!=b->row)return INVALIDMAT;
	matrix c;
	Set(&c, a->row, b->acolumn);
	matrix bt;
	int i, h, j, k;
	bt = transpose(b);
	unsigned char *pc, *pb, *pa;
	pa = a->matrix;
	pb = bt.matrix;
	pc = c.matrix;
	
	unsigned char sum = 0;
	char curr = 0;
	for (i = 0; i < a->row; i++){
		for (h = 0; h < b->column; h++){
			for (j = 0; j < 8; j++){
				for (k = 0; k < bt.column; k++)
					sum ^= *(pa++)&*(pb++);
				curr ^= ((parity[sum]) << (7 - j));
				sum = 0;
				pa -= bt.column;
			}
			*(pc++) = curr;
			curr = 0;
		}
		pa += a->column;
		pb = bt.matrix;
	}
	Delete(&bt);
	return c;
}

matrix MatrixVectorMult(const matrix*m, const matrix*v) {
	//i need to mult each row in m in all of v,and because v is organized as one row
	//i mult each row of m with the row that represents the column vector v 
	if(m->column!=v->column)return INVALIDMAT;
	
	matrix a;
	Set(&a, 1, m->row);
	unsigned char *pm, *pa, *pv;
	pm = m->matrix;
	pa = a.matrix;
	pv = v->matrix;
	unsigned char sum = 0;
	int i, h, j;
	for (i = 0; i < m->row / 8; i++)
	{
		for (h = 0; h < 8; h++)
		{
			for (j = 0; j < v->column; j++)
			{
				sum ^= *(pm++) & *(pv++);
			}
			*(pa) |= parity[sum] << (7 - h);
			pv = v->matrix;
			sum = 0;
		}
		pa++;
	}
	return a;
}

matrix RX(matrix* X, matrix* A, matrix* B, matrix* C, matrix* D) {
	matrix YW, XC, XCX, XD, AX, Add1, Minus1;
	XC = Mult(X, C);
	XCX = Mult(&XC, X);
	Delete(&XC);
	XD = Mult(X, D);
	AX = Mult(A, X);
	Add1 = Add(&XCX, &XD);
	Minus1 = Add(&Add1, &AX);
	Delete(&Add1);
	YW = Add(&Minus1, B);
	Delete(&XCX);
	Delete(&XD);
	Delete(&AX);
	Delete(&Minus1);
	return YW;
}

void randombytes (unsigned char *stream, size_t num_bytes){
	size_t i;
	for (i = 0; i < num_bytes; i++) stream[i] = rand();
}

int crypto_encrypt( unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen, const unsigned char *pk){
	*clen = 512;
	matrix V, X, Q, QV, YW, AW, BW, CW, DW;
	int n = 4 * tt;
	Set(&V, 1, 520);

	Set(&AW, n, n);
	memcpy(AW.matrix, pk, 512);
	Set(&BW, n, n);
	memcpy(BW.matrix, pk + 512, 512);
	Set(&CW, n, n);
	memcpy(CW.matrix, pk + 1024, 512);
	Set(&DW, n, n);
	memcpy(DW.matrix, pk + 1536, 512);
	Set(&Q, 4096, 520);
	memcpy(Q.matrix, pk + 2048, 266240);
	memcpy(V.matrix, m, 24);
	randombytes(V.matrix + 24, 40);

	V.matrix[V.column - 1] = 0x80;
	QV = MatrixVectorMult(&Q, &V);
	X = mat(&QV, n, n);

	YW = RX(&X, &AW, &BW, &CW, &DW);
	memcpy(c, YW.matrix, n*n / 8);

	Delete(&X);
	Delete(&QV);
	Delete(&YW);
	Delete(&V);
	Delete(&Q);
	Delete(&AW);
	Delete(&BW);
	Delete(&CW);
	Delete(&DW);
	return 0;
}

void readCipher(char *name, unsigned char *c){
	FILE * fp = fopen(name, "rb");
	fread(c, CRYPTO_CIPHERTEXT_SIZE, 1, fp);
	fclose(fp);
}

int main(){
	srand(time(NULL));
	int i, j, k, l;
	FILE * fp1 = fopen("pk", "rb");
	fread(pk, CRYPTO_PUBLICKEYBYTES, 1, fp1);
	fclose(fp1);
	readCipher("ct", c);
	readCipher("ct2", c2);
	readCipher("ct3", c3);
	crypto_encrypt(czero,&clen,mzero,MLEN,pk);
	for (i = 0;i < RANDOMCOVER;++i) {
		crypto_encrypt(cdiff[i],&clen,mzero,MLEN,pk);
		xor(cdiff[i],czero);
	}
	i = 0;
	for (j = 0;j < 4096;++j){
		for (k = i;k < RANDOMCOVER;++k){
			if (bit(cdiff[k],j)) {
				swap(cdiff[i],cdiff[k]);
				for (l = 0;l < RANDOMCOVER;++l)
					if (l != i)
						if (bit(cdiff[l],j))
							xor(cdiff[l],cdiff[i]);
				cdiffpivot[i++] = j;
				break;
			}
		}
	}
	cdiffpivotlen = i;
	for (i = 0;i < MLEN * 8;++i) {
		for (j = 0;j < 512;++j) mbits[i][j] = 0;
		mbits[i][i / 8] = 1 << (i & 7);
		crypto_encrypt(cbits[i],&clen,mbits[i],MLEN,pk);
		xor(cbits[i],czero);
		for (k = 0;k < cdiffpivotlen;++k)
			if (bit(cbits[i],cdiffpivot[k]))
				xor(cbits[i],cdiff[k]);
	}
	i = 0;
	for (j = 0;j < 4096;++j){
		for (k = i;k < MLEN * 8;++k){
			if (bit(cbits[k],j)) {
				swap(mbits[i],mbits[k]);
				swap(cbits[i],cbits[k]);
				for (l = 0;l < MLEN * 8;++l)
					if (l != i)
						if (bit(cbits[l],j)) {
							xor(mbits[l],mbits[i]);
							xor(cbits[l],cbits[i]);
						}
				cbitspivot[i++] = j;
				break;
			}
		}
	}
	cbitspivotlen = i;
	xor(c,czero);
	xor(c2,czero);
	xor(c3,czero);
	for (k = 0;k < cdiffpivotlen;++k){
		if (bit(c,cdiffpivot[k])){
			xor(c,cdiff[k]);
		}
		if (bit(c2,cdiffpivot[k])){
			xor(c2,cdiff[k]);
		}
		if (bit(c3,cdiffpivot[k])){
			xor(c3,cdiff[k]);
		}
	}
	for (k = 0;k < cbitspivotlen;++k){
		if (bit(c,cbitspivot[k])) {
			xor(c,cbits[k]);
			xor(e,mbits[k]);
		}
		if (bit(c2,cbitspivot[k])) {
			xor(c2,cbits[k]);
			xor(e2,mbits[k]);
		}
		if (bit(c3,cbitspivot[k])) {
			xor(c3,cbits[k]);
			xor(e3,mbits[k]);
		}
	}
	printf("%s%s%s\n", e, e2, e3);
	return 0;
}
