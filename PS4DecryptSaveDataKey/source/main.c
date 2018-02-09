#include "ps4.h"
#include "kern.h"
#include "kernel.h"

#define debug(sock, format, ...)\
	do {\
		char buffer[512];\
		int size = sprintf(buffer, format, ##__VA_ARGS__);\
		sceNetSend(sock, buffer, size, 0);\
	} while(0)


 typedef struct sealedkey_t {
     const unsigned char MAGIC[8];
     const unsigned char CAT[8];
     const unsigned char IV[16];
     const unsigned char KEY[32];
     const unsigned char SHA256[32];
 } PfsSKKey;

 
 typedef unsigned char byte;              /* byte defination for c/c++ */
 byte PFSK_IDENT[8] = "pfsSKKey";
 byte VERSION[8] = "\x01\x00\x00\x00\x00\x00\x00\x00";
 const char *USER1 = "10000000";
 const char *usb0 = "/mnt/usb0/";
 const char *usb1 = "/mnt/usb1/";
 const char *pfs = "dec_pfsSK.Key";
 const char *home = "/user/home/";
 const char *tropkey = "/trophy/data/sce_trop/sealedkey";
 char *usb_error = "[-] ERROR: Can't access usb0 nor usb1!\n[-] Will return now to caller.\n";

 int sock;
 
 /* Get's the encrypted sealed key based on user id */
 int get_pfsSKKey(byte *buffer) {
	 
	 debug(sock,"[-] Inside get_pfsSKKey\n");
	 
	 int fd = open("/mnt/usb0/pfskeyencrypted", O_RDONLY,0);
	 if (fd != -1) {
		 debug(sock,"[-] Inside get_pfsSKKey open OK: %d", fd);
		 int leido = read(fd,  buffer,  96 );
		 if (leido != -1) {
			 debug(sock,"[-] Inside get_pfsSKKey read OK: leido - %d", leido);
			 close(fd);
			 return 1;
		 }
		 else {
			 debug(sock, "read err : %s\n", strerror(errno));
			 close(fd);
			 return 0;
		 }
	 }
	 else {
		 debug(sock, "open %s err : %s\n", "/mnt/usb0/pfskeyencrypted", strerror(errno));
		 return 0;
	 }


 }
 


int _main(void) {

	initKernel();
	initLibc();
	initNetwork();

	// Connect to server and send message
	char socketName[] = "debug";

	struct sockaddr_in server;

	// udp log to port 18194
	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	sceNetInetPton(2, "192.168.1.80", &server.sin_addr);
	server.sin_port = sceNetHtons(18194);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));

	sock = sceNetSocket(socketName, AF_INET, SOCK_DGRAM, 0);
	sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));

	debug(sock, "debugnet Initialized\n");	
	
	kexec(kernelPayload, NULL);
	
	
	
	
	// sceSblSsDecryptSealedKeyPayload
	debug(sock, "Kernel patched! starting sceSblSsDecryptSealedKeyPayload\n");
	
	byte encryptedKey[96];
	memset(encryptedKey, 0, sizeof(encryptedKey));

	byte decryptedKey[16];
	memset(decryptedKey, 0, sizeof(decryptedKey));	
	
	get_pfsSKKey(encryptedKey);
	
	
	struct payload_info payload_info;
	memset(&payload_info, 0, sizeof(payload_info));
	payload_info.bufEncryptedKey = encryptedKey;
	payload_info.bufDecryptedKey = decryptedKey;
	
	kexec(sceSblSsDecryptSealedKeyPayload, &payload_info);
	
	
	
	
	// got the keys, now save them to usb
	debug(sock, "sceSblSsDecryptSealedKeyPayload finished. Saving decrypted save data key to file\n");
	
	FILE *dump = fopen("/mnt/usb0/decryptedSaveDataKey.bin", "w");
	fwrite(decryptedKey, sizeof(decryptedKey), 1, dump);
	fclose(dump);
	
	
	
	

	sceNetSocketClose(sock);


	// Return to browser
	return 0;
}
