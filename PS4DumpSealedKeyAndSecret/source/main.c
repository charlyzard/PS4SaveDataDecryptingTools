#include "ps4.h"
#include "kern.h"
#include "kernel.h"

#define debug(sock, format, ...)\
	do {\
		char buffer[512];\
		int size = sprintf(buffer, format, ##__VA_ARGS__);\
		sceNetSend(sock, buffer, size, 0);\
	} while(0)



 #define foreach(item, array) \
     for (int keep = 1, \
              count = 0, \
              size = sizeof(array) / sizeof*(array); \
          keep && count != size; \
          keep = !keep, count++) \
         for (item = (array) + count; keep; keep = !keep)

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
 
 // /* Dump the sealedkey. Send over tcp and save to file */
 // int dumpDecryptedSealedKey() {
 
     // /* First load the sealedkey into a buffer */
	// byte enc[96];
     // if (!get_pfsSKKey(enc)) {
         // debug(sock,"[-] Can not load the sealed key!\n");
         // return -1;
     // }
 
	// debug(sock,"[-] Clave leida correctamente\n");
	
	// //debug(sock,"[-] Ubicacion getSealedKeyKeyAndSecret : %d\n", getSealedKeyKeyAndSecret);
	
     // /* Let's check the pfsSKKEy */
	 // /*
     // if (enc.MAGIC == PFSK_IDENT && enc.CAT == VERSION) {
         // debug(sock,"[+] Magic and version ok!\n[+] sk IV = ");
         // foreach(byte *val, &enc.IV) debug(sock,"%02X", *val);
 
         // debug(sock,"\n[+] sk KEY = ");
         // foreach(byte *val, enc.KEY) debug(sock,"%02X", *val);
 
         // debug(sock,"\n[+] sk Key-SHA256 = ");
         // foreach(byte *val, enc.SHA256) debug(sock,"%02X", *val);
         // debug(sock,"\n");
 
     // }
     // else return -4;
	 // */
 
     // /* Now decrypt it */
     // byte dec[16];
 
     // int i;
     // if (!(i = getSealedKeyKeyAndSecret(enc, dec))) {
         // debug(sock,"[-] Error!\n[-] getSealedKeyKeyAndSecret returned %d\n", i);
         // return -1;
     // }
     // debug(sock,"[+] getSealedKeyKeyAndSecret returned %d\n", i);
 
		// /* Saving to file */
         // debug(sock,"[+] Will try to save to file...");
 
         // FILE *dump = fopen("/mnt/usb0/pfskeydecrypted", "w");

             // if (!dump) {
                 // debug(sock,"fail!\n%s", usb_error);
                 // return -3;
             // }
         
 
         // fwrite(dec, 16, 1, dump);
         // debug(sock,"done!\n");
         // fclose(dump);
         // return 1;
 
 // }

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
	
	
	
	
	// getSealedKeyAndSecretPayload
	debug(sock, "Kernel patched! starting getSealedKeyAndSecretPayload\n");
	
	byte sealedKey[16];
	memset(sealedKey, 1, 16);

	byte sealedSecret[16];
	memset(sealedSecret, 1, 16);	
	
	
	struct payload_info payload_info;
	memset(&payload_info, 0, sizeof(payload_info));
	payload_info.bufSealedKey = sealedKey;
	payload_info.bufSealedSecret = sealedSecret;
	
	kexec(getSealedKeyAndSecretPayload, &payload_info);
	
	
	
	
	// got the keys, now save them to usb
	debug(sock, "getSealedKeyAndSecretPayload finished. Saving keys to file\n");
	
	FILE *dump = fopen("/mnt/usb0/sealedKey.bin", "w");
	fwrite(sealedKey, 16, 1, dump);
	fclose(dump);
	
	dump = fopen("/mnt/usb0/sealedSecret.bin", "w");
	fwrite(sealedSecret, 16, 1, dump);
	fclose(dump);
	
	
	

	sceNetSocketClose(sock);


	// Return to browser
	return 0;
}
