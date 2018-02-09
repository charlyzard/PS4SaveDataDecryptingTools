#include "ps4.h"
#include "kern.h"
#include "kernel.h"

#define debug(sock, format, ...)\
	do {\
		char buffer[512];\
		int size = sprintf(buffer, format, ##__VA_ARGS__);\
		sceNetSend(sock, buffer, size, 0);\
	} while(0)
 int sock;
 


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
