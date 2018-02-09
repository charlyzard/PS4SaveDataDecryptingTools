#include "kern.h"

Inline uint64_t readCr0(void) {
	uint64_t cr0;

	__asm__ __volatile__(
		"movq %0, %%cr0"
		: "=r" (cr0)
		: : "memory"
	);

	return cr0;
}

Inline void writeCr0(uint64_t cr0) {
	__asm__ __volatile__(
		"movq %%cr0, %0"
		: : "r" (cr0)
		: "memory"
	);
}

Inline uint8_t* getKernelBase() {
	uint32_t lo, hi;
	__asm__ __volatile__("rdmsr" : "=a" (lo), "=d" (hi) : "c"(0xC0000082));
	return (uint8_t*)(((uint64_t)lo | ((uint64_t)hi << 32)) - KERN_XFAST_SYSCALL);
}

int kernelPayload(struct thread *td, void* uap) {
	uint8_t* ptrKernel = getKernelBase();
	struct ucred* cred = td->td_proc->p_ucred;
	struct filedesc* fd = td->td_proc->p_fd;

	// Escalate privileges
	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	// Escape sandbox
	void** prison0 = (void**)&ptrKernel[KERN_PRISON_0];
	void** rootvnode = (void**)&ptrKernel[KERN_ROOTVNODE];
	cred->cr_prison = *prison0;
	fd->fd_rdir = fd->fd_jdir = *rootvnode;

	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access

	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

	// Disable write protection
	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// Disable ptrace checks
	ptrKernel[KERN_PTRACE_CHECK_1] = 0xEB;
	*(uint16_t*)&ptrKernel[KERN_PTRACE_CHECK_2] = 0x27EB;

	// Disable process aslr
	*(uint16_t*)&ptrKernel[KERN_PROCESS_ASLR] = 0x9090;

	// Enable write protection
	writeCr0(cr0);

	return 0;
}

int getSealedKeyAndSecretPayload(void* td, struct get_sealed_key_payload_args* args) {
	
	uint8_t* ptrKernel = getKernelBase();
	
	typedef int (*myGetSealedKeyKeyAndSecret)(void *p1, void *p2);
	// typedef int (*mycopyin)(const void *uaddr, void *kaddr, size_t len);
	typedef int (*mycopyout)(const void	*kaddr,	void *uaddr, size_t len);
	
	
	myGetSealedKeyKeyAndSecret getSealedKeyKeyAndSecret = (myGetSealedKeyKeyAndSecret)&ptrKernel[0x05FB630];
	// mycopyin copyin = (mycopyin)&ptrKernel[0x00286DF0];
	mycopyout copyout = (mycopyout)&ptrKernel[0x0286D70];
	
	byte p1[16];
	byte p2[16];
	
	getSealedKeyKeyAndSecret(p1, p2);
	
	copyout(p1, args->payload_info->bufSealedKey, sizeof(p1));
	copyout(p2, args->payload_info->bufSealedSecret, sizeof(p2));
	
	
	return 0;
}