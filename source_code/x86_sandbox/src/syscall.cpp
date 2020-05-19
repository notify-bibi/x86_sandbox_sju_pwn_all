
#include "syscall.h"
#ifdef __GNUG__ 
#include <sys/stat.h>
#include <unistd.h>
#endif


//#define OUTMSG

using namespace std;

string get_str(uc_engine* uc, int64_t addr) {
    string ret;
    char buff[64];
    unsigned size = 0;
    while (ret.size() == size) {
        uc_mem_read(uc, addr, buff, 64);
        ret.assign(buff);
        size += 64;
    }
    return ret;
}


unsigned read(char *p, size_t size) {
    unsigned i;
    for (i = 0; i < size; p[i] = getchar(), i++);
    return i;
}

bool sandbox_safe_syscall(uc_engine* uc, void* user_data)
{
    x86_sandbox& box = *(x86_sandbox*)user_data;
    char buff[100];
    int64_t ret = -1;

    int64_t rax = 0;
    int64_t rbx = 0;
    int64_t rcx = 0;
    int64_t rdx = 0;
    int64_t rsi = 0;
    int64_t rdi = 0;
    int64_t rsp = 0;
    int64_t RIP = 0;

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_read(uc, UC_X86_REG_RIP, &RIP);

    //rdi   rsi	   rdx 	r10	  r8	r9
    switch(rax) {
    case 0x0://sys_read
    {
        if(debug) 
            printf("sandbox:  sys_read(fd=%d, buf=%p, count:%d) ", rdi, rsi, rdx);

        unsigned rcount = 0;
        while (rdx > 0) {
            unsigned count = read(rdi, buff, rdx >= sizeof(buff) ? sizeof(buff) : rdx);
            uc_mem_write(uc, rsi, buff, count);
            rsi += count;
            rdx -= count;
            rcount += count;
            if(buff[count-1]=='\n') break;
        }
        ret = rcount;
        break;
    }
    case 0x1://sys_write
    {
        if(debug) 
            printf("sandbox:  sys_write(fd=%d, buf=%p, count:%d)", rdi, rsi, rdx);
        void *p = malloc(rdx);
        uc_mem_read(uc, rsi, p, rdx);
        write(rdi, p, rdx);
        free(p);
        ret = rdx;
        break;
    }
    case 0x2:{//sys_open
        string fname = get_str(uc, rdi);
        if(debug) 
            printf("sandbox:  sys_open(filename=%s, flags=0x%x, mode=%d)", fname.c_str(), rsi, rdx);
        ret = box.file_open(fname.c_str(), rsi, rdx);
        break;
    }
    case 0x3:{//sys_close
        ret = 0;
        break;
    }
    case 0x5://sys_newfstat
        if(debug) 
            printf("sandbox:  sys_newfstat(fd=%d, struct stat __user *statbuf = %p)", rdi, rsi);

        struct stat64 buf;
        ret = fstat64(rdi, &buf);
        uc_mem_write(uc, rsi, &buf, sizeof(buf));

        break;
    case 0x9://sys_mmap unsigned long addr	unsigned long len	int prot	int flags	int fd	long off
    {    
        if(debug) 
            printf("sandbox:  sys_mmap(addr=%p, len=0x%x, prot=%d, flags=%d, ...)", rdi, rsi, rdx);
            
        uc_err err = uc_mem_map(uc, ALIGN(rdi, 0x1000), ALIGN(rdi+rsi+0x1000, 0x1000) - ALIGN(rdi, 0x1000), UC_PROT_ALL);
        ret = err;
        break;
    }
    case 0xc: //sys_brk
    {
        if(debug) 
            printf("sandbox: sys_brk(address:0x%p)", rbx);
        int64_t brk = rbx;
        if (brk) {
            if (brk < box.g_brk) {
                uc_mem_unmap(uc, brk, box.g_brk - brk);
                box.g_brk = ALIGN(brk, 32);
            }
            else if (brk == box.g_brk) {
                uc_mem_map(uc, box.g_brk, 0x21000, UC_PROT_ALL);
                box.g_brk = ALIGN(box.g_brk + 0x21000, 32);
            }
            else {
                uc_mem_map(uc, box.g_brk, brk - box.g_brk, UC_PROT_ALL);
                box.g_brk = ALIGN(brk, 32);
            }
        }
        ret = box.g_brk;
        break; 
    }
    case 0xE7: {//LINUX - sys_Exit
        if(debug) 
            printf("system call: sys_Exit");
        uc_emu_stop(uc);
        return false;
    }
    default:
        printf("\n\nsandbox:  ERROR: was not expecting rax=0x%llx" " in syscall\n", rax);
        uc_emu_stop(uc);
        return false;
    }
    if(debug) 
        printf("[ rax:0x%llx syscall at %p  ret 0x%llx ] \n",rax , RIP, ret);

    uc_reg_write(uc, UC_X86_REG_RAX, &ret);
    return true;
}