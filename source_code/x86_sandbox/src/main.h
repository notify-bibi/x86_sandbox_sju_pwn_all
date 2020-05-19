#ifndef _MAIN_
#define _MAIN_
#include <unicorn/unicorn.h>
#include <string.h>
#ifdef _MSC_VER 
#include <windows.h>
#endif

#include <iostream>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <vector>
#include "syscall.h"



#define GET1(addr) (*(unsigned char*)((addr))) 
#define GET2(addr) (*(unsigned short*)((addr)))
#define GET4(addr) (*(unsigned int*)((addr)))
#define GET8(addr) (*(unsigned long long*)((addr)))
#define ALIGN(a, size)  ((a) & ~((size) - 1))


extern bool show_info;
extern bool debug;
extern bool tcode;



class x86_sandbox {
    uc_engine* m_uc;
    uc_err m_err;
    uc_mode m_mode;
    std::vector<int> m_fd;
    bool m_file_flag = true;
public:
    void Disable_file_RDWR(){
        m_file_flag = false;
    }
    
    
    int file_open(const char *filename, int flags, int mode){
        int fd = open(filename, flags, mode);
        if(fd){
            m_fd.emplace_back(fd);
            
            if(!m_file_flag){
                printf("sandbox: open(filename=%s, flags=0x%x, mode=%d) was forbidden\n",filename, flags, mode);
                return -1;
            }
        }
        return fd;
    }

    unsigned long long g_brk = 0x0000000000603000;

    bool is_mode64() { return m_mode = UC_MODE_64; }
    operator uc_engine* () { return m_uc; };
    x86_sandbox(const char* filename, uc_mode m, bool f);

    bool read_mem_dump(const char* filename, bool f);
    void engine_start();
    void show_regs();

    uc_hook add_syscall_hook();
    uc_hook add_code_hook();
    uc_hook add_unmap_hook();
    ~x86_sandbox() { 
        for(int fd : m_fd) { close(fd); }
        uc_close(m_uc);
    };
};

#endif