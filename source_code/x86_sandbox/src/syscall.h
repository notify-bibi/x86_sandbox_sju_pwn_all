#ifndef _SYSCALL_
#define _SYSCALL_
#include "main.h"
extern bool show_info;
extern bool debug;


bool sandbox_safe_syscall(uc_engine* uc, void* user_data);


#endif