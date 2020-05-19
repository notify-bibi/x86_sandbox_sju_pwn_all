#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

//g++ -std=c++11 ./main.cpp
//#define OUT

class RemoteServer;
class Login;


void pad(){
    __asm__(
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        "nop;\n\t"
        :::
    );
}


size_t get_num(){
    char buff[0x61];
    int n = read(0, buff, 0x60);
    buff[n] = 0;
    return atol(buff);
}


static void StrToHex(char* pbDest, char* pbSrc, int nLen)
{
    char h1, h2;
    unsigned char s1, s2;
    int i;

    for (i = 0; i < nLen; i++)
    {
        h1 = pbSrc[2 * i];
        h2 = pbSrc[2 * i + 1];

        s1 = toupper(h1) - 0x30;
        if (s1 > 9)
            s1 -= 7;

        s2 = toupper(h2) - 0x30;
        if (s2 > 9)
            s2 -= 7;

        pbDest[i] = s1 * 16 + s2;
    }
};


void get_flag(const char *file){
    char flag[100];
    FILE *fp = fopen(file, "r");
    if(fp){
        fgets(flag, 100, fp);
        fclose(fp);
        printf("[%s]\n", flag);
    }else{
        printf("\33[1;31m (¨s#-_-)¨s \33[0m %s not found! why?\n", file);
    }
}



class Login {
    friend class RemoteServer;
    size_t m_count = 0;
    char m_count_w = 0;
    char pad[7];
    char m_sign[0x70];
    char m_key[0x90];
    bool m_is_right;
    
public:
    static unsigned long long cpuid(int _n) {
        unsigned int _v1 = 0, _v2 = 0, _v3 = 0;
        __asm__(
            "movl %[n],%%eax;\n\t"
            "xor %%rdx,%%rdx;\n\t"
            "cpuid;\n\t"
            "mov %%ebx,%[v1];\n\t"
            "mov %%ecx,%[v2];\n\t"
            "mov %%edx,%[v3];\n\t"
            : [v1] "=r" (_v1), [v2] "=r" (_v2), [v3] "=r" (_v3)
            : [n] "r" (_n)
            : "rax", "rdx", "rcx", "rbx"
        );
        return (((unsigned long long)_v1) << 32) | _v2 ^ _v3;

    };

    char count() const{ return m_count; }
    
    char* input_key() {
        char c;
        char max = 0;
        printf("your password << \33[32;1m");
        
        for (c = getchar(); 
             c != '\n';
             c = getchar()
            ) {
            if(c < 0){
                c += 128;
            }
            if (max++ >= 127) { break; }
            m_key[max - 1] = c;
            
        }
        printf("\033[0m");
        m_key[max] = 0;
        printf("Your key is %s\n", m_key);
        StrToHex(m_key, m_key, 0x40);
        m_count_w += max;
        
#ifdef OUT
        printf("-%p %d-\n", m_count, max);
#endif
        return m_key;
    }
    
    
    void add_count(){ m_count++; };
    
    Login() : m_is_right(false){
        ((unsigned long long*) m_sign)[0] = cpuid(0);
        ((unsigned long long*) m_sign)[1] = cpuid(1);
    }
};

class RemoteServer :private Login {
    friend class Login;




public:

    operator Login* () { return reinterpret_cast<Login*>(this); }
    Login* base() { return reinterpret_cast<Login*>(this); }
    
    virtual void show_message() {
        puts("Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)");
    }

    virtual void get_shell() {
        puts("Welcome to ubuntu shell\n");
        char data[0x500];
        puts("please write your shellcode i will run  [ size_t (*intput)(size_t , size_t , size_t ) ]");
        printf("data ptr:%p\n", data);
        
        printf("data<<");
        read(0, data, 0x500);
        
        printf("invoke ptr<<");
        size_t (*ptr) (size_t, size_t, size_t) = (size_t (*) (size_t, size_t, size_t))(get_num());
        
        printf("arg0<<");
        size_t arg0 = get_num();
        
        printf("arg1<<");
        size_t arg1 = get_num();
        
        printf("arg2<<");
        size_t arg2 = get_num();
        
        long long unsigned int ret = ptr(arg0, arg1, arg2);
        printf("ret is 0x%llx\n", ret);
    }


    char count() { return m_count; }
    const char *get_sign() const { return m_sign; }
    
    void show_machine_code() {
        char buff[16];
        memcpy(buff, m_sign, sizeof(buff));
        for (int i = 0; i < 15; i++) {
            buff[i] ^= buff[i + 1];
        }
        unsigned int* c = (unsigned int*)buff;
        printf("Your machine-code is \33[1;31;5m %08X-%08X-%08X-%08X \033[0m\n", c[0], c[1], c[2], c[3]);
    }

    ~RemoteServer() {
    }

    RemoteServer() {
#ifdef OUT
        void* vptr = (void*)((unsigned long long*) this)[0];
        printf("RemoteServer::vptr %p\n", vptr);
#endif
    }



};

class Safe_Server :public RemoteServer {
    
public:
    virtual void get_shell() override {
        puts("interactive mode Disable\n");
        printf("but do you like flag? [Y/n]");
        char c = getchar();
        if(!(c=='n'||c=='N')){
            puts("First blood to you ");
            get_flag("flag.txt");
        }
    }

    virtual void show_message() override {
        RemoteServer::show_message();
        puts("[ Disable system call safe mode ]\n");
    }

    Safe_Server(){
        puts("\n\n############## Safe_Server ####################");
#ifdef OUT
        void* vptr = (void*)((unsigned long long*) this)[0];
        printf("Safe_Server::vptr %p\n", vptr);
#endif
    }

    ~Safe_Server(){
        puts("\n\n##############   ServerEnd  ####################");
    }
};

bool check(Login *log, const char *sign){
    char *input = log->input_key();
#ifdef OUT
    printf("sign<");
    write(1, sign, 16);
    printf("><");
    write(1, input, 16);
    printf(">%d\n", memcmp(sign, input, 16));
#endif

    if (!memcmp(sign, input, 16)) {
        puts("WOW. you can really dance. \n");
        return true;
    }
    log->add_count();
    puts("\33[1;33mtry again\33[0m\n");
    return false;
}

int main() {
    setbuf(stdin,0);
    setbuf(stdout,0);
    setbuf(stderr,0);
    
    
    Safe_Server _server;
    RemoteServer &server = _server;
    server.show_message();
    server.show_machine_code();
    printf("You need to get the server passwd from vendor(xxxxxxx@qq.com) with machine-code\n");
    while(1){
        if(check(server, server.get_sign())){
            break;
        }
#ifdef OUT
        printf("- %p -\n", server.count());
#endif
        if(server.count()>=5) {
            puts("\33[1;31mConnection denied!\33[0m");
            return 0;
        }
    }
    server.get_shell();
    puts("Good");
}