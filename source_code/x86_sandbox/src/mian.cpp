
#include "main.h"

#define MB (0x2000)
#define GDT_ADDR 0x3000

#define FSMSR  0xC0000100
#define GSMSR  0xC0000101
#define SCRATCH_ADDR  GDT_ADDR
#define SCRATCH_SIZE  0x1000

bool show_info = false;
bool debug = false;
bool tcode = false;
    
    
static bool map(uc_engine* uc, uint64_t address, size_t size, uint32_t perms) {
    size_t max_address = ALIGN(size + address, MB);
    address = ALIGN(address, MB);
    for (; address <= max_address; address += MB) {
        uc_err err = uc_mem_map(uc, address, MB, perms);
        if (err == UC_ERR_OK) {
            continue;
        }
        if (err == UC_ERR_MAP) {
            continue;
        }
        return false;
    }
    return true;
}

void set_msr(uc_engine* uc, uint64_t msr, uint64_t value, uint64_t scratch = SCRATCH_ADDR) {
    //# save clobbered registers
    uint64_t orax, ordx, orcx, orip;
    uc_reg_read(uc, UC_X86_REG_RAX, &orax);
    uc_reg_read(uc, UC_X86_REG_RDX, &ordx);
    uc_reg_read(uc, UC_X86_REG_RCX, &orcx);
    uc_reg_read(uc, UC_X86_REG_RIP, &orip);
    uc_err err;
    //# x86: wrmsr
    char buf[] = { "\x0f\x30" };
    err = uc_mem_write(uc, scratch, buf, 2);

    uint64_t tmp = value & 0xFFFFFFFF;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &tmp);

    tmp = (value >> 32) & 0xFFFFFFFF;
    err = uc_reg_write(uc, UC_X86_REG_RDX, &tmp);

    tmp = msr & 0xFFFFFFFF;
    err = uc_reg_write(uc, UC_X86_REG_RCX, &tmp);
    err = uc_emu_start(uc, scratch, scratch + sizeof(buf) - 1, 0, 1);

    //# restore clobbered registers
    uc_reg_write(uc, UC_X86_REG_RAX, &orax);
    uc_reg_write(uc, UC_X86_REG_RDX, &ordx);
    uc_reg_write(uc, UC_X86_REG_RCX, &orcx);
    uc_reg_write(uc, UC_X86_REG_RIP, &orip);
}

uint64_t get_msr(uc_engine *uc, uint64_t msr, uint64_t scratch = SCRATCH_ADDR) {

    uint64_t orax, ordx, orcx, orip;
    uc_err err;
    //# save clobbered registers
    uc_reg_read(uc, UC_X86_REG_RAX, &orax);
    uc_reg_read(uc, UC_X86_REG_RDX, &ordx);
    uc_reg_read(uc, UC_X86_REG_RCX, &orcx);
    uc_reg_read(uc, UC_X86_REG_RIP, &orip);

        //# x86: rdmsr
    char buf[] = { "\x0f\x32" };
    err = uc_mem_write(uc, scratch, buf, 2);
    uint64_t tmp = msr & 0xFFFFFFFF;
    uc_reg_write(uc, UC_X86_REG_RCX, &tmp);
    err = uc_emu_start(uc, scratch, scratch + sizeof(buf) - 1, 0, 1);
    int32_t eax;
    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    int32_t edx;
    uc_reg_read(uc, UC_X86_REG_EDX, &edx);
    //# restore clobbered registers
    uc_reg_write(uc, UC_X86_REG_RAX, &orax);
    uc_reg_write(uc, UC_X86_REG_RDX, &ordx);
    uc_reg_write(uc, UC_X86_REG_RCX, &orcx);
    uc_reg_write(uc, UC_X86_REG_RIP, &orip);

    return (((uint64_t)edx) << 32) | (eax & 0xFFFFFFFF);
};



unsigned short create_selector(unsigned idx, unsigned TI, unsigned RPL) { //: #TI : 1 LDT 0 : GDT   PRL : 最高级:00  11最低级
    unsigned short to_ret = RPL & 0b11;
    to_ret |= (TI & 0b1) << 2;
    to_ret |= ((idx * 2) & 0b1111111111111) << 3;
    return to_ret;
}

size_t create_gdt_entry(size_t base, size_t limit, size_t DPL, size_t S, size_t TYPE, size_t flags) {
    size_t to_ret = limit & 0xffff;             //[:16]      seg_limit_lo[:16]
        to_ret |= (base & 0xffffff) << 16;      //[16:40]    base[:24]
        to_ret |= (TYPE & 0xf) << 40;           //TYPE(1 << ) | (C << 1) | (R << 1) | A         段的类型特征和存取权限
        //#C:Conforming = 此段中的代码可以从低特权级别调用
        //#R : Readable 如果0，段可以执行，但不读取
        //#A : Accessed 当访问段并通过软件清除时，硬件将此位设置为1  This bit is set to 1 by hardware when the segment is accessed, and cleared by software
        to_ret |= (S & 0xb1) << 44;             //#S: 如果s = 0 这是一个系统段 1是普通代码段或数据段
        to_ret |= (DPL & 0xb11) << 45;          //#DPL 描述符特权级别 0~3
        to_ret |= (1ull & 0xb1) << 47;             //#p:1 Present 如果清楚，则在对该段的任何引用上生成“段不存在”异常If clear, a "segment not present" exception is generated on any reference to this segment
        to_ret |= ((limit >> 16) & 0xf) << 48;  //#[48:52]    seg_limit_hi[16:20]: 存放段最后一个内存单元的偏移量
        to_ret |= (flags & 0xf) << 52;          //#[52:56]    flag: (G << 3) | (D << 2) | (L << 1) | AVL(各1bit)如果G = 0那么段大小为0~1MB, G = 1段大小为4KB~4GB  D或B 这个我还没搞懂 以后再说只要知道32位访问为1
        //#(AVL: linux忽略这个Available :For software use, not used by hardware)
        //#L : Long - mode segment 如果设置为64位段(D必须为零)，则此段中的代码使用64位指令编码If set, this is a 64 - bit segment(and D must be zero), and code in this segment uses the 64 - bit instruction encoding
        //#D = 默认操作数的大小 如果清楚，这是一个16位代码段; 如果设置为32位段If clear, this is a 16 - bit code segment; if set, this is a 32 - bit segment
        //#G = 粒度:如果清除，限制以字节为单位，最大值为220字节。如果设置该限制，则以4096字节页面为单位，最多232字节。If clear, the limit is in units of bytes, with a maximum of 220 bytes.If set, the limit is in units of 4096 - byte pages, for a maximum of 232 bytes.
        to_ret |= ((base >> 24) & 0xff) << 56;  //#[56:64]    base[24:32]
        return to_ret;
}

static void gdt_init(uc_engine* uc, uc_x86_reg reg, unsigned index, size_t base, size_t limit) {
    size_t G = 0, D = 0, L = 1, AVL = 1;
    size_t gdt[2] = { create_gdt_entry(base , limit, 1, 1, 0xf, (G << 3) | (D << 2) | (L << 1) | AVL), 0 };
    unsigned short sel = create_selector(index, 0, 0);
    uc_reg_write(uc, reg, &sel);
    uc_mem_write(uc, GDT_ADDR + index * 16, &gdt, 16);
}


x86_sandbox::x86_sandbox(const char* filename, uc_mode m, bool f) :m_mode(m)
{
    m_err = uc_open(UC_ARCH_X86, m, &m_uc);
    if (m_err) { printf("Failed on uc_open() with error returned: %u\n", m_err); return; }
    if (!is_mode64()) {
        uc_mem_map(m_uc, GDT_ADDR, 0x1000, UC_PROT_WRITE | UC_PROT_READ);
        size_t cr8 = 1;
        uc_reg_write(m_uc, UC_X86_REG_CR8, &cr8);
        uc_x86_mmr gh{ 0, GDT_ADDR, 0x1000, 0x0 };
        uc_reg_write(m_uc, UC_X86_REG_GDTR, &gh);
        uc_reg_write(m_uc, UC_X86_REG_LDTR, &gh);
    }
    else {
        uc_mem_map(m_uc, SCRATCH_ADDR, SCRATCH_SIZE, UC_PROT_ALL);
    }
    read_mem_dump(filename, f);
}

bool x86_sandbox::read_mem_dump(const char* filename, bool f)
{
    struct memdump {
        unsigned long long nameoffset;
        unsigned long long address;
        unsigned long long length;
        unsigned long long dataoffset;
    }buf;
    FILE* infile;
    infile = fopen(filename, "rb");
    if (!infile) {
        printf("%s, %s", filename, "not exit/n");
        getchar();
        exit(1);
    }
    unsigned long long length, fp, err, name_start_offset, name_end_offset, need_write_size = 0;
    fread(&length, 8, 1, infile);
    fseek(infile, 24, SEEK_SET);
    name_start_offset = length;
    fread(&name_end_offset, 8, 1, infile);
    length /= 32;
    char* name_buff = (char*)malloc(name_end_offset - name_start_offset);
    fseek(infile, name_start_offset, SEEK_SET);
    fread(name_buff, 1, name_end_offset - name_start_offset, infile);
    fseek(infile, 0, SEEK_SET);
    char* name;
    if(f)
        printf("Initializing Virtual Memory\n"
    "/------------------------------+--------------------+--------------------+------------\\\n"
    "|              SN              |         VA         |         FOA        |     LEN    |\n"
    "+------------------------------+--------------------+--------------------+------------+\n");

    for (unsigned int segnum = 0; segnum < length; segnum++) {
        fread(&buf, 32, 1, infile);
        unsigned char* data = (unsigned char*)malloc(buf.length);
        fp = ftell(infile);
        fseek(infile, buf.dataoffset, SEEK_SET);
        fread(data, buf.length, 1, infile);
        name = &name_buff[buf.nameoffset - name_start_offset];
        if (GET8(name) == 0x7265747369676572) {
#if 0
            printf("name:%18s address:%016llx data offset:%010llx length:%010llx\n", name, buf.address, buf.dataoffset, buf.length);
#endif

            if (buf.address == UC_X86_REG_FS || buf.address == UC_X86_REG_GS) {
                if (is_mode64()) {
                    set_msr(m_uc, (buf.address == UC_X86_REG_FS) ? FSMSR : GSMSR, GET8(data));
                }
                else {
                    gdt_init(m_uc, (uc_x86_reg)buf.address, buf.address - 30, GET8(data), 0x4000);
                }
            }
            else {
                m_err = uc_reg_write(m_uc, (uc_x86_reg)buf.address, data);
                if (m_err) {
                    printf("Failed to write emulation data to register, quit!\n");
                    return false;
                }
            }
        }
        else {
            if(f)
                printf("| %-28s |  %16llx  |  %16llx  | %10llx |\n", name, buf.address, buf.dataoffset, buf.length);
            map(m_uc, buf.address, buf.length, UC_PROT_ALL);
            need_write_size += buf.length;
            m_err = uc_mem_write(m_uc, buf.address, data, buf.length);
            if (m_err) {
                printf("Failed to write emulation code to memory, quit!\n");
                return false;
            }
        }
        fseek(infile, fp, SEEK_SET);
        free(data);
    }
    if(f){
        printf("\\-------------------------------------------------------------------------------------/\n");
        printf(
            "Need to write    %16lf MByte.\n", ((double)need_write_size) / 0x100000);
    }
    free(name_buff);
    fclose(infile);
}


void x86_sandbox::engine_start() {
    uint64_t rip;
    uc_reg_read(m_uc, UC_X86_REG_RIP, &rip);
    m_err = uc_emu_start(m_uc, rip, 0/*until*/, 0/*timeout*/, 0);
    if (m_err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
            m_err, uc_strerror(m_err));
    }
}

void x86_sandbox::show_regs() {
    uint64_t rax = 0;
    uint64_t rbx = 0;
    uint64_t rcx = 0;
    uint64_t rdx = 0;
    uint64_t rsi = 0;
    uint64_t rdi = 0;
    uint64_t r8  = 0;
    uint64_t r9  = 0;
    uint64_t r10 = 0;
    uint64_t r11 = 0;
    uint64_t r12 = 0;
    uint64_t r13 = 0;
    uint64_t r14 = 0;
    uint64_t r15 = 0;
    uint64_t rsp = 0;
    uint64_t rip = 0;
    uint64_t fs = 0;
    uint64_t gs = 0;

    uc_reg_read(m_uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(m_uc, UC_X86_REG_RBX, &rbx);
    uc_reg_read(m_uc, UC_X86_REG_RCX, &rcx);
    uc_reg_read(m_uc, UC_X86_REG_RDX, &rdx);
    uc_reg_read(m_uc, UC_X86_REG_RSI, &rsi);
    uc_reg_read(m_uc, UC_X86_REG_RDI, &rdi);
    uc_reg_read(m_uc, UC_X86_REG_R8, &r8);
    uc_reg_read(m_uc, UC_X86_REG_R9, &r9);
    uc_reg_read(m_uc, UC_X86_REG_R10, &r10);
    uc_reg_read(m_uc, UC_X86_REG_R11, &r11);
    uc_reg_read(m_uc, UC_X86_REG_R12, &r12);
    uc_reg_read(m_uc, UC_X86_REG_R13, &r13);
    uc_reg_read(m_uc, UC_X86_REG_R14, &r14);
    uc_reg_read(m_uc, UC_X86_REG_R15, &r15);
    uc_reg_read(m_uc, UC_X86_REG_FS, &fs);
    uc_reg_read(m_uc, UC_X86_REG_GS, &gs);
    
    uc_reg_read(m_uc, UC_X86_REG_RIP, &rip);

    printf(">>> RAX = 0x%llx" "\n", (long long unsigned int)rax);
    printf(">>> RBX = 0x%llx" "\n", (long long unsigned int)rbx);
    printf(">>> RCX = 0x%llx" "\n", (long long unsigned int)rcx);
    printf(">>> RDX = 0x%llx" "\n", (long long unsigned int)rdx);
    printf(">>> RSI = 0x%llx" "\n", (long long unsigned int)rsi);
    printf(">>> RDI = 0x%llx" "\n", (long long unsigned int)rdi);
    printf(">>> R8  = 0x%llx" "\n", (long long unsigned int)r8);
    printf(">>> R9  = 0x%llx" "\n", (long long unsigned int)r9);
    printf(">>> R10 = 0x%llx" "\n", (long long unsigned int)r10);
    printf(">>> R11 = 0x%llx" "\n", (long long unsigned int)r11);
    printf(">>> R12 = 0x%llx" "\n", (long long unsigned int)r12);
    printf(">>> R13 = 0x%llx" "\n", (long long unsigned int)r13);
    printf(">>> R14 = 0x%llx" "\n", (long long unsigned int)r14);
    printf(">>> R15 = 0x%llx" "\n", (long long unsigned int)r15);
    printf(">>> fs = 0x%llx" "\n", (long long unsigned int)fs);
    printf(">>> gs = 0x%llx" "\n", (long long unsigned int)gs);
    printf(">>> RIP = 0x%llx" "\n", (long long unsigned int)rip);
}


uc_hook x86_sandbox::add_syscall_hook() {
    uc_hook trace1;
    m_err = uc_hook_add(m_uc, &trace1, UC_HOOK_INSN, (void*)sandbox_safe_syscall, this, 0, -1, UC_X86_INS_SYSCALL);
    return trace1;
}

// callback for tracing instruction
static void hook_code64(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
    printf("RIP is 0x%llx size = %x\n", address, size);
}

// tracing all instructions in the range [ADDRESS, ADDRESS+20]
uc_hook x86_sandbox::add_code_hook() {
    uc_hook trace1;
    m_err = uc_hook_add(m_uc, &trace1, UC_HOOK_CODE, (void*)hook_code64, NULL, 0, -1);
    return trace1;
}
static bool hook_mem_invalid(uc_engine* uc, uc_mem_type type,
    uint64_t address, int size, uint64_t value, void* user_data)
{
    switch (type) {
    case UC_MEM_READ_UNMAPPED:
        printf(">>> Missing memory is being READ at 0x%llx" ", data size = %u, data value = 0x%llx" "\n",
            address, size, value);
        return false;
    case UC_MEM_WRITE_UNMAPPED:
        printf(">>> Missing memory is being WRITE at 0x%llx" ", data size = %u, data value = 0x%llx" "\n",
            address, size, value);
        // return true to indicate we want to continue
        return false;
    }
}


uc_hook x86_sandbox::add_unmap_hook() {
    uc_hook trace1;
    m_err = uc_hook_add(m_uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, (void*)hook_mem_invalid, NULL, 0, -1);
    return trace1;
}




int main(int argc, char** argv, char** envp)
{
    
    setbuf(stdin,0);
    setbuf(stdout,0);
    setbuf(stderr,0);
    for(int n = 0; n < argc;n++){
        if (!strcmp(argv[n], "-info")) {
            show_info = true;
        }
        if (!strcmp(argv[n], "-debug")) {
            debug = true;
        }
        if (!strcmp(argv[n], "-tcode")) {
            tcode = true;
        }
    }
    
    x86_sandbox box("xctf_pwn.dump", UC_MODE_64, show_info);
    
    char xsave[] = { "\x90\x90\x90\x90\x90" };
    char xrstor[] = { "\x90\x90\x90\x90\x90" };
    uc_mem_write(box, 0x7FFFF7DEEF48, xsave, sizeof(xsave) - 1);
    uc_mem_write(box, 0x7FFFF7DEEF64, xrstor, sizeof(xrstor) - 1);
    
    if(tcode) box.add_code_hook();
    box.Disable_file_RDWR();
    
    box.add_syscall_hook();
    box.add_unmap_hook();
    //box.add_code_hook();
    box.show_regs();
    std::cout << "/------------------------Sandbox Start-------------------------\\" << std::endl;
    box.engine_start();
    std::cout << "\\-------------------------Sandbox Exit--------------------------/" << std::endl;
    box.show_regs();
    
    return 0;
}