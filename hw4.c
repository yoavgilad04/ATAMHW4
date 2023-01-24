#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type
#define	ET_REL	1	//Relocatable file
#define	ET_EXEC	2	//Executable file
#define	ET_DYN	3	//Shared object file
#define	ET_CORE	4	//Core file

#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_RELA 4
#define SHT_DYNSYM 11


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */


bool is_execute(Elf64_Ehdr* elf_header){
    return (elf_header->e_type == ET_EXEC);
}

Elf64_Shdr* get_shdr_by_index(FILE* file, Elf64_Ehdr* elf_header, int index, int ignore){
    Elf64_Shdr* section_headers = (Elf64_Shdr*)malloc(sizeof(*section_headers)*elf_header->e_shnum);
    fseek(file, elf_header->e_shoff, SEEK_SET);
    fread(section_headers, (sizeof(*section_headers)*elf_header->e_shnum),  1, file);
    for(int i = 0; i<elf_header->e_shnum; i++){
        if(section_headers[i].sh_type == index){
            if (ignore == 0 ){
                Elf64_Shdr* sym_shdr = (Elf64_Shdr*)malloc(sizeof(*sym_shdr));
                memcpy(sym_shdr, &section_headers[i], sizeof(*sym_shdr));
                free(section_headers);
                return sym_shdr;
            }
            else{
                ignore--;
            }
        }
    }
    return NULL;
}

char* get_shstr_tab(FILE* file, Elf64_Ehdr* elf_header){
    Elf64_Shdr* section_headers = (Elf64_Shdr*)malloc(sizeof(*section_headers)*elf_header->e_shnum);
    fseek(file, elf_header->e_shoff, SEEK_SET);
    fread(section_headers, (sizeof(*section_headers)*elf_header->e_shnum),  1, file);
    for(int i = 0; i<elf_header->e_shnum; i++){
        if(section_headers[i].sh_type == SHT_STRTAB){
            Elf64_Off offset = section_headers[i].sh_offset;
            Elf64_Xword size = section_headers[i].sh_size;
            char* str_table = (char*)malloc(size);
            fseek(file, offset, SEEK_SET);
            fread(str_table, size, 1, file);
            if (strcmp(".shstrtab", section_headers[i].sh_name + str_table) == 0){
                free(section_headers);
                return str_table;
            }
            else
                free(str_table);
        }
    }
    free(section_headers);
    return NULL;
}

char* get_strtab(FILE* file, Elf64_Ehdr* elf_header, char* sh_str_tab){
    Elf64_Shdr* section_headers = (Elf64_Shdr*)malloc(sizeof(*section_headers)*elf_header->e_shnum);
    fseek(file, elf_header->e_shoff, SEEK_SET);
    fread(section_headers, (sizeof(*section_headers)*elf_header->e_shnum),  1, file);
    for(int i = 0; i<elf_header->e_shnum; i++){
        if(strcmp(".strtab", section_headers[i].sh_name + sh_str_tab)==0) {
            Elf64_Off offset = section_headers[i].sh_offset;
            Elf64_Xword size = section_headers[i].sh_size;
            char* str_table = (char*)malloc(size);
            fseek(file, offset, SEEK_SET);
            fread(str_table, size, 1, file);
            free(section_headers);
            return str_table;
        }
    }
    free(section_headers);
    return NULL;
}

void update_error_val(bool is_exist, bool is_global, bool is_local, bool is_in_ex, int * error_val)
{
    if (is_exist == true)
    {
        if (is_global == true && is_in_ex == true)
            *error_val = 1;
        if (is_local == true && is_global == false)
            *error_val = -2;
        if (is_global == true && is_in_ex == false)
            *error_val = -4;
    }
    else
        *error_val = -1;
}

Elf64_Sym* get_matching_symbol_address(FILE* file, Elf64_Off offset, int num_of_symbols, char* str_table, char*  name, int *error_val ){
    Elf64_Sym* symbols = (Elf64_Sym*)malloc(sizeof(*symbols)*num_of_symbols);
    fseek(file, offset, SEEK_SET);
    fread(symbols, (sizeof(*symbols)*num_of_symbols), 1, file);
    bool is_global = false , is_local = false, is_in_ex = true, is_exist = false;
    Elf64_Sym* matching_symbol_ptr=(Elf64_Sym*)malloc(sizeof(*matching_symbol_ptr));
    for (int i = 0; i<num_of_symbols; i++){
        if(strcmp(name, str_table + symbols[i].st_name) == 0){
            is_exist = true;
            memcpy(matching_symbol_ptr, &symbols[i], sizeof(*matching_symbol_ptr));
            if (ELF64_ST_BIND(symbols[i].st_info) == 0)
                is_local = true;
            if (ELF64_ST_BIND(symbols[i].st_info) == 1)
                is_global = true;
            if (symbols[i].st_shndx == SHN_UNDEF)
                is_in_ex = false;
        }
    }
    update_error_val(is_exist, is_global, is_local, is_in_ex, error_val);
    if (*error_val == 1)
    {
        free(symbols);
        return matching_symbol_ptr;
    }
    else
    {
        free(symbols);
        return NULL;
    }
}



unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {

    FILE* file = fopen(exe_file_name, "rb");
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)malloc(sizeof(*elf_header)); //remember to free this
    fread(elf_header, sizeof((*elf_header)), 1, file);
    if (!is_execute(elf_header)){
        *error_val = -3;
        return 0;
    }
    Elf64_Shdr* sym_shdr = get_shdr_by_index(file, elf_header, SHT_SYMTAB, 0);
    if(sym_shdr == NULL){
        *error_val = -1;
        return 0;
    }
    char* sh_strtab = get_shstr_tab(file, elf_header);
    if(sh_strtab == NULL){
        *error_val = -1;
        return 0;
    }
    char* strtab = get_strtab(file, elf_header, sh_strtab);
    if(strtab == NULL){
        *error_val = -1;
        return 0;
    }
    Elf64_Off sym_offset = sym_shdr->sh_offset;
    Elf64_Xword sym_size = sym_shdr->sh_size;
    Elf64_Xword sym_entsize = sym_shdr->sh_entsize;
    int num_of_symbols = sym_size / sym_entsize;

    Elf64_Sym* matching_symbol = get_matching_symbol_address(file, sym_offset, num_of_symbols, strtab,  symbol_name, error_val);
    free(strtab);
    free(sh_strtab);
    free(sym_shdr);
    free(elf_header);
    if (matching_symbol != NULL)
        return sym_shdr->sh_addr + matching_symbol->st_value;
    return 0;
}

unsigned long find_dynamic_symbol(char* symbol_name, char* exe_file_name) {
    FILE* file = fopen(exe_file_name, "rb");
    if(!file) exit(1);
    Elf64_Ehdr ehdr;
    fread(&ehdr, sizeof(ehdr), 1, file);


    Elf64_Shdr shdr;
    fseek(file, ehdr.e_shoff + ehdr.e_shentsize * ehdr.e_shstrndx, SEEK_SET);
    fread(&shdr, ehdr.e_shentsize, 1, file);

    //find string table
    char * stringTable = (char *) malloc(shdr.sh_size);
    fseek(file, shdr.sh_offset, SEEK_SET);
    fread(stringTable, shdr.sh_size, 1, file);


    Elf64_Rela * rela_table = NULL;
    Elf64_Sym* dyn_symbols = NULL;


    int index = -1;
    int num_of_rela = 0;
    int num_of_symbols = 0;
    char * dynNames = NULL;

    for(int i=0; i<ehdr.e_shnum; i++){
        fseek(file, ehdr.e_shoff + i * sizeof(shdr), SEEK_SET);
        fread(&shdr, sizeof(shdr), 1, file);
        char * curr_section_name = (char *) (stringTable+ shdr.sh_name);
        //printf("rela: %s", curr_section_name);

        //found rela.plt
        if (!strcmp(curr_section_name, ".rela.plt")){
            rela_table = malloc(shdr.sh_size);
            fseek(file, shdr.sh_offset, SEEK_SET);
            fread(rela_table, shdr.sh_size , 1, file);
            num_of_rela = shdr.sh_size / shdr.sh_entsize;

        }

        //found dynsym
        else if (!strcmp(curr_section_name, ".dynsym")){

            dyn_symbols = (Elf64_Sym*) malloc (shdr.sh_size);
            fseek(file, shdr.sh_offset, SEEK_SET);
            fread(dyn_symbols, shdr.sh_size, 1, file);
            num_of_symbols = shdr.sh_size / shdr.sh_entsize;
        }
        
        //found dynstr
        else if (!strcmp(curr_section_name, ".dynstr")){

            dynNames = (char *)malloc (shdr.sh_size);
            fseek(file, shdr.sh_offset, SEEK_SET);
            fread(dynNames, shdr.sh_size, 1, file);

        }

    }
    //search for funcName
    for(int i=0; i<num_of_rela; i++){
        Elf64_Rela curr_rela = rela_table[i];
        char * curr = dynNames + dyn_symbols[ELF64_R_SYM(curr_rela.r_info)].st_name;
        if (!strcmp(curr, symbol_name)){
            //printf("found!\n");
            index=i;
        }
    }

    unsigned long addr = index >-1 ? rela_table[index].r_offset : 0;
    free(rela_table);
    free(dyn_symbols);
    free(dynNames);
    free(stringTable);
    return addr;
}



pid_t run_target(const char* programname) {
    pid_t pid;

    pid = fork();

    if (pid > 0) {
        return pid;

    } else if (pid == 0) {
        /* Allow tracing of this process */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        /* Replace this process's image with the given program */
        execl(programname, programname, NULL);

    } else {
        // fork error
        perror("fork");
        exit(1);
    }
}

void run_breakpoint_debugger(pid_t child_pid, unsigned long sym_addr, bool is_dyn)
{
    int wait_status;
    int counter = 0;
    struct user_regs_struct regs;
    unsigned long addr = sym_addr;
    unsigned long old_addr = sym_addr;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);

    if(is_dyn)
    {
        addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
        addr -= 6;
    }

    // Insert the entries instruction of the function to data
    unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);

    /* Write the trap instruction 'int 3' into the address */
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap);

    /* Let the child run to the breakpoint and wait for it to reach it */
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);

    /* Look at the word at the address we're interested in */

    while(WIFSTOPPED(wait_status))
    {
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

        // getting the return address of the function
        unsigned long return_address = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)regs.rsp, NULL);
        unsigned long rsp = regs.rsp;
        unsigned long return_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)return_address, NULL);
        unsigned long return_data_trap = (return_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void*)return_address, (void*)return_data_trap);
        // Restore the enter of the function instruction

        ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data);
        regs.rip-=1;
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

        // continue executing the function
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        //wait for the function to return
        wait(&wait_status);

        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

        //if this is recursive call, and do not return to the original call
       while(regs.rsp != rsp + 8) {
           //if this is recursive call, and return from the original call. we need to remove the breakpoint

           ptrace(PTRACE_POKETEXT, child_pid, (void*)return_address, (void*)return_data);
           regs.rip -= 1;
           ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
           ptrace(PTRACE_SINGLESTEP,child_pid,NULL,NULL);
           wait(&wait_status);

           ptrace(PTRACE_POKETEXT, child_pid, (void*)return_address, (void*)return_data_trap);

           /* Let the child run to the breakpoint and wait for it to reach it */
           ptrace(PTRACE_CONT, child_pid, NULL, NULL);
           wait(&wait_status);
           ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

       }

        counter++;
        regs.rip-=1;
        printf("PRF:: run #%d returned with %d\n", counter, (int)regs.rax);

        ptrace(PTRACE_POKETEXT, child_pid, (void*)return_address, (void*)return_data);
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

        if(is_dyn && counter==1){
            addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)old_addr, NULL);
            data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
            data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        }

        ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap);
        /* Let the child run to the breakpoint and wait for it to reach it */
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
    }

}

int main(int argc, char *const argv[]) {
    int err = 0;
    unsigned long addr = find_symbol(argv[1], argv[2], &err);
    bool is_dyn = false;

    if (err > 0) is_dyn = false;

    else if (err == -2){
        printf("PRF:: %s is not a global symbol! :(\n", argv[1]);
        return 0;
    }
    else if (err == -1){
        printf("PRF:: %s not found!\n", argv[1]);
        return 0;
    }
    else if (err == -3){
        printf("PRF:: %s not an executable! :(\n", argv[2]);
        return 0;
    }
    else if (err == -4){
        //printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
        addr = find_dynamic_symbol(argv[1], argv[2]);
        is_dyn = true;
    }

    //printf("%s will be loaded to 0x%lx\n", argv[1], addr);
    pid_t child_pid;

    child_pid = run_target(argv[2]);

    // run specific "debugger"
    run_breakpoint_debugger(child_pid, addr, is_dyn);

    return 0;
}