#include "elf64.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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

pid_t run_target(const char* programname)
{
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

int main(int argc, char** argv)
{
	//find elf header:
	FILE* file = fopen(argv[2], "rb");
	if(!file) exit(1);
    Elf64_Ehdr ehdr;
	if (fread(&ehdr, sizeof(ehdr), 1, file) != 1) {
		fclose(file);
		exit(1);
	}

	/*
	//find shstrtab:
	Elf64_Shdr shstrtab;
	if(ehdr.e_shstrndx==0){
		fclose(file);
		exit(1);
	}
	fseek(file, ehdr.e_shoff + ehdr.e_shstrndx * sizeof(shstrtab), SEEK_SET);
	if(fread(&shstrtab, sizeof(shstrtab), 1, file)!=1){
		fclose(file);
		exit(1);
	}
	char *names = malloc (shstrtab.sh_size);
	if(names==NULL){
		fclose(file);
		exit(1);
	}
	fseek(file, shstrtab.sh_offset, SEEK_SET);
	if(fread(names, shstrtab.sh_size, 1, file)!=1){
		free(names);
		fclose(file);
		exit(1);
	}
	*/
	
	//find the symtab and strtab:
	Elf64_Shdr symtab;
	Elf64_Shdr strtab;
	char *sym_names = NULL;
	Elf64_Sym* symbols = NULL;
	int index_of_func = -1;
	for(int i=0; i<ehdr.e_shnum; i++){
		fseek(file, ehdr.e_shoff + i * sizeof(symtab), SEEK_SET);
		if(fread(&symtab, sizeof(symtab), 1, file)!=1){
			//free(names);
			fclose(file);
			exit(1);
		}
		if(symtab.sh_type==2) {
			fseek(file, ehdr.e_shoff + symtab.sh_link * sizeof(strtab), SEEK_SET);
			if(fread(&strtab, sizeof(strtab), 1, file)!=1){
				//free(names);
				fclose(file);
				exit(1);
			}
			sym_names = malloc(strtab.sh_size);
			symbols = malloc(symtab.sh_size);
			if(symbols==NULL || sym_names==NULL){
				free(symbols);
				free(sym_names);
				//free(names);
				fclose(file);
				exit(1);
			}
			fseek(file, symtab.sh_offset, SEEK_SET);
			if(fread(symbols, symtab.sh_size, 1, file)!=1){
				free(symbols);
				free(sym_names);
				//free(names);
				fclose(file);
				exit(1);
			}
			fseek(file, strtab.sh_offset, SEEK_SET);
			if(fread(sym_names, strtab.sh_size, 1, file)!=1){
				free(symbols);
				free(sym_names);
				//free(names);
				fclose(file);
				exit(1);
			}
			for(int j=0; j<(symtab.sh_size / symtab.sh_entsize); j++){
				if(strcmp(sym_names + symbols[j].st_name, argv[1])==0){
					index_of_func=j;
					break;
				}
			}
			if(index_of_func!=-1 && (symbols[index_of_func].st_info >> 4) == 0){
				printf("PRF:: local found!\n");
				free(symbols);
				free(sym_names);
				//free(names);
				fclose(file);
				exit(1);
			}
			if(index_of_func!=-1 && (symbols[index_of_func].st_info >> 4) == 1){
				break;
			}
			free(symbols);
			symbols=NULL;
			free(sym_names);
			sym_names=NULL;
		}
	}
	if(index_of_func == -1){
		printf("PRF:: not found!\n");
		free(symbols);
		free(sym_names);
		//free(names);
		fclose(file);
		exit(1);
	}
	
	unsigned long address_of_func = symbols[index_of_func].st_value;
	free(symbols);
	free(sym_names);
	//free(names);
	fclose(file);

	//debbuging the func:
	pid_t child_pid = run_target(argv[2]);
	int wait_status;
	struct user_regs_struct regs;
	wait(&wait_status);
	unsigned long original_instr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)address_of_func, NULL);
	unsigned long data_trap = ((original_instr & 0XFFFFFFFFFFFFFF00) | 0xCC);
	ptrace(PTRACE_POKETEXT, child_pid, (void*)address_of_func, (void*)data_trap);
	ptrace(PTRACE_CONT, child_pid, NULL, NULL);
	wait(&wait_status);

	while(WIFSTOPPED(wait_status)){
		ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
		unsigned long long ret_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)regs.rsp, NULL);
		unsigned long long rsp=regs.rsp;
		unsigned long ret_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)ret_addr, NULL);
		unsigned long ret_trap = ((ret_data & 0XFFFFFFFFFFFFFF00) | 0xCC);
		ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_trap);
		ptrace(PTRACE_POKETEXT, child_pid, (void*)address_of_func, (void*)original_instr);
		regs.rip--;
		ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
		ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);

		wait(&wait_status);
		//we are gonna get here because of syscall or got to return address

		ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
		//this while loop check if we got here because of syscall,
		//and that it is not a recurrsive call back to the caller function (as callee this time)
		while(regs.rip != ret_addr+1 || regs.rsp!=rsp+8){
			//this if statement check if we got back to the caller function as recurssive call, so we need to remove the breakpoint
			if(regs.rip == ret_addr+1 && regs.rsp!=rsp+8){
				ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_data);
				regs.rip--;
				ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
				ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
				wait(&wait_status);
				ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
				wait(&wait_status);
				ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
				//checking the return value of syscall
				if((long long)regs.rax < 0){
					printf("PRF:: syscall in %llx returned with %lld\n", regs.rip-2, (long long)regs.rax);
				}
				ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_trap);
				ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
				wait(&wait_status);
				ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
				continue;
			}
			//we get here if there was a syscall not in the caller function
			ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
			wait(&wait_status);
			ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
			//checking the return value of syscall
			if((long long)regs.rax < 0){
				printf("PRF:: syscall in %llx returned with %lld\n", regs.rip-2, (long long)regs.rax);
			}
			ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
			wait(&wait_status);
			ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
		}
		//we get here if we go back to return address, then we will put its data back
		ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_data);
		regs.rip--;
		ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

		//putting breakpoint back
		ptrace(PTRACE_POKETEXT, child_pid, (void*)address_of_func, (void*)data_trap);
		ptrace(PTRACE_CONT, child_pid, NULL, NULL);
		wait(&wait_status);
	}
	//we get here if we stopped not because of a breakpoint, aka end of program
	//so we put original data back
	ptrace(PTRACE_POKETEXT, child_pid, (void*)address_of_func, (void*)original_instr);
	return 0;
}