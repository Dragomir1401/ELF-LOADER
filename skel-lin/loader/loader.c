// /*
//  * Loader Implementation
//  *
//  * 2022, Operating Systems
//  */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include "exec_parser.h"
#define ERROR -1
#define FILE_PERMISSION 0644
static so_exec_t *exec;
static struct sigaction old_handler;
int file_descriptor;

static void segv_handler(int signum, siginfo_t *info, void *context)
{
	// fprintf(stderr, "Segfault at address %p\n", info->si_addr);


	// one page size
	int page_size = getpagesize();
	int found_seg_index = -1;
	int self_memory_segfault = 0;

	// case when error is not SIGSEV and we use old handler
	if(signum != SIGSEGV)
	{
		old_handler.sa_sigaction(signum, info, context);
		exit(ERROR);
	}



	// search to see if seg fault happened in what given memory segment
	for(int seg_counter = 0; seg_counter < exec->segments_no; seg_counter++)
		// lower bound and higher bound memory segment check
		if ((uintptr_t)info->si_addr >= exec->segments[seg_counter].vaddr && 
			(uintptr_t)info->si_addr < (exec->segments[seg_counter].vaddr + exec->segments[seg_counter].mem_size))
			{
				// if it passed double if it is in the given segment seg_counter
				found_seg_index = seg_counter;
				self_memory_segfault = 1;
				break;
			}
	// fprintf(stderr, "%d\n", found_seg_index);

	// if SIGSEV did not happen on the given memory we use the old handler
	if(!self_memory_segfault) {
		old_handler.sa_sigaction(signum, info, context);
		exit(ERROR);
	}



	// if data was not alloced yet in that area
	if (exec->segments[found_seg_index].data == NULL) {
		// nr of pages in segment
		int no_of_pages = exec->segments[found_seg_index].mem_size / page_size;
		if (exec->segments[found_seg_index].mem_size % page_size != 0)
			no_of_pages++;

		// alloc the area
		exec->segments[found_seg_index].data = calloc(no_of_pages, sizeof(int));
	}


	// find the nearest mem page after the one where the address was found
	uintptr_t nearest_mem_page = -1;
	nearest_mem_page = ALIGN_DOWN((uintptr_t)(info->si_addr), page_size);

	int no_of_nearest_page = (nearest_mem_page - exec->segments[found_seg_index].vaddr) / page_size;

	// if page was already mapped
	if (((int *)exec->segments[found_seg_index].data)[no_of_nearest_page] == 1)
	{
		old_handler.sa_sigaction(signum, info, context);
		exit(ERROR);
	}


	// offset in the found mem page
	int offset = exec->segments[found_seg_index].offset;

	// alloc memory for the nearest page down in memory	with FIXED, SHARED and ANONYMOUS flags
	void *result_mapped_page;
	result_mapped_page = mmap((void *)nearest_mem_page, page_size, PROT_WRITE | PROT_READ, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	// fprintf(stderr, "result mapped page is at addr %p\n", result_mapped_page);

	((int *)exec->segments[found_seg_index].data)[no_of_nearest_page] = 1;

	if (result_mapped_page == MAP_FAILED)
	{
		exit(ERROR);
	}

	int page_no_segfault = (nearest_mem_page - exec->segments[found_seg_index].vaddr) / page_size;

	// place cursor in the file at the beginning of the mapped mem page
	int seek_code = lseek(file_descriptor, offset + page_no_segfault * page_size, SEEK_SET);
	if(seek_code == ERROR) {
		exit(ERROR);
	}

	// default to read is one page_size
	int size_to_read = page_size;
	// see if file_size ends in another memory page
	

	if ((uintptr_t)result_mapped_page + page_size > exec->segments[found_seg_index].file_size + exec->segments[found_seg_index].vaddr &&
	 exec->segments[found_seg_index].file_size + exec->segments[found_seg_index].vaddr > (uintptr_t)result_mapped_page)
	{
		// case for last page in the mem segment
		size_to_read = exec->segments[found_seg_index].file_size + exec->segments[found_seg_index].vaddr - (int)result_mapped_page;
	}
	else if ((uintptr_t)result_mapped_page + page_size > exec->segments[found_seg_index].file_size + exec->segments[found_seg_index].vaddr)
	{
		// .bss case
		size_to_read = 0;
	}


	read(file_descriptor, result_mapped_page, size_to_read);
	// change permissions to mem segment permissions
	mprotect(result_mapped_page, page_size, exec->segments[found_seg_index].perm);
	// fprintf(stderr, "1\n");
}

int so_init_loader(void)
{
	int rc;
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	rc = sigaction(SIGSEGV, &sa, NULL);
	if (rc < 0) {
		perror("sigaction");
		return -1;
	}
	return 0;
}

int so_execute(char *path, char *argv[])
{
	// get the file descriptor
	file_descriptor = open(path, O_RDONLY | O_CREAT);
	if(file_descriptor == ERROR)
		return ERROR;

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	return -1;
}

// #include "exec_parser.h"
// #include "loader.h"
// #define PAGE_SIZE getpagesize()
// #define SEG_MEM 0
// #define SEG_FILEMEM 1

// static so_exec_t *exec;
// int exec_file;
// static struct sigaction def_segv_handler;

// static void segv_handler(int signum, siginfo_t *info, void *context)
// {
// 	char *sig_addr = info->si_addr;
// 	if (signum != SIGSEGV || (char *)exec->segments[0].vaddr > sig_addr)
// 	{
// 		def_segv_handler.sa_sigaction(signum, info, context);
// 		return;
// 	}

// 	int seg_id = 0;

// 	while (seg_id < exec->segments_no)
// 	{
// 		if (so_getaddr(exec, seg_id, SEG_MEM) > sig_addr)
// 			break;
// 		seg_id++;
// 	}

// 	if (seg_id == exec->segments_no)
// 	{
// 		def_segv_handler.sa_sigaction(signum, info, context);
// 	}

// 	int pagenum = (sig_addr - so_getaddr(exec, seg_id, SEG_FILEMEM)) / PAGE_SIZE;
// 	int read_size;

// 	char *close_page = (char *)ALIGN_DOWN((uintptr_t)sig_addr, PAGE_SIZE);
// 	char *new_addr = mmap(close_page, PAGE_SIZE, PERM_W, MAP_SHARED | MAP_ANON | MAP_FIXED, 0, 0);

// 	if (new_addr == MAP_FAILED)
// 	{
// 		printf("MAPPING ERROR AT MMAP!\n");
// 		exit(-1);
// 	}

// 	if (close_page + PAGE_SIZE > so_getaddr(exec, seg_id, SEG_FILEMEM) && close_page < so_getaddr(exec, seg_id, SEG_FILEMEM))
// 	{
// 		read_size = so_getaddr(exec, seg_id, SEG_FILEMEM) - close_page;
// 	}
// 	else if (close_page == so_getaddr(exec, seg_id, SEG_FILEMEM))
// 	{
// 		read_size = 0;
// 	}

// 	lseek(exec_file, exec->segments[seg_id].offset + pagenum * PAGE_SIZE, SEEK_SET);
// 	read(exec_file, new_addr, read_size);

// 	int perms = mprotect(new_addr, PAGE_SIZE, exec->segments[seg_id].perm);
// 	if (perms == -1)
// 		exit(-1);
// }

// char *so_getaddr(so_exec_t *exec, int seg_id, int type)
// {
// 	switch (type)
// 	{
// 	case SEG_MEM:
// 		return (char *)(exec->segments[seg_id].vaddr + exec->segments[seg_id].mem_size);
// 		break;
// 	case SEG_FILEMEM:
// 		return (char *)(exec->segments[seg_id].vaddr + exec->segments[seg_id].file_size);
// 		break;
// 	}
// 	return NULL;
// }

// int so_init_loader(void)
// {
// 	int rc;
// 	struct sigaction sa;

// 	memset(&sa, 0, sizeof(sa));
// 	sa.sa_sigaction = segv_handler;
// 	sa.sa_flags = SA_SIGINFO;
// 	rc = sigaction(SIGSEGV, &sa, NULL);
// 	if (rc < 0)
// 	{
// 		perror("sigaction");
// 		return -1;
// 	}
// 	return 0;
// }

// int so_execute(char *path, char *argv[])
// {
// 	exec = so_parse_exec(path);
// 	if (!exec)
// 		return -1;

// 	exec_file = open(path, PERM_R);
// 	so_start_exec(exec, argv);

// 	return -1;
// }
