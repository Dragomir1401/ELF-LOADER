/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include "exec_parser.h"
#define ERROR -1
static so_exec_t *exec;
static struct sigaction old_handler;
int file_descriptor;

static void segv_handler(int signum, siginfo_t *info, void *context)
{
	// one page size
	int page_size = getpagesize();
	int found_seg_index = -1;
	// address where segfault happened
	uintptr_t seg_fault_addr = (uintptr_t)info->si_addr;
	// flags for mapping
	int mmap_flags = MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS;
	// protections for mmap
	int mmap_prots = PROT_WRITE | PROT_READ;

	// case when error is not SIGSEV and we use old handler
	if (signum != SIGSEGV) {
		old_handler.sa_sigaction(signum, info, context);
		exit(ERROR);
	}

	// search to see if seg fault happened in what given memory segment
	for (int seg_counter = 0; seg_counter < exec->segments_no; seg_counter++) {
		uintptr_t start_addr = exec->segments[seg_counter].vaddr;
		uintptr_t end_addr = start_addr + exec->segments[seg_counter].mem_size;

		// lower bound and higher bound memory segment check
		if (seg_fault_addr >= start_addr && seg_fault_addr < end_addr) {
			found_seg_index = seg_counter;
			break;
		}
	}

	// if SIGSEV did not happen on the given memory we use the old handler
	if (found_seg_index == -1) {
		old_handler.sa_sigaction(signum, info, context);
		exit(ERROR);
	}


	// start address of the found memory segment
	uintptr_t found_start_addr = exec->segments[found_seg_index].vaddr;
	// file size of the found memory segment
	uintptr_t found_file_size = exec->segments[found_seg_index].file_size;


	// if data was not allocated yet in that area
	if (exec->segments[found_seg_index].data == NULL) {
		// nr of pages in segment
		int no_of_pages = exec->segments[found_seg_index].mem_size / page_size;

		if (exec->segments[found_seg_index].mem_size % page_size != 0)
			no_of_pages++;

		// alloc the area and fill with zeros
		exec->segments[found_seg_index].data = calloc(no_of_pages, sizeof(int));
	}

	// find the nearest memory page after the one where the address was found
	uintptr_t nearest_mem_page = -1;
	nearest_mem_page = ALIGN_DOWN((uintptr_t)(seg_fault_addr), page_size);

	// number of the nearest memory page down
	int no_of_nearest_page = (nearest_mem_page - found_start_addr) / page_size;

	// if page was already mapped
	if (((int *)exec->segments[found_seg_index].data)[no_of_nearest_page] == 1) {
		old_handler.sa_sigaction(signum, info, context);
		exit(ERROR);
	}


	// offset in the found mem page
	int offset = exec->segments[found_seg_index].offset;

	// alloc memory for the nearest page down in memory	with FIXED, SHARED and ANONYMOUS flags
	void *result_mapped_page;
	result_mapped_page = mmap((void *)nearest_mem_page, page_size, mmap_prots, mmap_flags, -1, 0);

	// put 1 in the array to know if we will try to map the same page
	((int *)exec->segments[found_seg_index].data)[no_of_nearest_page] = 1;

	if (result_mapped_page == MAP_FAILED)
		exit(ERROR);
	

	// place cursor in the file at the beginning of the mapped mem page
	int seek_code = lseek(file_descriptor, offset + no_of_nearest_page * page_size, SEEK_SET);
	// check seek error
	if (seek_code == ERROR)
		exit(ERROR);

	// default to read is one page_size
	int size_to_read = page_size;

	int higher_bound_check = (uintptr_t)result_mapped_page + page_size > found_file_size + 
							 found_start_addr;

	// see if file_size ends in another memory page
	if (higher_bound_check) {
		if (found_file_size + found_start_addr > (uintptr_t)result_mapped_page) {
			// case for copying less than an entire page size
			size_to_read = found_file_size + found_start_addr - (int)result_mapped_page;
		} else {
			// .bss case
			size_to_read = 0;
		}
	}

	// copy data in that page
	read(file_descriptor, result_mapped_page, size_to_read);
	// change permissions to mem segment permissions
	mprotect(result_mapped_page, page_size, exec->segments[found_seg_index].perm);
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
	if (file_descriptor == ERROR)
		return ERROR;

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	return -1;
}
