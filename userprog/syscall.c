#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/init.h"
struct lock filesys_lock;


void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init(void) {

	lock_init(&filesys_lock);

	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
		((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
		FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}



/* The main system call interface */
void
syscall_handler(struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	// rdi, rsi, rdx, r10, r8, r9

	uint64_t syscall_number = f->R.rax;
	switch (syscall_number) {

	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
		// case SYS_FORK:
		// 	fork(f->R.rdi);
		// 	break;
		// case SYS_EXEC:
		// 	exec(f->R.rdi);
		// 	break;
		// case SYS_WAIT:
		// 	wait(f->R.rdi);
		// 	break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = (f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rdx);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	default:
		exit(-1);
		break;
	}
	// printf("%d system call!\n", syscall_number);
	// thread_exit();
}

void
check_address(void *addr) {
	/*포인터가 가리키는 주소가 유저영역의 주소인지 확인하고, 잘못된 접근일 경우 프로세스 종료*/
	struct thread *t = thread_current();
	// pml4_get_page 함수로 user vaddr space 내에서 할당되지 않은 공간을 가리키는 것도 체크
	if (!is_user_vaddr(addr) || addr == NULL || pml4_get_page(t->pml4, addr) == NULL) {
		exit(-1);
	}
}

void
halt(void)
{
	power_off();
}

void
exit(int status) {
	/* thread_current() -> status = THREAD_DYING;
	 이는 thread_exit() 내에서 처리되므로 따로 안해줘도 됨 */
	thread_current()->exit_status = status;
	thread_exit();
}

bool create(const char *file, unsigned initial_size) {
	check_address(file); // 잘못된 참조면 바로 process terminate
	return filesys_create(file, initial_size);
}

bool remove(const char *file) {
	check_address(file);
	return filesys_remove(file);
}


int open(const char *file) {
	check_address(file);
	struct thread *cur = thread_current();
	struct file *fp = filesys_open(file);
	if (fp) {
		for (int i = 3; i < 128; i++) {
			if (cur->fdt[i] == NULL) {
				cur->fdt[i] = fp;
				return i;
			}
		}
		file_close(fp);
	}
	return -1;
}


int filesize(int fd) {
	struct file *fp = thread_current()->fdt[fd];
	if (fp)
		return file_length(fp);
	return -1;
}


int read(int fd, void *buffer, unsigned size) {
	check_address(buffer);
	if (fd == 1)
		return -1;
	int byte;
	if (fd == 0) {
		byte = input_getc();
		return byte;
	}
	struct thread *cur = thread_current();
	struct file *fp = cur->fdt[fd];
	if (fp) {
		byte = file_read(fp, buffer, size);

		return byte;
	}
	return -1;
}



int write(int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	if (fd == 1) {
		putbuf(buffer, size);
		return size;
	}
	else if (fd > 2) {
		struct thread *cur = thread_current();
		struct file *fp = cur->fdt[fd];
		if (fp) {
			lock_acquire(&filesys_lock);
			int byte = file_write(fp, buffer, size);
			lock_release(&filesys_lock);
			return byte;
		}
	}
	return -1;
}

/* Sets the current position in FILE to NEW_POS bytes from the
 * start of the file. */
void
seek(int fd, unsigned position) {
	struct file *fp = thread_current()->fdt[fd];
	if (fd) {
		file_seek(fd, position);
	}
}

/* Returns the current position in FILE as a byte offset from the
 * start of the file. */
unsigned
tell(int fd) {
	struct file *fp = thread_current()->fdt[fd];
	if (fd) {
		return file_tell(fp);
	}
}


void
close(int fd) {
	struct file * fp = thread_current()->fdt[fd];
	if (fp) {
		lock_acquire(&filesys_lock);
		file_close(fp);
		thread_current()->fdt[fd] = NULL;
		lock_release(&filesys_lock);
	}
	filesys_done();
}