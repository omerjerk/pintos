#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int call_id = *((int*) f->esp);
  if (call_id == 9) {
    f->esp += 4;
    printf("first arg = %d\n", *((int*) f->esp));
    f->esp += 4;
    printf("arg value = %s\n",  *((char**)f->esp));
    f->esp += 4;
    printf("third arg = %d\n", *((int*) f->esp));
  } else {
    printf("unsupported system call\n");
  }
  
  thread_exit ();
}
