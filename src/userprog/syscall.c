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
  void *esp = f->esp;
  //printf("syscall handler begin\n");
  int call_id = *((int*) esp);
  if (call_id == SYS_WRITE) {
    esp += 4;
    //printf("first arg = %d\n", *((int*) esp));
    esp += 4;
    printf("%s",  *((char**)esp));
    esp += 4;
    int third = *((int*) esp);
    f->eax = third;
    //printf("third arg = %d\n", third);
  } else if (call_id == SYS_EXIT) {
    thread_exit();
  } else {
    printf("Unsupported system call, exiting\n");
    thread_exit();
  }
  //printf("finish\n"); 
  //thread_exit ();
}
