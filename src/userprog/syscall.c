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
  printf("syscall handler begin\n");
  int call_id = *((int*) esp);
  if (call_id == 9) {
    esp += 4;
    printf("first arg = %d\n", *((int*) esp));
    esp += 4;
    printf("arg value = %s\n",  *((char**)esp));
    esp += 4;
    int third = *((int*) esp);
    f->eax = third;
    printf("third arg = %d\n", third);
  } else {
    printf("unsupported system call\n");
  }
  printf("finish\n"); 
  //thread_exit ();
}
