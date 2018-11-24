#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
static void sys_exit(void* esp);
static int sys_wait(void* esp);
static int sys_exec(void* esp);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  void *esp = f->esp;
  int call_id = *((int*) esp);
  esp += 4;
  //printf("call_id = %d\n", call_id);
  if (call_id == SYS_WRITE) {
    //printf("first arg = %d\n", *((int*) esp));
    esp += 4;
    printf("%s",  *((char**)esp));
    esp += 4;
    int third = *((int*) esp);
    f->eax = third;
    //printf("third arg = %d\n", third);
  } else if (call_id == SYS_EXIT) {
    sys_exit(esp);
  } else if (call_id == SYS_HALT) {
    shutdown_power_off();
  } else if (call_id == SYS_WAIT) {
    f->eax = sys_wait(esp);
  } else if (call_id == SYS_EXEC) {
    f->eax = sys_exec(esp);
  } else {
    printf("Unsupported system call, exiting\n");
    thread_exit();
  }
  //printf("finish\n"); 
  //thread_exit ();
}

static void sys_exit(void* esp) {
  int exit_code = *((int*)esp);
  struct thread* t = thread_current();
  t->exit_code = exit_code;
  thread_exit();
}

static int sys_wait(void* esp) {
  //esp += 4;
  tid_t child_id = *((int*) esp);
  int status = process_wait(child_id);
  if (status == -1) {
    thread_exit();
  }
  return status;
}

static int sys_exec(void* esp) {
  const char* cmdline = *((char**) esp);
  return process_execute(cmdline);
}
