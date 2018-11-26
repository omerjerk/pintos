#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/off_t.h"

static void syscall_handler (struct intr_frame *);

void halt (void) NO_RETURN;
static void exit (int status) NO_RETURN;
static tid_t exec (const char *cmdline);
static int wait (tid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, char* buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

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
  if (call_id == SYS_WRITE) {

    int fd = *((int*) esp);
    esp += 4;
    char *string_to_write = *((char**)esp);
    esp += 4;
    int length = *((int*)esp);
    int num_of_bytes_written = write(fd,string_to_write,length);
    f->eax = num_of_bytes_written;
  }
  else if (call_id == SYS_CREATE){
    char* file_name = *((char**)esp);
    esp += 4;
    unsigned initial_size = *((unsigned*)esp);
    bool status = create(file_name,initial_size);
    f->eax = status;
  } else if (call_id == SYS_OPEN){
    char* file_name = *((char**)esp);
    int fd = open(file_name);
    f->eax = fd;
  } else if (call_id == SYS_FILESIZE){
    int fd = *((int*)esp);
    f->eax = filesize(fd);

  } else if (call_id == SYS_CLOSE){
    int fd = *((int*)esp);
    close(fd);
  } else if(call_id == SYS_READ){
    int fd = *((int*)esp);
    esp += 4;
    char *buf = *((char**)esp);
    esp += 4;
    unsigned size = *((unsigned*)esp);
    f->eax = read(fd,buf,size);
  } else if (call_id == SYS_EXIT) {
    int exit_code = *((int*)esp);
    exit(exit_code);
  } else if (call_id == SYS_HALT) {
    shutdown_power_off();
  } else if (call_id == SYS_WAIT) {
    tid_t child_id = *((int*) esp);
    f->eax = wait(child_id);
  } else if (call_id == SYS_EXEC) {
    const char* cmdline = *((char**) esp);
    f->eax = exec(cmdline); 
  } else {
    printf("Unsupported system call, exiting\n");
    thread_exit();
  }
}

struct file* get_file_from_fd(int fd){
  if (fd < 2 || fd >= 10|| fd == NULL){
    exit(-1);
  }
  struct thread* cur = thread_current();
  struct file* fp = cur->fd_to_file[fd];
  if (fp == NULL){
    exit(-1);
  }
  return fp;
}

bool create (const char *file, unsigned initial_size){
  if (file == NULL){
    exit(-1);
  }
  bool status = filesys_create (file,initial_size);
  return status;
}

int open (const char *file_name){
if (file_name == NULL){
  return -1;
}
struct thread *cur = thread_current();
if (cur->next_fd >= 10 || cur->next_fd < 2){
  cur->next_fd = 2;
  int i = 0;
    for(i=0;i<10;i++){
      cur->fd_to_file[i] = NULL;
  }
}
struct file* fp = filesys_open(file_name);
if (fp ==NULL){
  return -1;
}
int fd = cur->next_fd;
cur->fd_to_file[fd] = fp;
cur->next_fd++;
return fd;
}
int filesize(fd){
  struct file* fp = get_file_from_fd(fd);
  int file_size = file_length(fp);
  return file_size;
}
void close(int fd){
  struct file* fp = get_file_from_fd(fd);
  file_close(fp);
  struct thread* cur = thread_current();
  cur->fd_to_file[fd] = NULL;
}

int read (int fd, char *buffer, unsigned size){
   if (fd == 0){
    char* string_to_read = (char*)buffer;
    return size;
  }
  struct file* fp = get_file_from_fd(fd);
  //file_deny_write(fp);
  int bytes_read = file_read (fp, buffer, size) ;
  return bytes_read;
}

int write (int fd, const void *buffer, unsigned size){ 
  if (fd == 1){
    char *string_to_write = (char*)buffer;
    printf("%s",string_to_write);
    return size;
  }
  struct file* fp = get_file_from_fd(fd);
  int bytes_written = file_write(fp,buffer,size);
  return bytes_written;
}

static void exit(int exit_code) { 
  struct thread* t = thread_current();
  t->exit_code = exit_code;
  thread_exit();
}

static int wait(tid_t child_id) { 
  int status = process_wait(child_id);
  if (status == -1) {
    thread_exit();
  }
  return status;
}

static int exec(const char* cmdline) { 
  return process_execute(cmdline);
}
