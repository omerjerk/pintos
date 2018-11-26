#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/off_t.h"
#include "userprog/exception.h"
#define MAX_FD 100
#define MIN_FD 2
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

static bool is_addr_ok(const void* addr) {
    if (is_user_vaddr(addr)) {
      struct thread* curr = thread_current();
      if (pagedir_get_page(curr->pagedir, addr) != NULL) {
        return true;
      }
    }
    return false;
}

static bool check_next_four_addrs(const void* esp) {
  if (!is_addr_ok(esp) || !is_addr_ok(esp+1)
      || !is_addr_ok(esp+2) || !is_addr_ok(esp+3)) {
    return false;
  }
  return true;
}


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  void *esp = f->esp;
  if (!check_next_four_addrs(esp)) {
    exit(-1);
  }
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
  } else if (call_id == SYS_CREATE){
    char* file_name = *((char**)esp);
    esp += 4;
    unsigned initial_size = *((unsigned*)esp);
    bool status = create(file_name,initial_size);
    f->eax = status;
  } else if (call_id == SYS_REMOVE){
    char* file_name = *((char**)esp);
    f->eax = remove(file_name);
  } 
  else if (call_id == SYS_OPEN){
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
  } else if(call_id == SYS_SEEK){
    int fd = *((int*)esp);
    esp += 4;
    unsigned position = *((unsigned*)esp);
    seek(fd, position);
  }
  else if (call_id == SYS_EXIT) {
    int exit_code = *((int*)esp);
    exit(exit_code);
  } else if (call_id == SYS_HALT) {
    shutdown_power_off();
  } else if (call_id == SYS_WAIT) {
    tid_t child_id = *((int*) esp);
    f->eax = wait(child_id);
  } else if (call_id == SYS_EXEC) {
    if (!check_next_four_addrs(esp)) {
      exit(-1);
    }
    const char* cmdline = *((char**) esp);
    if (!check_next_four_addrs(cmdline)) {
      exit(-1);
    }
    f->eax = exec(cmdline); 
  } else {
    printf("Unsupported system call, exiting\n");
    thread_exit();
  }
}

struct file* get_file_from_fd(int fd){
  if (fd < MIN_FD || fd > MAX_FD|| fd == NULL){
    exit(-1);
  }
  struct thread* cur = thread_current();
  struct file* fp = cur->fd_to_file[fd];
  if (fp == NULL){
    exit(-1);
  }
  return fp;
}

void initialize_fd(struct thread* t){
  t->next_fd = 2;
    for(int fd=0;fd<=MAX_FD;fd++){
      t->fd_to_file[fd] = NULL;
  }
}
bool create (const char *file, unsigned initial_size){
  if (file == NULL||!check_next_four_addrs(file)){
    exit(-1);
  }
  bool status = filesys_create (file,initial_size);
  return status;
}
bool remove (const char *file){
  if (file == NULL||!check_next_four_addrs(file)){
    exit(-1);
  }
  return filesys_remove(file);
}

int open (const char *file_name){
if (file_name == NULL ){
  return -1;
}
if( !check_next_four_addrs(file_name)){
  exit(-1);
}
struct thread *cur = thread_current();
if (cur->next_fd == 0){
  initialize_fd(cur);
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
   if (buffer == NULL ||!check_next_four_addrs(buffer)){
      exit(-1);
    }
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
   if (buffer == NULL ||!check_next_four_addrs(buffer)){
      exit(-1);
    }
   if (fd == 1){
     char *string_to_write = (char*)buffer;
     printf("%s",string_to_write);
     return size;
  }
  struct file* fp = get_file_from_fd(fd);
  int bytes_written = file_write(fp,buffer,size);
  return bytes_written;
}
void seek(int fd,unsigned position){
  struct file* fp = get_file_from_fd(fd);
  file_seek(fp,position);  
}

static void exit(int exit_code) { 
  struct thread* t = thread_current();
  t->exit_code = exit_code;
  thread_exit();
}

static int wait(tid_t child_id) { 
  int status = process_wait(child_id);
  if (status == -2) {
    struct thread* t = thread_current();
    t->exit_code = -1;
    thread_exit();
  }
  return status;
}

static int exec(const char* cmdline) {
  return process_execute(cmdline);
}
