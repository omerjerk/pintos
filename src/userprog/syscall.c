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
#include "threads/synch.h"
#define MAX_FD 128
#define MIN_FD 2
struct lock file_lock_struct;
struct lock* file_lock;
static void syscall_handler (struct intr_frame *);

void halt_handler (void) NO_RETURN;
static void exit_handler (int status) NO_RETURN;
static tid_t exec_handler (const char *cmdline);
static int wait_handler (tid_t);
bool create_handler (const char *file, unsigned initial_size);
bool remove_handler (const char *file);
int open_handler (const char *file);
int filesize_handler (int fd);
int read_handler (int fd, char* buffer, unsigned size);
int write_handler (int fd, const void *buffer, unsigned size);
void seek_handler (int fd, unsigned position);
unsigned tell (int fd);
void close_handler (int fd);

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
static bool is_executable(char *file_name){
  for(int i = 0;i<next_exec;i++){
    if (exec_arr[i] != NULL && strcmp(file_name,exec_arr[i]) == 0){
      return true;
    }
  }
  return false;
}
void initialize_file_lock(){
  file_lock = malloc(sizeof(struct lock));
  lock_init(file_lock);
}
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  if(file_lock == NULL){
    initialize_file_lock();
  }
  void *esp = f->esp;
  if (!check_next_four_addrs(esp)) {
    exit_handler(-1);
  }
  int call_id = *((int*) esp);
  esp += 4;

  if (call_id == SYS_WRITE) {
    int fd = *((int*) esp);
    esp += 4;
    char *string_to_write = *((char**)esp);
    esp += 4;
    int length = *((int*)esp);
    int num_of_bytes_written = write_handler(fd,string_to_write,length);
    f->eax = num_of_bytes_written;
  } else if (call_id == SYS_CREATE){
    char* file_name = *((char**)esp);
    esp += 4;
    unsigned initial_size = *((unsigned*)esp);
    bool status = create_handler(file_name,initial_size);
    f->eax = status;
  } else if (call_id == SYS_REMOVE){
    char* file_name = *((char**)esp);
    f->eax = remove_handler(file_name);
  } 
  else if (call_id == SYS_OPEN){
    char* file_name = *((char**)esp);
    int fd = open_handler(file_name);
    f->eax = fd;
  } else if (call_id == SYS_FILESIZE){
    int fd = *((int*)esp);
    f->eax = filesize_handler(fd);

  } else if (call_id == SYS_CLOSE){
    int fd = *((int*)esp);
    close_handler(fd);
  } else if(call_id == SYS_READ){
    int fd = *((int*)esp);
    esp += 4;
    char *buf = *((char**)esp);
    esp += 4;
    unsigned size = *((unsigned*)esp);
    f->eax = read_handler(fd,buf,size);
  } else if(call_id == SYS_SEEK){
    int fd = *((int*)esp);
    esp += 4;
    unsigned position = *((unsigned*)esp);
    seek_handler(fd, position);
  }
  else if (call_id == SYS_EXIT) {
    if (!check_next_four_addrs(esp)) {
      exit_handler(-1);
    }
    int exit_code = *((int*)esp);
    exit_handler(exit_code);
  } else if (call_id == SYS_HALT) {
    shutdown_power_off();
  } else if (call_id == SYS_WAIT) {
    tid_t child_id = *((int*) esp);
    f->eax = wait_handler(child_id);
  } else if (call_id == SYS_EXEC) {
    if (!check_next_four_addrs(esp)) {
      exit_handler(-1);
    }
    const char* cmdline = *((char**) esp);
    if (!check_next_four_addrs(cmdline)) {
      exit_handler(-1);
    }
    f->eax = exec_handler(cmdline); 
  } else {
    printf("Unsupported system call, exiting\n");
    thread_exit();
  }
}

struct file* get_file_from_fd(int fd){
  if (fd < MIN_FD || fd > MAX_FD|| fd == NULL){
    exit_handler(-1);
  }
  struct thread* cur = thread_current();
  struct file* fp = cur->fd_to_file[fd];
  if (fp == NULL){
    exit_handler(-1);
  }
  return fp;
}
char* get_file_name_from_fd(int fd){
    if (fd < MIN_FD || fd > MAX_FD|| fd == NULL){
    exit_handler(-1);
  }
  struct thread* cur = thread_current();
  char* file_name = cur->fd_to_file_name[fd];
  if (file_name == NULL){
    exit_handler(-1);
  }
  return file_name;

}

void initialize_fd(struct thread* t){
  t->next_fd = 2;
    for(int fd=0;fd<=MAX_FD;fd++){
      t->fd_to_file[fd] = NULL;
      t->fd_to_file_name[fd] = NULL;
  }
}

bool create_handler (const char *file, unsigned initial_size){
  if (file == NULL||!check_next_four_addrs(file)){
    exit_handler(-1);
  }
  lock_acquire(file_lock);
  bool status = filesys_create (file,initial_size);
  lock_release(file_lock);
  return status;
}

bool remove_handler (const char *file){
  if (file == NULL||!check_next_four_addrs(file)){
    exit_handler(-1);
  } 
  lock_acquire(file_lock);
  bool status = filesys_remove(file);
  lock_release(file_lock);
  return status;
}

int open_handler (const char *file_name) {
  if (file_name == NULL ){
    return -1;
  }
  if( !check_next_four_addrs(file_name)) {
    exit_handler(-1);
    //return -1;
  }
  struct thread *cur = thread_current();
  if (cur->next_fd == 0){
    initialize_fd(cur);
  }
  lock_acquire(file_lock);
  struct file* fp = filesys_open(file_name);
  lock_release(file_lock);
  if (fp ==NULL){
    return -1;
  }
  int fd = cur->next_fd;
  cur->fd_to_file[fd] = fp;
  cur->fd_to_file_name[fd] = file_name;
  cur->next_fd++;
  return fd;
}

int filesize_handler(fd){
  struct file* fp = get_file_from_fd(fd);
  lock_acquire(file_lock);
  int file_size = file_length(fp);
  lock_release(file_lock);
  return file_size;
}
void close_handler(int fd){
  struct file* fp = get_file_from_fd(fd);
  lock_acquire(file_lock);
  file_close(fp);
  lock_release(file_lock);
  struct thread* cur = thread_current();
  cur->fd_to_file[fd] = NULL;
  cur->fd_to_file_name[fd] = NULL;
}

int read_handler (int fd, char *buffer, unsigned size){
   if (buffer == NULL ||!check_next_four_addrs(buffer)){
      exit_handler(-1);
    }
   if (fd == 0){
    return size;
  }
  struct file* fp = get_file_from_fd(fd);
  lock_acquire(file_lock);
  int bytes_read = file_read (fp, buffer, size) ;
  lock_release(file_lock);
  return bytes_read;
}

int write_handler (int fd, const void *buffer, unsigned size){ 
   if (buffer == NULL ||!check_next_four_addrs(buffer)){
      exit_handler(-1);
    }
   if (fd == 1){
     char *string_to_write = (char*)buffer;
     printf("%s",string_to_write);
     return size;
  }
  struct file* fp = get_file_from_fd(fd);
  char* file_name = get_file_name_from_fd(fd);
  
  if (is_executable(file_name)){
    file_deny_write(fp);
  }
  else{
    file_allow_write(fp);
  }
  lock_acquire(file_lock);
  int bytes_written = file_write(fp,buffer,size);
  lock_release(file_lock);
  return bytes_written;
}

void seek_handler(int fd,unsigned position){
  struct file* fp = get_file_from_fd(fd);
  lock_acquire(file_lock);
  file_seek(fp,position); 
  lock_release(file_lock);
}

static void exit_handler(int exit_code) { 
  struct thread* t = thread_current();
  t->exit_code = exit_code;
  thread_exit();
}

static int wait_handler(tid_t child_id) { 
  int status = process_wait(child_id);
  if (status == -2) {
    struct thread* t = thread_current();
    t->exit_code = -1;
    thread_exit();
  }
  return status;
}

static int exec_handler(const char* cmdline) {
  return process_execute(cmdline);
}
