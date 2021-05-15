#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"

#include "fs.h"
#include "sleeplock.h"
#include "file.h"

struct {
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;

int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

static void wakeup1(void *chan);


int nice_value_to_weight[40] = {
/*   0 */  88761,	71755,	56483,	46273,	36291,
/*   5 */  29154,	23254,	18705,	14949,	11916,
/*  10 */   9548,	7620,	6100,	4904,	3906,
/*  15 */   3121,	2501,	1991,	1586,	1277,
/*  20 */   1024,	820,	655,	526,	423,
/*  25 */    335,	272,	215,	172,	137,
/*  30 */    110,	87,	70,	56,	45,
/*  35 */    36,	29,	23,	18,	15};

void
pinit(void)
{
  initlock(&ptable.lock, "ptable");
}

// Must be called with interrupts disabled
int
cpuid() {
  return mycpu()-cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu*
mycpu(void)
{
  int apicid, i;
  
  if(readeflags()&FL_IF)
    panic("mycpu called with interrupts enabled\n");
  
  apicid = lapicid();
  // APIC IDs are not guaranteed to be contiguous. Maybe we should have
  // a reverse map, or reserve a register to store &cpus[i].
  for (i = 0; i < ncpu; ++i) {
    if (cpus[i].apicid == apicid)
      return &cpus[i];
  }
  panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc*
myproc(void) {
  struct cpu *c;
  struct proc *p;
  pushcli();
  c = mycpu();
  p = c->proc;
  popcli();
  return p;
}

//PAGEBREAK: 32
// Look in the process table for an UNUSED proc.
// If found, change state to EMBRYO and initialize
// state required to run in the kernel.
// Otherwise return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;
  char *sp;

  acquire(&ptable.lock);

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == UNUSED)
      goto found;

  release(&ptable.lock);
  return 0;

found:
  p->state = EMBRYO;
  p->pid = nextpid++;
  
  p->long_runtime.front = 0;
  p->long_runtime.end = 0;
  p->long_vruntime.front = 0;
  p->long_vruntime.end = 0;
  p->nice_value = 20;
  p->weight = 1024;
  p->runtime = 0;
  p->vruntime = 0;
  p->time_slice = 0;
  p->now_tick = 0;
  
  total_weight += p->weight;

  release(&ptable.lock);

  // Allocate kernel stack.
  if((p->kstack = kalloc()) == 0){
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;

  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe*)sp;

// Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint*)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context*)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;

  return p;
}

//PAGEBREAK: 32
// Set up first user process.
void
userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];
  total_weight = 0;
  p = allocproc();
  
  initproc = p;
  if((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0;  // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  // this assignment to p->state lets other cores
  // run this process. the acquire forces the above
  // writes to be visible, and the lock is also needed
  // because the assignment might not be atomic.
  acquire(&ptable.lock);

  p->state = RUNNABLE;

  release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint sz;
  struct proc *curproc = myproc();

  sz = curproc->sz;
  if(n > 0){
    if((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  } else if(n < 0){
    if((sz = deallocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  curproc->sz = sz;
  switchuvm(curproc);
  return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

  // Copy process state from proc.
  if((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0){
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  np->sz = curproc->sz;
  np->parent = curproc;
  *np->tf = *curproc->tf;

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for(i = 0; i < NOFILE; i++)
    if(curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;

  acquire(&ptable.lock);

  np->state = RUNNABLE;
  np->vruntime = curproc->vruntime;
  np->weight = curproc->weight;
  np->nice_value = curproc->nice_value;
  np->time_slice = curproc->time_slice;
  np->now_tick = curproc->now_tick;
  np->runtime = curproc->runtime;

  // Copy parent's mmap_area to child
  int parent_ma = -1;

  for (i = 0; i < 64; i++) {
	  if (ma_array[i].p->pid == curproc->pid) {
		  parent_ma = i;
		  break;
	  }
  }
  
  struct mmap_area *ma = 0;

  if (parent_ma != -1) {
	  for (i = 0; i < 64; i++) {
		  if (ma_array[i].addr < 0x40000000) {
			  ma = &ma_array[i];
			  break;
	  	}
	  }

      ma->f = ma_array[parent_ma].f;
      ma->addr = ma_array[parent_ma].addr;
      ma->length = ma_array[parent_ma].length;
      ma->offset = ma_array[parent_ma].offset;
      ma->prot = ma_array[parent_ma].prot;
      ma->flags = ma_array[parent_ma].flags;
      ma->p = np;

  }


  release(&ptable.lock);

  return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void
exit(void)
{
  struct proc *curproc = myproc();
  struct proc *p;
  int fd;

  if(curproc == initproc)
    panic("init exiting");

  // Close all open files.
  for(fd = 0; fd < NOFILE; fd++){
    if(curproc->ofile[fd]){
      fileclose(curproc->ofile[fd]);
      curproc->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(curproc->cwd);
  end_op();
  curproc->cwd = 0;

  total_weight -= curproc->weight;

  acquire(&ptable.lock);

  // Parent might be sleeping in wait().
  wakeup1(curproc->parent);

  // Pass abandoned children to init.
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->parent == curproc){
      p->parent = initproc;
      if(p->state == ZOMBIE)
        wakeup1(initproc);
    }
  }
  
  // Jump into the scheduler, never to return.
  curproc->state = ZOMBIE;
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(void)
{
  struct proc *p;
  int havekids, pid;
  struct proc *curproc = myproc();
  
  acquire(&ptable.lock);
  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->parent != curproc)
        continue;
      havekids = 1;
      if(p->state == ZOMBIE){
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        p->state = UNUSED;
        release(&ptable.lock);
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || curproc->killed){
      release(&ptable.lock);
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sleep(curproc, &ptable.lock);  //DOC: wait-sleep
  }
}

//PAGEBREAK: 42
// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run
//  - swtch to start running that process
//  - eventually that process transfers control
//      via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;

  uint min_vruntime = 4294967295;
  //struct long_int min_vruntime;
  //min_vruntime.front = 4294967295;
  //min_vruntime.end = 4294967295;
  struct proc *tmp = 0;
  int flag = 0;

  for(;;){
    // Enable interrupts on this processor.
    sti();
    flag = 0;
    min_vruntime = 4294967295;
    //min_vruntime.front = 4294967295;
    //min_vruntime.end = 4294967295;

    // Loop over process table looking for process to run.
    acquire(&ptable.lock);
    
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->state != RUNNABLE)
        continue;
      
      if (p->vruntime < min_vruntime) {
      //if (p->long_vruntime.front < min_vruntime.front || (p->long_vruntime.front == min_vruntime.front && p->long_vruntime.end < min_vruntime.end));
	      min_vruntime = p->vruntime;
	      //min_vruntime.front = p->long_vruntime.front;
	      //min_vruntime.end = p->long_vruntime.end;

	      tmp = p;
	      flag = 1;
      }
    }

    if (flag == 1) {
      tmp->time_slice = 10000*(tmp->weight)/total_weight;
      tmp->now_tick = 0;
      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      c->proc = tmp;
      switchuvm(tmp);
      tmp->state = RUNNING;

      swtch(&(c->scheduler), tmp->context);
      switchkvm();
    
      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    release(&ptable.lock);
  }
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&ptable.lock))
    panic("sched ptable.lock");
  if(mycpu()->ncli != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(readeflags()&FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;
  swtch(&p->context, mycpu()->scheduler);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  acquire(&ptable.lock);  //DOC: yieldlock
  myproc()->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void
forkret(void)
{
  static int first = 1;
  // Still holding ptable.lock from scheduler.
  release(&ptable.lock);

  if (first) {
    // Some initialization functions must be run in the context
    // of a regular process (e.g., they call sleep), and thus cannot
    // be run from main().
    first = 0;
    iinit(ROOTDEV);
    initlog(ROOTDEV);
  }

  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();
  
  if(p == 0)
    panic("sleep");

  if(lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  if(lk != &ptable.lock){  //DOC: sleeplock0
    acquire(&ptable.lock);  //DOC: sleeplock1
    release(lk);
  }
  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  if(lk != &ptable.lock){  //DOC: sleeplock2
    release(&ptable.lock);
    acquire(lk);
  }
}

//PAGEBREAK!
// Wake up all processes sleeping on chan.
// The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == SLEEPING && p->chan == chan)
      p->state = RUNNABLE;
}

// Wake up all processes sleeping on chan.
void
wakeup(void *chan)
{
  acquire(&ptable.lock);
  wakeup1(chan);
  release(&ptable.lock);
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
int
kill(int pid)
{
  struct proc *p;

  acquire(&ptable.lock);
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      p->killed = 1;
      // Wake process from sleep if necessary.
      if(p->state == SLEEPING)
        p->state = RUNNABLE;
      release(&ptable.lock);
      return 0;
    }
  }
  release(&ptable.lock);
  return -1;
}

//PAGEBREAK: 36
// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [EMBRYO]    "embryo",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };
  int i;
  struct proc *p;
  char *state;
  uint pc[10];

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if(p->state == SLEEPING){
      getcallerpcs((uint*)p->context->ebp+2, pc);
      for(i=0; i<10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
  }
}

int
getnice(int pid)
{
  struct proc *p;
  acquire(&ptable.lock);

  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state != 0 && p->pid == pid)
      break;
  }

  release(&ptable.lock);
  if (p->state != 0) return p->nice_value;
  else return -1;
}

int
setnice(int pid, int value)
{
  struct proc *p;
  acquire(&ptable.lock);
  

  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if (p->state != 0 && p->pid == pid) 
      break;
  }

  release(&ptable.lock);

  if (p->state != 0) {
	  p->nice_value = value;
	  
	  total_weight -= p->weight;
	  p->weight = nice_value_to_weight[value];
	  total_weight += p->weight;
	  return 0;
  }
  else return -1;
}

void
ps(int pid)
{
  struct proc *p;
  acquire(&ptable.lock);
  
  if (pid == 0) {
    cprintf("name\t\tpid\tstate\t\tpriority\truntime/weight\truntime\t\tvruntime\t\ttick %d\n", ticks*1000);

    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++) {
      if (p->state != 0) {
        cprintf("%s\t\t%d\t", p->name, p->pid);

	if (p->state == 1) cprintf("EMBRYO\t\t");
        else if (p->state == 2) cprintf("SLEEPING\t");
        else if (p->state == 3) cprintf("RUNNABLE\t");
        else if (p->state == 4) cprintf("RUNNING\t\t");
        else if (p->state == 5) cprintf("ZOMBIE\t\t");

	cprintf("%d\t\t%d\t\t%d\t\t%d\n", p->nice_value, p->runtime/p->weight, p->runtime, p->vruntime);
      }
    }
  }

  else {
    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++) {
      if (p->state != 0 && p->pid == pid) {
    	cprintf("name\t\tpid\tstate\t\tpriority\truntime/weight\truntime\t\tvruntime\t\ttick %d\n", ticks*1000);
        cprintf("%s\t\t%d\t", p->name, p->pid);

	if (p->state == 1) cprintf("EMBRYO\t\t");
        else if (p->state == 2) cprintf("SLEEPING\t");
        else if (p->state == 3) cprintf("RUNNABLE\t");
        else if (p->state == 4) cprintf("RUNNING\t\t");
        else if (p->state == 5) cprintf("ZOMBIE\t\t");

	cprintf("%d\t\t%d\t\t%d\t\t%d\n", p->nice_value, p->runtime/p->weight, p->runtime, p->vruntime);
        break;
      }
    }
  }
  
  release(&ptable.lock);
  return;
}

unsigned int 
mmap(unsigned int _addr, int _len, int prot, int flags, int _fd, int _offset)
{
	int fd = _fd;
	int offset = _offset;

	if (flags == MAP_ANONYMOUS) {
		fd = -1;
		offset = 0;
	}

	int i = 0;
	int n = 0;
	int k = 0;
	uint addr = (uint)PGROUNDDOWN(_addr);
	int len = (int)PGROUNDDOWN(_len);
	struct proc *p = myproc();
	struct file *f = p->ofile[fd];
	char* dst = (char*)(0x40000000 + addr);
	char* vm_addr;
	uint phy_addr;
	
	// Failed
	if (flags != MAP_ANONYMOUS && fd == -1)
		return -1;
	else if (prot == PROT_READ && !(f->readable))
		return -1;
	else if (prot == (PROT_READ|PROT_WRITE) && !(f->readable))
		return -1;
	else if (prot == (PROT_READ|PROT_WRITE) && !(f->writable))
		return -1;
	
	// Flags : 0 (file mapping & recording mapping area)
	struct mmap_area *ma = 0;
	
	for (i = 0; i < 64; i++) {
		if (ma_array[i].addr < 0x40000000) {
			ma = &ma_array[i];
			break;
		}
	}
	
	ma->f = f;
	ma->addr = (uint)dst;
	ma->length = len;
	ma->offset = offset;
	ma->prot = prot;
	ma->flags = flags;
	ma->p = p;

	f->off=offset;

	n = len / 4096;

	if (flags == MAP_POPULATE) {
		for (k = 0; k < n; k++) {
			vm_addr = kalloc();
		
			if (vm_addr == 0) panic("kalloc");
			else phy_addr = V2P((uint)vm_addr);

			memset(vm_addr, 0, PGSIZE);
			mappages(p->pgdir, dst+4096*k, PGSIZE, phy_addr, PTE_P|PTE_U);
	
			fileread(f,vm_addr,PGSIZE);
		}
	}

	else if (flags == (MAP_ANONYMOUS|MAP_POPULATE)) {
		for (k = 0; k < n; k++) {
			vm_addr = kalloc();

			if (vm_addr == 0) panic("kalloc");
			else phy_addr = V2P((uint)vm_addr);

			memset(vm_addr, 0, PGSIZE);
			mappages(p->pgdir, dst+4096*k, PGSIZE, phy_addr, PTE_P|PTE_U);
		}
	}
	
	return (uint)dst;
}

int
munmap(unsigned int _addr) {
	int i = 0, j = 0, n;
	pte_t *pte;
	uint pa;
	char* va;
	char* addr = (char*)PGROUNDDOWN(_addr);
	struct proc *p = myproc();

	for (i = 0; i < 64; i++) {
		if (ma_array[i].addr == (uint)addr) {
			// Initialize page table and physical memory
			pte = walkpgdir(p->pgdir, addr, 0);
			if (pte != 0) {
				pa = PTE_ADDR(*pte);
				va = P2V(pa);
				n = ma_array[i].length / 4096;

				for (j = 0; j < n; j++) {
					kfree((char*)((uint)va + 4096 * j));
				}
			}

			// Initialize ma_array[i]
			ma_array[i].addr = 0;
			ma_array[i].f = 0;
			ma_array[i].length = 0;
			ma_array[i].offset = 0;
			ma_array[i].prot = 0;
			ma_array[i].flags = 0;
			ma_array[i].p = 0;

			break;
		}
	}
	
	if (i == 64)
		return -1;
	else
		return 0;
}
