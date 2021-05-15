#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "x86.h"
#include "traps.h"
#include "spinlock.h"

// Interrupt descriptor table (shared by all CPUs).
struct gatedesc idt[256];
extern uint vectors[];  // in vectors.S: array of 256 entry pointers
struct spinlock tickslock;
uint ticks;

int
page_fault_handler(struct trapframe *tf)
{
	int i = 0;
	struct proc *p = myproc();
	struct mmap_area *ma = 0;


  uint va = rcr2();
	 //read error : tf->err&2 == 0
	 //write error : tf->err&2 == 1

  for (int i = 0; i < 64; i++) {
	if (ma_array[i].addr == va) {
	  ma = &ma_array[i];		
	}
  }

  // No corresponding mmap_area
  if (i == 64)
	  return -1;

  int err_code=(tf->err)&2;

  // Case of fault was write and write prohibited
  if ((err_code == 1) && ma->prot == (PROT_READ|PROT_WRITE))
	  return -1;

	char* vm_addr=kalloc();
	memset(vm_addr,0,PGSIZE);

	// Not anonymous
	if(ma->flags==0){
		fileread(ma->f,vm_addr,PGSIZE);	
	}

	if(ma->prot==3)
		mappages(p->pgdir,(char *)va,PGSIZE,V2P((uint)vm_addr),PTE_P|PTE_U|PTE_W);
	else 
		mappages(p->pgdir,(char *)va,PGSIZE,V2P((uint)vm_addr),PTE_P|PTE_U);


	return 0;
}

void
tvinit(void)
{
  int i;

  for(i = 0; i < 256; i++)
    SETGATE(idt[i], 0, SEG_KCODE<<3, vectors[i], 0);
  SETGATE(idt[T_SYSCALL], 1, SEG_KCODE<<3, vectors[T_SYSCALL], DPL_USER);

  initlock(&tickslock, "time");
}

void
idtinit(void)
{
  lidt(idt, sizeof(idt));
}

//PAGEBREAK: 41
void
trap(struct trapframe *tf)
{
  if(tf->trapno == T_SYSCALL){
    if(myproc()->killed)
      exit();
    myproc()->tf = tf;
    syscall();
    if(myproc()->killed)
      exit();
    return;
  }

  switch(tf->trapno){
  case T_IRQ0 + IRQ_TIMER:
    if(myproc() != 0){
      myproc()->runtime+=1000;
      myproc()->vruntime=(myproc()->runtime)*1024/(myproc()->weight);
      myproc()->now_tick+=1000;
    }
    if(cpuid() == 0){
      acquire(&tickslock);
      ticks++;
      wakeup(&ticks);
      release(&tickslock);
    }
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE:
    ideintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE+1:
    // Bochs generates spurious IDE1 interrupts.
    break;
  case T_IRQ0 + IRQ_KBD:
    kbdintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_COM1:
    uartintr();
    lapiceoi();
    break;
  case T_IRQ0 + 7:
  case T_IRQ0 + IRQ_SPURIOUS:
    cprintf("cpu%d: spurious interrupt at %x:%x\n",
            cpuid(), tf->cs, tf->eip);
    lapiceoi();
    break;
  case T_PGFLT:
	page_fault_handler(tf);
	break;

  //PAGEBREAK: 13
  default:
    if(myproc() == 0 || (tf->cs&3) == 0){
      // In kernel, it must be our mistake.
      cprintf("unexpected trap %d from cpu %d eip %x (cr2=0x%x)\n",
              tf->trapno, cpuid(), tf->eip, rcr2());
      panic("trap");
    }
    // In user space, assume process misbehaved.
    cprintf("pid %d %s: trap %d err %d on cpu %d "
            "eip 0x%x addr 0x%x--kill proc\n",
            myproc()->pid, myproc()->name, tf->trapno,
            tf->err, cpuid(), tf->eip, rcr2());
    myproc()->killed = 1;
  }

  // Force process exit if it has been killed and is in user space.
  // (If it is still executing in the kernel, let it keep running
  // until it gets to the regular system call return.)
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();

  // Force process to give up CPU on clock tick.
  // If interrupts were on while locks held, would need to check nlock.
  if(myproc() && myproc()->state == RUNNING && myproc()->time_slice <= myproc()->now_tick && tf->trapno == T_IRQ0+IRQ_TIMER)
    yield();

  // Check if the process has been killed since we yielded
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();
}
