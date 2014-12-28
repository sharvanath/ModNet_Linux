/* ModNet's module management functionalities
 * Author: Sharvanath Pathak */
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/linkage.h>
#include <linux/rculist.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <linux/modnet.h>
#include <linux/tcp.h>
#include <linux/poll.h>

/* The Macros and data-structures for maintaining global modules */
#define MAXIMUM_MODNAME 100
static struct modules_table_entry modules_table;
static DEFINE_SPINLOCK(modules_table_lock);

/* The data structure for global modules */
int pending_socks;
struct isock_elem isock_elem_head;

/* The functions for maintaining global modules.
 * Returns the array of per_core_module_info for the given module. */
struct per_core_module_info * find_modnet_module(char __user * identifier, int is_add){

	char * curr_identifier;
	struct modules_table_entry * curr_entry;

	rcu_read_lock();
	list_for_each_entry_rcu(curr_entry, &modules_table.list, list) {
		curr_identifier = curr_entry->identifier;
		if(!strcmp(identifier,curr_identifier))
		{
			if(is_add==1){
				//this field is for testing purpose only, and can be casted and used
				current->module_task = (struct list_head *)curr_entry->module_task;
			}

			rcu_read_unlock();
			return curr_entry->pcore_infos;
		}
	}
	rcu_read_unlock();

	return NULL;

}

int add_modnet_module (char __user * identifier){
	char * ptr;
	struct modules_table_entry * curr_module;
	spinlock_t  * curr_lock;
	atomic_t * curr_interception_atomic;
	wait_queue_head_t * virt_event_wq;
	struct list_head * steal_queue_head;
	int i, err=0;

	if(find_modnet_module(identifier,0))
		return -1;

	ptr = kmalloc((strnlen_user(identifier,MAXIMUM_MODNAME)+1)*sizeof(char),GFP_KERNEL);
	//Todo(sharva) handle error if memory is not allocatable!!!!
	err = strncpy_from_user(ptr,identifier,MAXIMUM_MODNAME);
	if(err<0)
		goto out;

	curr_module = kmalloc(sizeof(struct modules_table_entry),GFP_KERNEL);
	curr_module -> identifier  = ptr;
	curr_module -> module_task = current;
	atomic_long_set(&(curr_module -> ref_cnt),1);

	for(i=0;i<NUM_MOD_QUEUES;i++){
		curr_lock = kmalloc(sizeof(spinlock_t),GFP_KERNEL);
		virt_event_wq = kmalloc(sizeof(wait_queue_head_t),GFP_KERNEL);
		curr_interception_atomic = kmalloc(sizeof(atomic_t),GFP_KERNEL);
		steal_queue_head = kmalloc(sizeof(struct list_head),GFP_KERNEL);
		curr_module -> pcore_infos[i].sock_list = steal_queue_head;
		curr_module -> pcore_infos[i].mod_lock = curr_lock;
		curr_module -> pcore_infos[i].virt_event_wq = virt_event_wq;
		curr_module -> pcore_infos[i].interception_on = curr_interception_atomic;
		//interception is on by defualt
		atomic_set(curr_interception_atomic,1);
		spin_lock_init(curr_lock);
		init_waitqueue_head(virt_event_wq);
		INIT_LIST_HEAD(steal_queue_head);
	}


	current->module_entry = curr_module;
	//adding a pointer to the modules array
	current->pcore_infos_array[0] = curr_module -> pcore_infos;
	// this implies the process is a module. Modules cannot be applied to modules,
	// use the chaining mechanism for that. locking??
	current->total_static_modules = -1;
	spin_lock(&modules_table_lock);
	list_add_rcu(&curr_module->list,&modules_table.list);
	spin_unlock(&modules_table_lock);

	out:
	return err;

}

int free_isocks(struct list_head * head){
	// to be implemented, map back all the sockets in the queue
	// ideally you should also map back all the sockets
	// that belonged to other apps.
	return 0;
}

// Todo(sharva) remove the assumption of only one module for each core.
void delete_modnet_module(struct per_core_module_info * pcore_module_infos, struct task_struct * tsk){
	struct modules_table_entry * curr_entry;

	spin_lock(&modules_table_lock);
	list_for_each_entry(curr_entry, &modules_table.list, list) {
		if( pcore_module_infos == curr_entry->pcore_infos )
		{
			atomic_long_dec(&curr_entry->ref_cnt);
			//ptr = curr_entry;
			spin_unlock(&modules_table_lock);
			goto delete_entry;

		}
	}
	spin_unlock(&modules_table_lock);
	return;

	delete_entry:
	if(atomic_long_read(&curr_entry->ref_cnt)==0)
	{
		list_del_rcu(&curr_entry->list);

		synchronize_rcu();
		kfree(curr_entry->identifier);
		kfree(curr_entry);
	}

}

int modnet_module_exists(struct per_core_module_info * pcore_module_infos){

	struct modules_table_entry * curr_entry;

	rcu_read_lock();
	list_for_each_entry_rcu(curr_entry, &modules_table.list, list) {

		if( pcore_module_infos == curr_entry->pcore_infos )
		{
			rcu_read_unlock();
			return 1;
		}
	}

	rcu_read_unlock();
	return 0;

} EXPORT_SYMBOL(modnet_module_exists);

/* when a module forks this is called */
void fork_modnet(struct task_struct * tsk){

	// the child processes are not allowed to call get_isock.
	// Since it only makes sense for them to act on what
	// is given to them. In kernel/fork.c, do_fork we set it to
	// null explictly for childs for cloned threads.
	if(tsk->total_static_modules!=0)
	{
		if(tsk->total_static_modules==-1)
		{
			atomic_long_inc(&(tsk->module_entry->ref_cnt));
		}

	}

}
EXPORT_SYMBOL(fork_modnet);

/* when a module exits, unmap all the sockets, free the paired sockets,
 * free the entry and all the kmalloc data.*/
void exit_modnet(struct task_struct * tsk){

	// the child processes are not allowed to call get_isock.
	// Since it only makes sense for them to act on what is
	// given to them. in kernel/fork.c, do_fork we set it
	// to null explictly for childs for cloned threads.
	if(tsk->total_static_modules!=0)
	{
		if(tsk->total_static_modules==-1)
			delete_modnet_module(tsk->pcore_infos_array[0],tsk);
	}

}
EXPORT_SYMBOL(exit_modnet);

SYSCALL_DEFINE1(modnet_register, char __user *, indentifier){

	int err;

	err = add_modnet_module(indentifier);

	return err;
}

int get_pcore_infos_array(char __user ** indentifier, int num_mods, struct per_core_module_info * pcore_info[]){
	int i;

	for( i = 0; i < num_mods; i++)
	{
		if(strnlen_user(indentifier[i],MAXIMUM_MODNAME)==0)
			return -EINVAL;
		pcore_info[i] = find_modnet_module(indentifier[i],1);

		//module doesn't exist (ESRCH: No such process)
		if(pcore_info[i]==NULL)
			return -ESRCH;
	}

	return 0;
} EXPORT_SYMBOL(get_pcore_infos_array);

SYSCALL_DEFINE2(modnet_apply, char __user **, indentifier, int, num_mods){

	int i;

	if(num_mods > MODNET_MAX_MODULES)
	{
		printk("modnet: applying more than %d modules is not legal\n",MODNET_MAX_MODULES);
		return -EINVAL;
	}

	for( i = 0; i < num_mods; i++)
	{

		// checking user access
		if(strnlen_user(indentifier[i],MAXIMUM_MODNAME)==0)
			return -EINVAL;

		current->pcore_infos_array[i] = find_modnet_module(indentifier[i],1);

		// module doesn't exist (ESRCH: No such process)
		if(current->pcore_infos_array[i]==NULL)
			return -ESRCH;
	}

	current->total_static_modules = num_mods;

#ifdef VSOCK_DEBUG
	// modules starting with g, will be treated specially when
	// running in debug mode
	if(indentifier[0]=='g')
		current->module[0] = (struct list_head *)1;
#endif

	return 0;
}

int is_curr_module(){

	if(current->total_static_modules == -1)
		return 1;

	return 0;

}EXPORT_SYMBOL(is_curr_module);

int is_curr_application(){

	if(current->total_static_modules > 0)
		return 1;

	return 0;

}EXPORT_SYMBOL(is_curr_application);

int is_curr_module_or_app(){

	if(current->total_static_modules != 0)
		return 1;

	return 0;

}EXPORT_SYMBOL(is_curr_module_or_app);

/////////////////////////////relocate it to some more appropriate file//////////////
/* sharvanath */
static int cstack_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct socket *sock = (struct socket *)(vma->vm_file->private_data);
	struct sock *sk = sock->sk;

	//fix this to allocate in terms of page and not small region, this exposes the other parts of page to application
	if(tcp_sk(sk)->stats==NULL)
	{
		printk(KERN_DEBUG "here In cstack_fault handler, the stats are NULL!\n");
		return VM_FAULT_SIGBUS;
	}

	vmf->page = sk->stat_page;

	if(sock->final_sock)
	{
		sock->final_sock->stat_page = vmf->page;
	}

	get_page(vmf->page);
	return 0;
}

static int cstack_fault1(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct socket *sock = (struct socket *)(vma->vm_file->private_data);

	if(sock->sk->stat_page==NULL)
	{
		printk(KERN_DEBUG "here In cstack_fault handler1 socket %lu, sock %lu, the stat_page is NULL!\n",
				(unsigned long)sock, (unsigned long)sock->sk);
		return VM_FAULT_SIGBUS;
	}
	vmf->page = sock->sk->stat_page;
	get_page(vmf->page);

	return 0;
}


static const struct vm_operations_struct cstack_vm_ops = {

		.fault      = cstack_fault

};

static const struct vm_operations_struct cstack_vm_ops1 = {
		.fault      = cstack_fault1
};

int cstack_mmap(struct file *file, struct socket *sock, struct vm_area_struct *vma)
{
	vma->vm_ops = &cstack_vm_ops;
	return 0;
}
EXPORT_SYMBOL(cstack_mmap);

int cstack_mmap1(struct file *file, struct socket *sock, struct vm_area_struct *vma)
{
	vma->vm_ops = &cstack_vm_ops1;
	return 0;
}
EXPORT_SYMBOL(cstack_mmap1);

static int __init modnet_init(void){

	int err = 0;
	INIT_LIST_HEAD(&modules_table.list);
	return err;

}
core_initcall(modnet_init);
/////////////////////////////////////////////////////////////////////////////////////
