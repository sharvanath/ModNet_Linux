/* Global Modnet Definitions
 * Author: Sharvanath Pathak */

#include <linux/types.h>
#include <linux/threads.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/net.h>
#include <linux/modnet_utils.h>


#ifndef _LINUX_VNET_H
#define _LINUX_VNET_H
//Todo(sharva) add these as configs
// #define VSOCK_DEBUG
// #define VSOCK_DEBUG_PRINT_ALL

#ifdef NUM_MOD_QUEUES
printk(KERN_DEBUG "modnet: fatal error NUM_MOD_QUEUES is already taken by some other kernel component\n");
#endif

#define NUM_MOD_QUEUES NR_CPUS
#define MODNET_MAX_MODULES 20

struct socket;

struct per_core_module_info {
	struct list_head * sock_list; //for module: the list of stolen socket, for appl: pointer to modules list of stolen socket.
	spinlock_t * mod_lock; //for module: the lock for list of stolen socket, for appl: pointer to lock for modules list of stolen socket.
	wait_queue_head_t * virt_event_wq; //for module: the pointer to blocled process (i.e. module) this is a list to be compatible with the existing epoll code. for applications: pointer, that is used to wake up module.
	atomic_t * interception_on; //not a readily used feature.
};

struct modules_table_entry {
	struct list_head list;
	char * identifier;
	atomic_long_t ref_cnt;
	struct task_struct * module_task;
	struct per_core_module_info pcore_infos[NUM_MOD_QUEUES];
	//may be add the level/order in the chain
};

struct tcp_sock_stats {
	u32 snd_cwnd;
	u32 snd_una; // last unacked
	u32 write_seq;  //last byte queued
	u32 mss_size;
	u32 srtt;
	u32 snd_wnd;

	unsigned int last_rtt;	//not good for estimating very high speeds, since the accuracy is usec
	unsigned int last_start_timestamp;
	unsigned int curr_rtt;
	unsigned int curr_start_timestamp;
	u32 last_size;
	u32 curr_size;
	u32 estimated_bandwidth; //kernel does this for you
};

struct isock_elem {
	struct list_head list;
	struct file * infile;
	struct file * outfile;
};

struct last_sock_status {

	struct socket * last_sock;
	struct page * stat_page;
	short closed;
	int ref_cnt;
	//check if there are alignment problems with short
};

/* sharva_mod3 */
extern int	cstack_mmap(struct file *file,
		struct socket *sock,
		struct vm_area_struct *vma);

extern int	cstack_mmap1(struct file *file,
		struct socket *sock,
		struct vm_area_struct *vma);

//sharva_modn_final
void raise_event_for_usage(int fd);
struct sock * get_unix_peer(struct sock * sk);
/* sharva_modn */
int tcp_yank (struct sock *sk, struct msghdr *msg, size_t len, size_t length);

void fork_modnet(struct task_struct * tsk);
void exit_modnet(struct task_struct * tsk);

// check when to remove the modules
int is_curr_module(void);
int is_curr_application(void);
int is_curr_module_or_app(void);

int modnet_module_exists(struct per_core_module_info * pcore_module_infos);
int get_pcore_infos_array(char __user ** indentifier, int num_mods, struct per_core_module_info * pcore_info[]);
#endif
