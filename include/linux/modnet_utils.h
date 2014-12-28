/* Global Modnet Definitions
 * Author: Sharvanath Pathak */

#include <linux/fs.h>
#ifndef _LINUX_VNET_UTILS_H
#define _LINUX_VNET_UTILS_H

// These macros are used for the yank.
// SIO options used for a cleaner implementation
#define SIOVNETPAIR 0x8AE0 /* to 89EF */
#define SIOVNETUSAGECHECK 0x8AA0 /* to 89EF */
#define SIOVNETUSAGECONFIRM 0x8AB0 /* to 89EF */
#define SIOVNETCHECKAVAILABLE 0x8AC0 /* to 89EF */
#define SIOVNETYANKPERFORM 0x8AD0 /* to 89EF */
#define SIOVNETYANKCLEAR 0x8AF0 /* to 89EF */

// This structure is used for masquerading, we put that data is sk_buff
struct msghdr_isock {
	void	*	msg_name;	/* Socket name			*/
	int		msg_namelen;	/* Length of name		*/
	struct iovec *	msg_iov;	/* Data blocks			*/
	__kernel_size_t	msg_iovlen;	/* Number of blocks		*/
	void 	*	msg_control;	/* Per protocol magic (eg BSD file descriptor passing) */
	__kernel_size_t	msg_controllen;	/* Length of cmsg list */
	unsigned int	msg_flags;

	void * isock_addr;
	int isock_addrlen;
};

void fd_install_custom(unsigned int fd, struct file *file);
int fd_swap_custom(int original_fd, struct file *file, struct file *file_new, struct task_struct * task_ptr);
int enqueue_sock(int fd, struct file* fp);
extern const struct proto_ops intermediate_stream_ops, intermediate_dgram_ops;
//extern void put_unused_fd_custom(unsigned int fd, struct task_struct * this_task);

/* modnet events */
#define POLLUSAGE	0x0800
#define POLLYANK	0x0800
#define POLLVNET	0x0800

/* modnet tcp shared memory */
inline void init_stat_page (struct sock * sk);
inline void free_state_page (struct sock * sk);
inline void update_state_page (struct sock * sk);
inline void update_sequence_n_rtt (struct sock * sk);
inline void update_bandwidth (struct sock * sk);

#endif
