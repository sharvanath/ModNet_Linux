/* The core ModNet socket functionalities and system calls
 * Author: Sharvanath Pathak */
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/interrupt.h>
#include <linux/thread_info.h>
#include <linux/rcupdate.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mutex.h>
#include <linux/if_bridge.h>
#include <linux/if_frad.h>
#include <linux/if_vlan.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/kmod.h>
#include <linux/audit.h>
#include <linux/wireless.h>
#include <linux/nsproxy.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/xattr.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>

#include <net/compat.h>
#include <net/wext.h>
#include <net/cls_cgroup.h>

#include <net/sock.h>
#include <linux/netfilter.h>

#include <linux/if_tun.h>
#include <linux/ipv6_route.h>
#include <linux/route.h>
#include <linux/sockios.h>
#include <linux/atalk.h>
#include <net/busy_poll.h>


#include <linux/tcp.h>
#include <linux/modnet.h>
#define YANK_LEN 10000000

struct socket *sock_alloc(void);
struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed);
int create_socks(struct socket * sock1, struct socket * sock2);


int create_isock_pair(struct socket ** sock1_ret, struct socket ** sock2_ret,
		struct file ** file1_ret, struct file ** file2_ret, struct file * final_sock_file) {
	struct socket *sock1, *sock2;
	struct file *newfile1, *newfile2;
	int flags, type, err=0;
	struct socket * sock_curr_sock;
	struct last_sock_status * last_sock;

	sock_curr_sock = (struct socket *) final_sock_file->private_data;
	type = sock_curr_sock->type;

	flags = type & ~SOCK_TYPE_MASK;
	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;
	type &= SOCK_TYPE_MASK;

	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	sock1 = sock_alloc();
	if(!(sock1))
		goto out;
	sock1->type = type;


	sock2 = sock_alloc();
	if(!(sock2))
		goto out_release_1;
	sock2->type = type;

	// Todo(sharva) error handling
	create_socks(sock1,sock2);
	err = sock1->ops->socketpair(sock1, sock2);
	if (err < 0)
		goto out_release_both;

	newfile1 = sock_alloc_file(sock1,flags,NULL);
	if (unlikely(IS_ERR(newfile1)))
	{
		printk("Error in file allocation, errno=%ld",PTR_ERR(newfile1));
		goto out_release_both;
	}

	newfile2 = sock_alloc_file(sock2, flags, NULL);
	if (unlikely(IS_ERR(newfile2)))
	{
		printk("Error in file allocation, errno=%ld",PTR_ERR(newfile2));
		goto out_release_both;
	}

	if(!sock_curr_sock->final_sock)
	{
		last_sock = kmalloc(sizeof(struct last_sock_status) + sizeof(spinlock_t), GFP_KERNEL);
		spin_lock_init ((spinlock_t *)((void *)last_sock+sizeof(struct last_sock_status)));
		last_sock->last_sock = sock_curr_sock;
		last_sock->closed = 0;
		sock_curr_sock->final_sock = last_sock;
	}
	else
		last_sock = sock_curr_sock->final_sock;

	sock1->final_sock = last_sock;
	sock2->final_sock = last_sock;
	atomic_long_inc_not_zero(&final_sock_file->f_count);
	atomic_long_inc_not_zero(&final_sock_file->f_count);

	if (sock_curr_sock->type == SOCK_STREAM)
	{
		sock1->ops = &intermediate_stream_ops;
		sock2->ops = &intermediate_stream_ops;
	}
	else
	{
		sock1->ops = &intermediate_dgram_ops;
		sock2->ops = &intermediate_dgram_ops;
	}

	if(final_sock_file->f_flags & O_NONBLOCK)
	{
		newfile1->f_flags |= O_NONBLOCK;
		newfile2->f_flags |= O_NONBLOCK;
	}

	*sock1_ret = sock1;
	*sock2_ret = sock2;
	*file1_ret = newfile1;
	*file2_ret = newfile2;
	return err;

	out_release_both: sock_release(sock2);
	out_release_1: sock_release(sock1);
	out:
	return err;
}

int yield_sockets(struct file *lsocket, struct file *rsocket, struct per_core_module_info * pcore_info[],
		int len, struct file * final_sock_file){

	int i = 0, err = 0, mods = 0;
	struct socket *sock1, *sock2;
	struct file *newfile1, *newfile2, *last_left;
	struct isock_elem * curr;

	if(!pcore_info)
		printk("modnet: Error in yield_sockets function\n");

	last_left = lsocket;

	// looping over the modules, and creating paired sockets for links between modules.
	// mod1<-->mod2<-->mod3, i.e. 3 modules, 2 links
	for(i = 0; i < len; i++)
	{
		if(!modnet_module_exists(pcore_info[i]) || !atomic_read(pcore_info[i][smp_processor_id()].interception_on))
			continue;
		else
			mods++;

		if(i<len-1)
		{
			err = create_isock_pair(&sock1, &sock2, &newfile1, &newfile2, final_sock_file);
			if(err<0)
			{
				printk("modnet: Error after create_isock_pair function\n");
				return 0;
			}
		}
		else
		{
			newfile1 = rsocket;
		}

		curr = (struct isock_elem *) kmalloc(sizeof(struct isock_elem), GFP_KERNEL);
		curr->infile = last_left;
		curr->outfile = newfile1;
		last_left = newfile2;
		spin_lock(pcore_info[i][smp_processor_id()].mod_lock);
		list_add(&(curr->list), pcore_info[i][smp_processor_id()].sock_list);
		spin_unlock(pcore_info[i][smp_processor_id()].mod_lock);
		wake_up_interruptible_sync_poll(pcore_info[i][smp_processor_id()].virt_event_wq, POLLVNET);
	}

	if(mods==0){
		printk("modnet: Error in yield_sockets, all the requested modules have exited\n");
		return 0;
	}

	return 1;
}

int enqueue_sock(int fd, struct file* fp) {

	struct socket *sock1, *sock2;
	struct file *newfile1, *newfile2;
	struct file * socket_file;
	int err = 0;

	if(current->total_static_modules <= 0)
		return 0;

	if(!modnet_module_exists(current->pcore_infos_array[0]) ||
			!atomic_read(current->pcore_infos_array[0][smp_processor_id()].interception_on))
	{
		return 0;
	}

	if (fp == NULL) {
		socket_file = fget(fd);
		put_filp(socket_file);
	} else
		socket_file = fp;

	err = create_isock_pair(&sock1, &sock2, &newfile1, &newfile2, socket_file);

	if(err<0)
		return 0;

	sock2->prev_module = current;
	fd_install_custom(fd, newfile1);
	return yield_sockets(newfile2, socket_file, current->pcore_infos_array, current->total_static_modules, socket_file);

}
EXPORT_SYMBOL(enqueue_sock);

SYSCALL_DEFINE3(modnet_yield, int __user *, fds, char __user **, indentifier, int, num_mods) {

	struct file *lfile, *rfile;
	struct file *newfile1, *newfile2;
	int left_fd,right_fd;
	int lfput_needed, rfput_needed;
	int err=0;
	struct per_core_module_info * pcore_info[MODNET_MAX_MODULES];
	struct final_socket;
	struct socket *sock,*sock1,*sock2;

	if(get_user(left_fd,fds))
		return -EFAULT;

	if(get_user(right_fd,fds+1))
		return -EFAULT;

	if(num_mods > MODNET_MAX_MODULES || num_mods < 0)
		return -EINVAL;

	if(left_fd < 0) {	// apply a module to the right

		rfile = fget_light(right_fd, &rfput_needed);
		if(!rfile){
			return -EINVAL;
		}

		sock = sock_from_file(rfile, &err);
		if(!sock)
		{
			err = -EINVAL;
			goto OUT1;
		}

		if(current->total_static_modules!=0)
		{
			err = -EOPNOTSUPP;
		}

		err = get_pcore_infos_array(indentifier, num_mods, pcore_info);

		if(err<0)
			goto OUT1;

		err = create_isock_pair(&sock1, &sock2, &newfile1, &newfile2, rfile);

		if(err<0)
			goto OUT1;

		fd_install_custom(right_fd, newfile1);
		sock2->prev_module = current;
		err = yield_sockets(newfile2, rfile, pcore_info, num_mods, rfile);

		OUT1:
		fput_light(rfile,rfput_needed);
		return err;
	}

	if(left_fd<0 || right_fd<0) {
		return -EOPNOTSUPP;
	}

	lfile = fget_light(left_fd, &lfput_needed);
	if(!lfile){
		return -EINVAL;
	}

	rfile = fget_light(right_fd, &rfput_needed);
	if(!rfile){
		fput_light(lfile,lfput_needed);
		return -EINVAL;
	}

	sock1 = sock_from_file(lfile, &err);
	if(!sock1 || !sock1->final_sock->last_sock)
	{
		err = -EINVAL;
		goto OUT;
	}

	sock2 = sock_from_file(rfile, &err);
	if(!sock2 || !sock2->final_sock->last_sock)
	{
		err = -EINVAL;
		goto OUT;
	}

	err = get_pcore_infos_array(indentifier, num_mods, pcore_info);

	if(err<0)
		return err;

	fd_install_custom(left_fd, NULL);
	fd_install_custom(right_fd, NULL);
	put_unused_fd(left_fd);
	put_unused_fd(right_fd);

	err = yield_sockets(lfile, rfile, pcore_info, num_mods, sock2->final_sock->last_sock->file);

	OUT:
	fput_light(lfile,lfput_needed);
	fput_light(rfile,rfput_needed);
	return err;

}


/* This syscall is used to temporarily disable interception */
SYSCALL_DEFINE1(modnet_interception, int, off){
	// the socket is not intercepted, but if this module had something
	// ahead the socket will still get intercepted by that.
	atomic_set(current->pcore_infos_array[0][smp_processor_id()].interception_on,off);
	return off;

}


//Todo(sharva): test this call
SYSCALL_DEFINE1(modnet_module_end, int, off){

	printk("modnet: Untested system call modnet_module_end.");
	current->total_static_modules = 0;
	return off;
}


SYSCALL_DEFINE3(modnet_yankputdata, int, fd, void __user *, data, int, length){

	int err,fput_needed;
	struct socket * sock;
	struct sock * sk;


	sock = sockfd_lookup_light(fd, &err, &fput_needed);

	if(!sock)
		goto out;

	sk = sock->sk;
	if(length>YANK_LEN || length<=0)
	{
		err = -1;
		goto out_put;
	}

	if(length != sk->yank_usage)
	{
		err = -2;
		goto out_put;
	}

	if(sk->yank_data == NULL)
		sk->yank_data = kmalloc(length,GFP_KERNEL);

	sk->yank_datalen = length;

	err = copy_from_user(sk->yank_data,data,length);

	out_put:
	fput_light(sock->file, fput_needed);
	out:
	return err;

}

SYSCALL_DEFINE3(modnet_yankdata, int, fd, void __user *, buff, int, length){

	int err,fput_needed;
	struct socket * sock = sockfd_lookup_light(fd, &err, &fput_needed);
	struct sock * sk = sock->sk;

	if(!sock)
		goto out;

	if(sock->ops->family==AF_INET||sock->ops->family==AF_INET6){
		struct iovec iov;
		struct msghdr msg;

		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_iovlen = 1;
		msg.msg_iov = &iov;
		iov.iov_len = length;
		iov.iov_base = buff;
		msg.msg_name = NULL;
		msg.msg_namelen = -1;

		// Todo(sharva) Fix this bug.
		// shouldn't use this method for UDP socks
		err = tcp_yank (sock->sk, &msg, length,length);
	}
	else
	{
		struct sock * sk_peer = get_unix_peer(sk);

		if(sk_peer == NULL)
		{
			err = -1;
			goto out_put;

		}
		if(sk_peer->yank_datalen<=0){
			err = -2;
			goto out_put;
		}
		if(sk_peer->yank_datalen>length){
			err = -3;
			goto out_put;
		}
		err = copy_to_user(buff,sk_peer->yank_data,sk_peer->yank_datalen);

	}

	out_put:
	fput_light(sock->file, fput_needed);
	out:
	return err;

}

SYSCALL_DEFINE3(modnet_yank, int, fd, int, option, int, length){

	int err,fput_needed;
	struct socket * sock = sockfd_lookup_light(fd, &err, &fput_needed);
	struct sock * sk_peer;

	if(!sock)
		return err;

	lock_sock(sock->sk);
	switch (option){
	case 0:
		err = sock->ops->ioctl(sock, SIOVNETUSAGECHECK, length);
		break;

	case 1:
		err = sock->ops->ioctl(sock, SIOVNETUSAGECONFIRM, length+1);
		break;

	case 2:
		//check yank available
		err = sock->ops->ioctl(sock, SIOVNETCHECKAVAILABLE, length);
		break;

	case 3:
		//do yank
		err = sock->ops->ioctl(sock, SIOVNETYANKPERFORM, length);
		break;

	case 4:
		//clear
		err = sock->ops->ioctl(sock, SIOVNETYANKCLEAR, length);
		break;

		//perform yank
	case 5:
		sk_peer = get_unix_peer(sock->sk);

		if(sk_peer == NULL)
		{
			err = -1;
			break;

		}
		err = sk_peer->yank_check;

	case 6:
		sk_peer = get_unix_peer(sock->sk);

		if(sk_peer == NULL)
		{
			err = -1;
			break;

		}
		err = sock->sk->yank_active;


	default:
		break;
	}

	release_sock(sock->sk);

	fput_light(sock->file, fput_needed);
	return err;
}

SYSCALL_DEFINE2(modnet_map_last_sock, int, fd_in, int, fd_out) {


	int err, fput_needed;
	int fput_needed1;
	struct socket * sock1;
	void * old_ptr;

	struct socket * sock = sockfd_lookup_light(fd_in, &err, &fput_needed);

	if(sock) {
		lock_sock(sock->sk);

		err = -1;
		if(fd_out==-1){
			printk(KERN_DEBUG "modnet_map_last_sock the outfile is was -1\n");
			fput_light(sock->file, fput_needed);
			return tcp_sk(sock->sk)->stats->snd_cwnd;
		}

		sock1 = sockfd_lookup_light(fd_out, &err, &fput_needed1);
		if(sock1) {

			lock_sock(sock1->sk);
			if(sock->sk->stat_page == NULL)
				printk(KERN_DEBUG "modnet_map_last_sock: stat_page is null in here\n");

			old_ptr = sock1->sk->stat_ptr;
			sock->sk->is_mapped = 1;
			sock1->sk->stat_page = sock->sk->stat_page;
			sock1->sk->stat_ptr = tcp_sk(sock->sk)->stats;
			err = sock1->ops->ioctl(sock1,SIOVNETPAIR,0);
			release_sock(sock1->sk);
			fput_light(sock1->file, fput_needed1);

		}

		release_sock(sock->sk);
		fput_light(sock->file, fput_needed);

	}

	return err;
}

// we can reduce the overhead of syscall by returning this with the events itself, see if that's helpful
/* do error_handling, similar to the original socket.c code */
/* sharva_mod1, the syscall for the module to get a isock */
SYSCALL_DEFINE4(modnet_getsockets, int, module, int __user *, fd_in, int __user *, fd_out, int __user*, max_elems_ptr) {

	int fd1=0,fd2=0,err=0,i=0;
	struct list_head * isock_list_head;
	struct list_head temp_list;
	struct isock_elem * curr_sock;
	int flags;
	int type = SOCK_STREAM;
	int max_elems = 0;

	INIT_LIST_HEAD(&temp_list);

	if(current->total_static_modules!=-1)
	{
		printk(KERN_DEBUG "modnet: Called get_isock from a non-module");
		err = 0;
		goto out;
	}

	isock_list_head = current->pcore_infos_array[0][smp_processor_id()].sock_list;
	spin_lock(current->pcore_infos_array[0][smp_processor_id()].mod_lock);

	if(list_empty(isock_list_head))
	{
		spin_unlock(current->pcore_infos_array[0][smp_processor_id()].mod_lock);
		err = 0;
		goto out;
	}

	// see if the flags is fine. what about the fd1 being negative?
	if(get_user(max_elems,max_elems_ptr))
		return -EFAULT;

	if(module==-1)
	{
		err = 0;
		goto out;
	}

	i=0;
	while(!list_empty(isock_list_head) && i<max_elems)
	{
		curr_sock = list_first_entry(isock_list_head, struct isock_elem, list);
		list_del(&(curr_sock->list));
		list_add(&(curr_sock->list), &temp_list);
		i++;
	}

	spin_unlock(current->pcore_infos_array[0][smp_processor_id()].mod_lock);


	///Todo(sharva) CHECK OF THE SOCKET IS ALREADY CLOSED
	flags = type & ~SOCK_TYPE_MASK;
	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
	{
		printk(KERN_DEBUG "Error in get_isock, flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK)");
	}

	type &= SOCK_TYPE_MASK;

	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	i = 0;
	while(!list_empty(&temp_list) && i < max_elems){
		curr_sock = list_first_entry(&temp_list, struct isock_elem, list);
		fd1 = get_unused_fd_flags(flags);

		if (unlikely(fd1 < 0)) {
			err = fd1;
			goto out_add;
		}

		fd2 = get_unused_fd_flags(flags);

		if (unlikely(fd2 < 0)) {
			put_unused_fd(fd1);
			err = fd2;
			goto out_add;
		}

		fd_install(fd1, curr_sock->infile);
		fd_install(fd2, curr_sock->outfile);

		put_user(fd1,fd_in+i);
		put_user(fd2,fd_out+i);

		list_del(&(curr_sock->list));
		kfree(curr_sock);
		i++;
	}

	if(i==max_elems)
		printk("Here we got max_elem entries and so some of them were lost based on this %d\n",
				list_empty(&temp_list));

	return i;

	out_add:
	printk(KERN_DEBUG "modnet: File limit overshoot in get_isock\n");
	err = 0;

	out:
	return err;

}

SYSCALL_DEFINE4(modnet_isock_yank, int, fd, void __user *, buff, size_t, len, size_t, length)
{

	struct socket *sock;
	struct iovec iov;
	struct msghdr msg;
	int err,fput_needed;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);

	if(!sock)
		goto out;

	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_len = length;
	iov.iov_base = buff;
	msg.msg_name = NULL;
	msg.msg_namelen = -1;

	err = tcp_yank (sock->sk, &msg, len, length);
	fput_light(sock->file, fput_needed);

	out:
	return err;
}


SYSCALL_DEFINE6(modnet_isock_send, int, fd, void __user *, buff, size_t, len,
		unsigned int, flags, struct sockaddr __user *, src_addr, int, src_addr_len)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int err;
	struct msghdr_isock msg;
	struct iovec iov;
	int fput_needed;

	if (len > INT_MAX)
		len = INT_MAX;
	sock = sockfd_lookup_light(fd, &err, &fput_needed);

	if (!sock)
		goto out;

	iov.iov_base = buff;
	iov.iov_len = len;
	msg.msg_name = NULL;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_namelen = -1;

	if (src_addr) {

		err = move_addr_to_kernel(src_addr, src_addr_len, &address);

		if (err < 0)
			goto out_put;

		msg.isock_addr = (struct sockaddr *)&address;
		msg.isock_addrlen = src_addr_len;

	}

	if (sock->file->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	msg.msg_flags = flags;

	// Todo(sp)
	// Fix this. Adding fields to msghdr is not a good idea.
	err = sock_sendmsg(sock, (struct msghdr *)&msg, len);

	out_put:
	fput_light(sock->file, fput_needed);
	out:
	return err;
}
