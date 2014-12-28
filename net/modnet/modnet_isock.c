/*Intermediate socket code.
 * Unfortunately since it's tighly coupled with unix static
 * functions it can't be moved out*/

int intermediate_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg){
	struct sock *sk = sock->sk;
	int err;

	struct unix_sock *u;
	struct sock *other;
	switch (cmd) {
	case SIOVNETPAIR:
		u = unix_sk(sk);
		err = -ENOTCONN;
		other = unix_peer(sk);
		if (!other)
			break;
#ifdef VSOCK_DEBUG_PRINT_ALL
		printk(KERN_DEBUG "SIOVNETPAIR stat_page = %u, other = %u, socket = %u, sock = %u \n",sk->stat_page,other,sock,sock->sk);
#endif
		other->stat_page = sk->stat_page;
		other->stat_ptr = sk->stat_ptr;
		break;

	case SIOVNETUSAGECHECK:
		u = unix_sk(sk);
		err = -ENOTCONN;
		other = unix_peer(sk);
		if (!other)
		{
			printk(KERN_DEBUG "The peer was null\n");
			break;
		}

		if(!sk->yank_active){

			other->yank_check = 1;
			other->yank_usage = -1;
			sk->yank_active = 1;
			sk->yank_usage = -1;
			return 0;
		}
		else
		{
			return -1;
		}
		break;

	case SIOVNETUSAGECONFIRM:
		u = unix_sk(sk);
		err = -ENOTCONN;
		other = unix_peer(sk);

		if (!other)
			break;

		if(sk->yank_check!=1)
			return -1;
		// check bit not set
		if(other->yank_active){
			if(arg>0){
				other->yank_usage = arg-1;
				return arg;
			}
			return 0;
		}

		// check_yank is set, while yank_active is not,
		// this is error
		return -2;

	case SIOVNETCHECKAVAILABLE:
		if(!sk->yank_active)
			return -2;

		if(sk->yank_usage>=0)
			return sk->yank_usage;
		else
			return -1;

	case SIOVNETYANKPERFORM:
		u = unix_sk(sk);
		err = -ENOTCONN;
		other = unix_peer(sk);
		if (!other)
			break;

#ifdef VSOCK_DEBUG_PRINT_ALL
		printk(KERN_DEBUG "SIOVNETYANKPERFORM sock %u, other %u\n",sk,other);
#endif
		// if this is active that means,
		// we need to set the info of yank for next
		if(sk->yank_active){
			if(arg>=0){
				other->yank_usage = arg;
				return arg;
			}
			return -1;

		}
		// if the other is active that means,
		// we need to get this info
		else if(other->yank_active){
			return sk->yank_usage;
		}
		//the peer stopped the yank process.
		else
			return -2;

	case SIOVNETYANKCLEAR:
		sock->sk->yank_check = 0;
		sock->sk->yank_active = 0;
		sock->sk->yank_usage = 0;
		sock->sk->yank_datalen = 0;
		if(sk->yank_data)
			kfree(sk->yank_data);

		sk->yank_data = NULL;

		u = unix_sk(sk);
		err = -ENOTCONN;
		other = unix_peer(sk);
		if (!other)
			break;

		other->yank_check = 0;
		other->yank_active = 0;
		other->yank_usage = 0;
		other->yank_datalen = 0;
		if(other->yank_data)
			kfree(other->yank_data);

		other->yank_data = NULL;
		break;

	default:
		err = -ENOIOCTLCMD;
		break;
	}
	return err;
}

inline int isock_forge_check(struct msghdr *msg){
	if(msg->msg_namelen==-1){
		msg->msg_namelen = 0;
		return 1;
	}
	return 0;
}

inline int isock_do_forge(struct msghdr *msg, struct sk_buff *skb)
{
	struct msghdr_isock * msg1 = (struct msghdr_isock *) msg;
	if(msg1->isock_addrlen>0){
		void * ptr = kmalloc(msg1->isock_addrlen,GFP_KERNEL);
		memcpy(ptr,msg1->isock_addr,msg1->isock_addrlen);
		skb->isock_addr = ptr;
		skb->isock_addrlen = msg1->isock_addrlen;
#ifdef VSOCK_DEBUG_PRINT_ALL
		printk(KERN_DEBUG "here getting and setting the address\n");
#endif
		return 1;
	}
	return 0;
}

inline int copy_forge_addr(struct socket *sock, struct msghdr *msg, struct sk_buff *skb)
{
	if(sock->final_sock&&skb->isock_addrlen!=0){
#ifdef VSOCK_DEBUG_PRINT_ALL
		printk(KERN_DEBUG "getting and setting the address1\n");
#endif
		msg->msg_namelen  = skb->isock_addrlen;
		memcpy(msg->msg_name,skb->isock_addr,skb->isock_addrlen);
		kfree(skb->isock_addr);
		return 1;
		//copy_addr(msg, skb->unix_addr);
	}

	return 0;
}

/* proto_ops for intermediate socket */
int intermediate_socket_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len){

#ifdef VSOCK_DEBUG_PRINT_ALL
	printk(KERN_DEBUG "Intermediate bind");
#endif

	struct socket * sock_final = sock->final_sock->last_sock;
	//how can this be closed at bind, only from a crash.
	if(sock->final_sock->closed)
		return -EBADF;

	return sock_final->ops->bind(sock_final,uaddr,addr_len);

}

int intermediate_socket_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags){

#ifdef VSOCK_DEBUG_PRINT_ALL
	printk(KERN_DEBUG "Intermediate connect");
#endif

	struct socket * sock_final = sock->final_sock->last_sock;
	// can't return this, unless the file has been closed by some s
	// standard mechanism, need the fidelity gaurantee
	if(sock->final_sock->closed)
		return -EBADF;

	return sock_final->ops->connect(sock_final,uaddr,addr_len,flags);
}

int intermediate_socketpair(struct socket *sock1, struct socket *sock2){
#ifdef VSOCK_DEBUG_PRINT_ALL
	printk(KERN_DEBUG "Intermediate sockpair");
#endif

	struct socket * sock_final = sock1->final_sock->last_sock;

	if(sock1->final_sock->closed)
		return -EBADF;

	return sock_final->ops->socketpair(sock_final,sock2);
}

/* to be implemented............. */
ssize_t intermediate_sendpage(struct socket *sock, struct page *page, int offset, size_t size, int flags)
{

	printk(KERN_DEBUG "modnet: intermediate sendpage not supported\n");
	return -1;

}

//intermediate_accept, do this!!!
/* to be implemented............. */
int intermediate_accept(struct socket *sock, struct socket *newsock, int flags){

#ifdef VSOCK_DEBUG_PRINT_ALL
	printk(KERN_DEBUG "in intermediate accept");
#endif

	struct socket * sock_final = sock->final_sock->last_sock;

	if(sock->final_sock->closed)
		return -EBADF;
	return sock_final->ops->accept(sock_final,newsock,flags);
}


int  intermediate_getname(struct socket *sock, struct sockaddr *uaddr, int *uaddr_len, int peer)
{
#ifdef VSOCK_DEBUG_PRINT_ALL
	printk(KERN_DEBUG "in intermediate getname");
#endif

	struct socket * sock_final = sock->final_sock->last_sock;

	if(sock->final_sock->closed)
		return -EBADF;

	return sock_final->ops->getname(sock_final,uaddr,uaddr_len,peer);
}

int intermediate_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen) {
#ifdef VSOCK_DEBUG_PRINT_ALL
	printk(KERN_DEBUG "in intermediate setsockopt");
#endif

	struct socket * sock_final = sock->final_sock->last_sock;

	if(sock->final_sock->closed)
		return -EBADF;

	return sock_final->ops->setsockopt(sock_final,level,optname,optval,optlen);
}

int intermediate_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen) {
#ifdef VSOCK_DEBUG_PRINT_ALL
	printk(KERN_DEBUG "in intermediate getsockopt");
#endif

	struct socket * sock_final = sock->final_sock->last_sock;

	if(sock->final_sock->closed)
		return -EBADF;

	return sock_final->ops->getsockopt(sock_final,level,optname,optval,optlen);
}


int intermediate_shutdown(struct socket *sock, int mode)
{
	struct sock *sk = sock->sk;
	struct sock *other;

	mode = (mode+1)&(RCV_SHUTDOWN|SEND_SHUTDOWN);

	if (!mode)
		return 0;

	unix_state_lock(sk);
	sk->sk_shutdown |= mode;
	other = unix_peer(sk);
	if (other)
		sock_hold(other);
	unix_state_unlock(sk);
	sk->sk_state_change(sk);

	if (other &&
			(sk->sk_type == SOCK_STREAM || sk->sk_type == SOCK_SEQPACKET)) {

		int peer_mode = 0;

		if (mode&RCV_SHUTDOWN)
			peer_mode |= SEND_SHUTDOWN;
		if (mode&SEND_SHUTDOWN)
			peer_mode |= RCV_SHUTDOWN;

		// dont let the peer affect my state.
		unix_state_lock(other);
		other->sk_shutdown |= peer_mode;
		unix_state_unlock(other);
		other->sk_state_change(other);
		if (peer_mode == SHUTDOWN_MASK)
			sk_wake_async(other, SOCK_WAKE_WAITD, POLL_HUP);
		else if (peer_mode & RCV_SHUTDOWN)
			sk_wake_async(other, SOCK_WAKE_WAITD, POLL_IN);
	}
	if (other)
		sock_put(other);

	return 0;
}


static unsigned int intermediate_poll(struct file *file, struct socket *sock, poll_table *wait){

	// sharva_modnet
	if(sock->final_sock){
		struct sock *sk =sock->final_sock->last_sock->sk;
		struct socket *final_sock =sock->final_sock->last_sock;
		if (sk->sk_state == TCP_LISTEN)
		{
			return final_sock->ops->poll(final_sock->file,final_sock,wait);
		}
	}

	return unix_poll(file,sock,wait);
}


/* Intermediate socket SPLICE Implementation */
struct intermediate_splice_state {
	struct pipe_inode_info *pipe;
	size_t len;
	unsigned int flags;
};

int __intermediate_splice_read(struct sock *sk, struct intermediate_splice_state *iss)
{
	struct sk_buff *skb;
	struct unix_sock *u = unix_sk(sk);
	int copied = 0;
	int err = 0;
	int chunk = 0;
	int size = 0;
	int used = 0;

	if (sk->sk_state != TCP_ESTABLISHED)
		return -ENOTCONN;

	size = iss->len;
	err = mutex_lock_interruptible(&u->readlock);

	while ( (skb = skb_peek(&sk->sk_receive_queue)) != NULL && size>0) {

		chunk = min_t(unsigned int, unix_skb_len(skb), size);

		used = skb_splice_bits(skb, UNIXCB(skb).consumed, iss->pipe, chunk,
				iss->flags);

		if (used <= 0) {
			if (!copied)
				copied = used;
			break;
		}
		else if(used <= chunk){
			copied += used;
			size -= used;
		}
		else {
			printk("__intermediate_splice_read: this case has not been handled\n");
		}

		UNIXCB(skb).consumed += used;

		if (unix_skb_len(skb))
			break;

		sk_eat_skb(sk, skb, false);
	}

	mutex_unlock(&u->readlock);

	return copied;
}

/**
 *  intermediate_splice_read - splice data from intermediate socket to a pipe
 * @sock:	socket to splice from
 * @ppos:	position (not valid)
 * @pipe:	pipe to splice to
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    Will read pages from given socket and fill them into a pipe.
 *
 **/
static ssize_t intermediate_splice_read(struct socket *sock, loff_t *ppos,
		struct pipe_inode_info *pipe, size_t len,
		unsigned int flags)
{
	struct sock *sk = sock->sk;

	struct intermediate_splice_state iss = {
			.pipe = pipe,
			.len = len,
			.flags = flags,
	};

	long timeo;
	ssize_t spliced;
	int ret;

	/*
	 * We can't seek on a socket input
	 */
	if (unlikely(*ppos))
		return -ESPIPE;

	ret = spliced = 0;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, sock->file->f_flags & O_NONBLOCK);
	while (iss.len) {
		ret = __intermediate_splice_read(sk, &iss);
		if (ret < 0)
			break;
		else if (!ret) {	//if no data was read
			if (spliced)
				break;		//if some data was read return
			if (sk->sk_err) {
				ret = sock_error(sk);
				break;
			}
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;	//if rcv has been shutdown return 0
			if (sk->sk_state == TCP_CLOSE) {
				/*
				 * This occurs when user tries to read
				 * from never connected socket.
				 */
				if (!sock_flag(sk, SOCK_DONE))
					ret = -ENOTCONN;
				break;
			}
			if (!timeo) {
				ret = -EAGAIN;
				break;
			}
			sk_wait_data(sk, &timeo);
			if (signal_pending(current)) {
				ret = sock_intr_errno(timeo);
				break;
			}
			continue;
		}

		iss.len -= ret;
		spliced += ret;

		if (!timeo)
			break;

		release_sock(sk);
		lock_sock(sk);

		if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
				(sk->sk_shutdown & RCV_SHUTDOWN) ||
				signal_pending(current))
			break;
	}

	release_sock(sk);

	if (spliced)
		return spliced;

	return ret;
}


const struct proto_ops intermediate_stream_ops = {
		.family =	PF_UNIX,
		.owner =	THIS_MODULE,
		.release =	unix_release,
		.bind =		intermediate_socket_bind,
		.connect =	intermediate_socket_connect,
		.socketpair =	intermediate_socketpair,
		.accept =	intermediate_accept,
		.getname =	intermediate_getname,
		.poll =		intermediate_poll,
		.ioctl =	unix_ioctl,
		.shutdown =	intermediate_shutdown,
		.setsockopt =	intermediate_setsockopt,
		.getsockopt =	intermediate_getsockopt,
		.sendmsg =	unix_stream_sendmsg,
		.recvmsg =	unix_stream_recvmsg,
		.splice_read = intermediate_splice_read,
		.mmap = cstack_mmap1,
		.sendpage =	intermediate_sendpage,
		.set_peek_off =	unix_set_peek_off,
};
EXPORT_SYMBOL(intermediate_stream_ops);

const struct proto_ops intermediate_dgram_ops = {
		.family =	PF_UNIX,
		.owner =	THIS_MODULE,
		.release =	unix_release,
		.bind =		intermediate_socket_bind,
		.connect =	intermediate_socket_connect,
		.socketpair =	intermediate_socketpair,
		.accept =	intermediate_accept,
		.getname =	intermediate_getname,
		.poll =		unix_poll,
		.ioctl =	unix_ioctl,
		.listen =	unix_listen,
		.shutdown =	unix_shutdown,
		.setsockopt =	intermediate_setsockopt,
		.getsockopt =	intermediate_getsockopt,
		.sendmsg =	unix_dgram_sendmsg,
		.recvmsg =	unix_dgram_recvmsg,
		.mmap = cstack_mmap1,
		.sendpage =	intermediate_sendpage,
		.set_peek_off =	unix_set_peek_off,
};
EXPORT_SYMBOL(intermediate_dgram_ops);


/* External functions */
struct sock * get_unix_peer(struct sock * sk){
	struct sock *other=NULL;

	if(sk->sk_socket==NULL)
	{
		printk(KERN_DEBUG "get_unix_peer: The socket was null here.\n");
		return NULL;
	}
	if(sk->sk_socket->ops->family != PF_UNIX)
	{
		printk(KERN_DEBUG "get_unix_peer: The current family is not unix, and the call was for modnet_yank status of pair.\n");
		return NULL;
	}

	other = unix_peer(sk);

	if (!other)
		return NULL;

	return other;
}
EXPORT_SYMBOL(get_unix_peer);

static int unix_create(struct net *net, struct socket *sock, int protocol,
		int kern);

int create_socks(struct socket * sock1, struct socket * sock2){


	unix_create(current->nsproxy->net_ns,sock1,0,0);
	unix_create(current->nsproxy->net_ns,sock2,0,0);
	return 0;

}
EXPORT_SYMBOL(create_socks);
