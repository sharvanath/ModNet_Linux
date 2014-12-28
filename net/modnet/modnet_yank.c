/* ModNet yank implementation
 * Author: Sharvanath Pathak */
#include <linux/tcp.h>
#include <net/tcp.h>

//sharva_modnet
static inline void tcp_reverse_send_head(struct sock *sk, const struct sk_buff *skb)
{

	struct tcp_sock *tp = tcp_sk(sk);

	//reset sk_send_head only if we are yanking the send_head skb
	if(sk->sk_send_head!=skb)
		return;

	if (skb_queue_is_first(&sk->sk_write_queue, skb))
		sk->sk_send_head = NULL;
	else
	{
		sk->sk_send_head = tcp_write_queue_prev(sk, skb);

		if(after(tp->snd_nxt,TCP_SKB_CB(sk->sk_send_head)->seq))
			sk->sk_send_head = NULL;
	}
}

//Todo(sp) check for memory leaks.
static int skb_kill_send_datagram(struct sock *sk, struct sk_buff *skb)
{
	int err = 0;
	struct tcp_sock *tp = tcp_sk(sk);

	sk->sk_wmem_queued -= skb->truesize;
	tp->write_seq = TCP_SKB_CB(skb)->seq;

	if(tp->pushed_seq >= TCP_SKB_CB(skb)->seq)
		tp->pushed_seq = TCP_SKB_CB(skb)->seq;

	sk_mem_uncharge(sk,skb->truesize);

	__skb_unlink(skb, &sk->sk_write_queue);

	return err;
}

// this function can return more data, it's upto user to push the res back.
// a better implementation would save the cost of another system call for pushing back,
// but since they are expected to be consuecutive this cost will also not be high.
// Note: this was the original idea, but now it can return lesser data and user has to
// take care of that.
int tcp_yank (struct sock *sk, struct msghdr *msg,
		size_t len, size_t length)
{

	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb, *tmp;
	int copied = 0, err = 0;
	struct sk_buff_head curr_list;
	int skb_ptr_len = 0;

	lock_sock(sk);

	__skb_queue_head_init(&curr_list);

	if(sk->sk_send_head==NULL)
	{
		release_sock(sk);
		return 0;
	}

	skb_queue_reverse_walk_safe(&sk->sk_write_queue, skb, tmp) {

		//copy less data, the last skb is not copied.
		if(copied+skb->len>=length)
			break;

		if(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
		{
			printk(KERN_DEBUG "Can't yank more coz encountered a FIN\n");
			break;
		}


		if(tp->snd_nxt>TCP_SKB_CB(skb)->seq)
		{
			printk(KERN_DEBUG "Can't yank more coz this last skb is already sent\n");
			break;
		}

		copied += skb->len;

		err = skb_kill_send_datagram(sk,skb);
		__skb_queue_tail(&curr_list, skb);

		skb_ptr_len++;

		// If this is the skb which has the snd_nxt in it, you can't yank further
		if(sk->sk_send_head==skb)
		{
			sk->sk_send_head = NULL;
			break;
		}

		// copy for than what is asked for
		if(copied>=len)
			break;

	}


	skb_queue_reverse_walk_safe(&curr_list, skb, tmp)
	{

		err = skb_copy_datagram_iovec( skb, 0, msg->msg_iov, skb->len);
		atomic_dec(&skb->users);
		kfree_skb(skb);

		if (err)
			break;
	}

	if(sk->stat_ptr){
		tp->stats->snd_una = tp->snd_una;
		tp->stats->write_seq = tp->write_seq;
		tp->stats->mss_size = tp->advmss;
	}

	release_sock(sk);

	return err? -1: copied;
}
EXPORT_SYMBOL(tcp_yank);