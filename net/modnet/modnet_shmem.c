#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/modnet.h>

inline void init_stat_page (struct sock * sk){

	struct tcp_sock *tp = tcp_sk(sk);

	tp->stats = (struct tcp_sock_stats *)__get_free_page(GFP_USER);

	// Todo(sharva) handle memory errors
	sk->stat_page = virt_to_page(tp->stats);
	sk->stat_ptr = tp->stats;
	sk->is_mapped = 0;


	tp->stats->snd_cwnd = tp->snd_cwnd*tp->advmss;
	tp->stats->snd_una = tp->snd_una;
	tp->stats->write_seq = tp->write_seq;
	tp->stats->mss_size = tp->advmss;
	tp->stats->srtt = jiffies_to_usecs(tp->srtt)>>3;
	tp->stats->snd_wnd = tp->snd_wnd;
	tp->stats->last_rtt = 0;

	// not good for estimating very high speeds,
	// since the accuracy is usec
	tp->stats->last_start_timestamp = 0;
	tp->stats->last_size = 0;
	tp->stats->curr_rtt = 0;
	tp->stats->curr_start_timestamp = 0;
	tp->stats->curr_size = 0;
	tp->stats->estimated_bandwidth = 0;

} EXPORT_SYMBOL(init_stat_page);

inline void free_state_page (struct sock * sk){

	if(!sk->is_mapped && sk->stat_ptr)
	{
		free_page((unsigned long)sk->stat_ptr);
		sk->stat_page = NULL;
		tcp_sk(sk)->stats = NULL;
		sk->stat_ptr = NULL;
	}

} EXPORT_SYMBOL(free_state_page);

inline void update_stat_una(struct sock *sk){
	if(tcp_sk(sk)->stats){
		tcp_sk(sk)->stats->snd_una = tcp_sk(sk)->snd_una;
	}
}
EXPORT_SYMBOL(update_stat_una);

inline void update_state_page (struct sock * sk){
	if(tcp_sk(sk)->stats){
		tcp_sk(sk)->stats->snd_cwnd = tcp_sk(sk)->snd_cwnd*tcp_sk(sk)->advmss;
		tcp_sk(sk)->stats->snd_una = tcp_sk(sk)->snd_una;
		tcp_sk(sk)->stats->write_seq = tcp_sk(sk)->write_seq;
		// Todo(sharva) you might not have to update each time,
		// just after the connect
		tcp_sk(sk)->stats->mss_size = tcp_sk(sk)->advmss;
		tcp_sk(sk)->stats->srtt = jiffies_to_usecs(tcp_sk(sk)->srtt)>>3;
		tcp_sk(sk)->stats->snd_wnd = tcp_sk(sk)->snd_wnd;
	}

} EXPORT_SYMBOL(update_state_page);



inline void update_sequence_n_rtt (struct sock * sk){
	struct tcp_sock * tp = tcp_sk(sk);
	if(tp->stats){
		// not good for estimating very high speeds, since the accuracy is usec
		tp->stats->last_rtt = tp->stats->curr_rtt;
		tp->stats->last_start_timestamp = tp->stats->curr_start_timestamp;
		tp->stats->curr_rtt = jiffies_to_usecs(tcp_time_stamp - tp->rx_opt.rcv_tsecr);
		tp->stats->curr_start_timestamp = jiffies_to_usecs(tp->rx_opt.rcv_tsecr);
	}

} EXPORT_SYMBOL(update_sequence_n_rtt);

// Also add a kernel mechanism for bandwidth estimation, if the process wants to reuse.
// This can be called by userspace process in general.
// Todo(sharva) Clean the code, currently is a big monolithic piece of ungly code.
inline void update_bandwidth (struct sock * sk){
	struct tcp_sock * tp = tcp_sk(sk);
	if(tp->stats){
		const int max_bandwidth = 10; //10MBps
		u32 curr_bandwidth;

		// allow 10% variability in packet size
		int x,y,z;
		x = tp->stats->curr_size && tp->stats->last_size;
		y = ((long int)(tp->stats->curr_size - tp->stats->last_size)) < (long int)(tp->stats->curr_size/10)
				&& ((long int)(tp->stats->curr_size - tp->stats->last_size)) > -((long int)tp->stats->curr_size/10);
		z = tp->stats->curr_start_timestamp - tp->stats->last_start_timestamp < tp->stats->curr_size/max_bandwidth;

		// make sure these are not zero
		if(tp->stats->curr_size && tp->stats->last_size)
			// maximum 10% relative variation
			if( ((long int)(tp->stats->curr_size - tp->stats->last_size)) < (long int)(tp->stats->curr_size/10)
					&& ((long int)(tp->stats->curr_size - tp->stats->last_size)) > -((long int)tp->stats->curr_size/10) )
				if(tp->stats->curr_start_timestamp - tp->stats->last_start_timestamp < tp->stats->curr_size/max_bandwidth)
				{
					//in KBps
					//the two packets will be close together (if the window was open) : In this case use packet pair
					if((tp->stats->curr_rtt - tp->stats->last_rtt))
					{
						curr_bandwidth = (tp->stats->curr_size * 1000 *1000) / ((tp->stats->curr_rtt - tp->stats->last_rtt)*1024);


						tp->stats->estimated_bandwidth = curr_bandwidth; // << 3;
					}
				}

		if( !z && x  && tcp_packets_in_flight(tp) >= tp->snd_cwnd-2 && tp->stats->curr_rtt - tp->stats->last_rtt < tp->stats->curr_rtt/50 ){
			//is snd_cwnd almost full
			// the two packets will have the send times, estimate based on rate: i.e. the windows opened after one packet was drained:
			// In this case use the packet size by time difference for the rate
			// in the the diff between two receive times, we sent the amount of data in last ack (since that much window is opened)
			if( (tp->stats->curr_start_timestamp + tp->stats->curr_rtt - (tp->stats->last_start_timestamp + tp->stats->last_rtt) ) )
			{

				curr_bandwidth = (tp->stats->curr_size * 1000 * 1000) /
						((tp->stats->curr_start_timestamp + tp->stats->curr_rtt - (tp->stats->last_start_timestamp + tp->stats->last_rtt) )*1024) ;

				if(tp->stats->curr_size >= (tp->advmss*9)/10)
					tp->stats->estimated_bandwidth = curr_bandwidth;
			}
		}
	}

} EXPORT_SYMBOL(update_bandwidth);
