#include <net/tcp.h>

/* The bandwidth estimator estimates the rate at which the network
 * can currently deliver outbound data packets for this flow. At a high
 * level, it operates by taking a delivery rate sample for each ACK.
 *
 * A rate sample records the rate at which the network delivered packets
 * for this flow, calculated over the time interval between the transmission
 * of a data packet and the acknowledgment of that packet.
 *
 * Specifically, over the interval between each transmit and corresponding ACK,
 * the estimator generates a delivery rate sample. Typically it uses the rate
 * at which packets were acknowledged. However, the approach of using only the
 * acknowledgment rate faces a challenge under the prevalent ACK decimation or
 * compression: packets can temporarily appear to be delivered much quicker
 * than the bottleneck rate. Since it is physically impossible to do that in a
 * sustained fashion, when the estimator notices that the ACK rate is faster
 * than the transmit rate, it uses the latter:
 *
 *    send_rate = #pkts_delivered/(last_snd_time - first_snd_time)
 *    ack_rate  = #pkts_delivered/(last_ack_time - first_ack_time)
 *    bw = min(send_rate, ack_rate)
 *
 * Notice the estimator essentially estimates the goodput, not always the
 * network bottleneck link rate when the sending or receiving is limited by
 * other factors like applications or receiver window limits.  The estimator
 * deliberately avoids using the inter-packet spacing approach because that
 * approach requires a large number of samples and sophisticated filtering.
 *
 * TCP flows can often be application-limited in request/response workloads.
 * The estimator marks a bandwidth sample as application-limited if there
 * was some moment during the sampled window of packets when there was no data
 * ready to send in the write queue.
 */

/* Snapshot the current delivery information in the skb, to generate
 * a rate sample later when the skb is (s)acked in tcp_rate_skb_delivered().
 */
void tcp_rate_skb_sent(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	 /* In general we need to start delivery rate samples from the
	  * time we received the most recent ACK, to ensure we include
	  * the full time the network needs to deliver all in-flight
	  * packets. If there are no packets in flight yet, then we
	  * know that any ACKs after now indicate that the network was
	  * able to deliver those packets completely in the sampling
	  * interval between now and the next ACK.
	  *
	  * Note that we use packets_out instead of tcp_packets_in_flight(tp)
	  * because the latter is a guess based on RTO and loss-marking
	  * heuristics. We don't want spurious RTOs or loss markings to cause
	  * a spuriously small time interval, causing a spuriously high
	  * bandwidth estimate.
	  */

	/*
		tp->first_tx_mstamp 	发送窗口开始时间，当前最新被确认的数据包的发送时间
		tp->delivered_mstamp	tp->delivered的更新时间（仅限tp->delivered有变化时更新）
		tp->delivered			当前已确认的数据包总量

		发送窗口时间长度
			当前被确认的数据包的发送时间 - 当前被确认的数据包在被发送时记录的发送窗口开始时间

		确认窗口时间长度
			当前被确认的数据包的确认时间 - 当前被确认的数据包在被发送时记录的已确认的数据包总量的更新时间

		采样间隔取以上两个时间长度的最大值

		tp->first_tx_mstamp tp->delivered_mstamp 在当前没有包发出的情况下，等于被发送包的发送时间
		如果该包被确认，发送窗口时间长度将为0，因为tp->first_tx_mstamp和该包的first_tx_mstamp相等

		后续的包在没有数据包被确认的情况下，都将使用首个数据包的发送时间作为tp->first_tx_mstamp

		有数据包被确认后，将使用最新被确认的数据包的发送时间作为tp->first_tx_mstamp
	*/
	if (!tp->packets_out) {
		tp->first_tx_mstamp  = skb->skb_mstamp;
		tp->delivered_mstamp = skb->skb_mstamp;
	}

	TCP_SKB_CB(skb)->tx.first_tx_mstamp	= tp->first_tx_mstamp;
	TCP_SKB_CB(skb)->tx.delivered_mstamp	= tp->delivered_mstamp;
	TCP_SKB_CB(skb)->tx.delivered		= tp->delivered;
	TCP_SKB_CB(skb)->tx.is_app_limited	= tp->app_limited ? 1 : 0;
}

/* When an skb is sacked or acked, we fill in the rate sample with the (prior)
 * delivery information when the skb was last transmitted.
 *
 * If an ACK (s)acks multiple skbs (e.g., stretched-acks), this function is
 * called multiple times. We favor the information from the most recently
 * sent skb, i.e., the skb with the highest prior_delivered count.
 */

/*
	STRETCH ACK: Stretch ACKs are acknowledgements that cover more than 2
	segments of previously unacknowledged data (d>2) [RFC2581].  Stretch
	ACKs can occur by design (although this is not standard), due to
	implementation bugs [All97b, RFC2525], or due to ACK loss [RFC2760]

	比如收到了连续ACK了超过2个MSS数据的确认包，就判断为是ACK丢失，保守增窗
	http://blog.csdn.net/dog250/article/details/51348568

	多个报文被确认时，使用被发送时记录的已确认的数据包总量最高的那个报文的上下文作为窗口开始
*/
void tcp_rate_skb_delivered(struct sock *sk, struct sk_buff *skb,
			    struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *scb = TCP_SKB_CB(skb);

	if (!scb->tx.delivered_mstamp.v64)
		return;

	if (!rs->prior_delivered ||
	    after(scb->tx.delivered, rs->prior_delivered)) {
		rs->prior_delivered  = scb->tx.delivered;
		rs->prior_mstamp     = scb->tx.delivered_mstamp;
		rs->is_app_limited   = scb->tx.is_app_limited;
		rs->is_retrans	     = scb->sacked & TCPCB_RETRANS;

		/* Find the duration of the "send phase" of this window: */
		rs->interval_us      = skb_mstamp_us_delta(
						&skb->skb_mstamp,
						&scb->tx.first_tx_mstamp);

		/* Record send time of most recently ACKed packet: */
		tp->first_tx_mstamp  = skb->skb_mstamp;
	}
	/* Mark off the skb delivered once it's sacked to avoid being
	 * used again when it's cumulatively acked. For acked packets
	 * we don't need to reset since it'll be freed soon.
	 */
	if (scb->sacked & TCPCB_SACKED_ACKED)
		scb->tx.delivered_mstamp.v64 = 0;
}

/* Update the connection delivery information and generate a rate sample. */
void tcp_rate_gen(struct sock *sk, u32 delivered, u32 lost,
		  struct skb_mstamp *now, struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 snd_us, ack_us;

	/* Clear app limited if bubble is acked and gone. */
	if (tp->app_limited && after(tp->delivered, tp->app_limited))
		tp->app_limited = 0;

	/* TODO: there are multiple places throughout tcp_ack() to get
	 * current time. Refactor the code using a new "tcp_acktag_state"
	 * to carry current time, flags, stats like "tcp_sacktag_state".
	 */
	if (delivered)
		tp->delivered_mstamp = *now;

	rs->acked_sacked = delivered;	/* freshly ACKed or SACKed */
	rs->losses = lost;		/* freshly marked lost */
	/* Return an invalid sample if no timing information is available. */
	if (!rs->prior_mstamp.v64) {
		rs->delivered = -1;
		rs->interval_us = -1;
		return;
	}
	rs->delivered   = tp->delivered - rs->prior_delivered;

	/* Model sending data and receiving ACKs as separate pipeline phases
	 * for a window. Usually the ACK phase is longer, but with ACK
	 * compression the send phase can be longer. To be safe we use the
	 * longer phase.
	 */
	snd_us = rs->interval_us;				/* send phase */
	ack_us = skb_mstamp_us_delta(now, &rs->prior_mstamp);	/* ack phase */
	rs->interval_us = max(snd_us, ack_us);

	/* Normally we expect interval_us >= min-rtt.
	 * Note that rate may still be over-estimated when a spuriously
	 * retransmistted skb was first (s)acked because "interval_us"
	 * is under-estimated (up to an RTT). However continuously
	 * measuring the delivery rate during loss recovery is crucial
	 * for connections suffer heavy or prolonged losses.
	 */
	if (unlikely(rs->interval_us < tcp_min_rtt(tp))) {
		if (!rs->is_retrans)
			pr_debug("tcp rate: %ld %d %u %u %u\n",
				 rs->interval_us, rs->delivered,
				 inet_csk(sk)->icsk_ca_state,
				 tp->rx_opt.sack_ok, tcp_min_rtt(tp));
		rs->interval_us = -1;
		return;
	}

	/* Record the last non-app-limited or the highest app-limited bw */
	if (!rs->is_app_limited ||
	    ((u64)rs->delivered * tp->rate_interval_us >=
	     (u64)tp->rate_delivered * rs->interval_us)) {
		tp->rate_delivered = rs->delivered;
		tp->rate_interval_us = rs->interval_us;
		tp->rate_app_limited = rs->is_app_limited;
	}
}

/* If a gap is detected between sends, mark the socket application-limited. */
void tcp_rate_check_app_limited(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (/* We have less than one packet to send. */
	    tp->write_seq - tp->snd_nxt < tp->mss_cache &&
	    /* Nothing in sending host's qdisc queues or NIC tx queue. */
	    sk_wmem_alloc_get(sk) < SKB_TRUESIZE(1) &&
	    /* We are not limited by CWND. */
	    tcp_packets_in_flight(tp) < tp->snd_cwnd &&
	    /* All lost packets have been retransmitted. */
	    tp->lost_out <= tp->retrans_out)
		tp->app_limited =
			(tp->delivered + tcp_packets_in_flight(tp)) ? : 1;
}
