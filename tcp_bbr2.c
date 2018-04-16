/* Bottleneck Bandwidth and RTT (BBR) congestion control
 *
 * BBR congestion control computes the sending rate based on the delivery
 * rate (throughput) estimated from ACKs. In a nutshell:
 *
 *   On each ACK, update our model of the network path:
 *      bottleneck_bandwidth = windowed_max(delivered / elapsed, 10 round trips)
 *      min_rtt = windowed_min(rtt, 10 seconds)
 *   pacing_rate = pacing_gain * bottleneck_bandwidth
 *   cwnd = max(cwnd_gain * bottleneck_bandwidth * min_rtt, 4)
 *
 * The core algorithm does not react directly to packet losses or delays,
 * although BBR may adjust the size of next send per ACK when loss is
 * observed, or adjust the sending rate if it estimates there is a
 * traffic policer, in order to keep the drop rate reasonable.
 *
 * BBR is described in detail in:
 *   "BBR: Congestion-Based Congestion Control",
 *   Neal Cardwell, Yuchung Cheng, C. Stephen Gunn, Soheil Hassas Yeganeh,
 *   Van Jacobson. ACM Queue, Vol. 14 No. 5, September-October 2016.
 *
 * There is a public e-mail list for discussing BBR development and testing:
 *   https://groups.google.com/forum/#!forum/bbr-dev
 *
 * NOTE: BBR *must* be used with the fq qdisc ("man tc-fq") with pacing enabled,
 * since pacing is integral to the BBR design and implementation.
 * BBR without pacing would not function properly, and may incur unnecessary
 * high packet loss rates.
 */
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include <linux/inet.h>
#include <linux/random.h>
#include <linux/win_minmax.h>

/* Scale factor for rate in pkt/uSec unit to avoid truncation in bandwidth
 * estimation. The rate unit ~= (1500 bytes / 1 usec / 2^24) ~= 715 bps.
 * This handles bandwidths from 0.06pps (715bps) to 256Mpps (3Tbps) in a u32.
 * Since the minimum window is >=4 packets, the lower bound isn't
 * an issue. The upper bound isn't an issue with existing technologies.
 */
#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

#define BBR_SCALE 8	/* scaling factor for fractions in BBR (e.g. gains) */
#define BBR_UNIT (1 << BBR_SCALE)

/* BBR has the following modes for deciding how fast to send: */
enum bbr_mode {
	BBR_STARTUP,	/* ramp up sending rate rapidly to fill pipe */
	BBR_DRAIN,	/* drain any queue created during startup */
	BBR_PROBE_BW,	/* discover, share bw: pace around estimated bw */
	BBR_PROBE_RTT,	/* cut cwnd to min to probe min_rtt */
};

/*
	“数据包守恒”的原则（conservation of packets principle）
	即带宽不变的情况下，在网络同一时刻能容纳数据包数量是恒定的。
	当“老”数据包离开了网络后，就能向网络中发送一个“新”的数据包。
	既然已经收到了3个冗余ACK，说明有三个数据数据包已经到达了接收端，既然三个数据包已经离开了网络，
	那么就是说可以在发送3个数据包了。于是只要发送方收到一个冗余的ACK，于是cwnd加1个MSS。
*/

/*
	round含义？
*/

/* BBR congestion control block */
struct bbr {
	u32	min_rtt_us;	        /* min RTT in min_rtt_win_sec window */
	u32	min_rtt_stamp;	        /* timestamp of min_rtt_us */
	u32	probe_rtt_done_stamp;   /* end time for BBR_PROBE_RTT mode */
	struct minmax bw;	/* Max recent delivery rate in pkts/uS << 24 */
	u32	rtt_cnt;	    /* count of packet-timed rounds elapsed */
	u32     next_rtt_delivered; /* scb->tx.delivered at end of round */
	struct skb_mstamp cycle_mstamp;  /* time of this cycle phase start */
	u32     mode:3,		     /* current bbr_mode in state machine */
		prev_ca_state:3,     /* CA state on previous ACK */
		packet_conservation:1,  /* use packet conservation? */
		restore_cwnd:1,	     /* decided to revert cwnd to old value */
		round_start:1,	     /* start of packet-timed tx->ack round? */
		tso_segs_goal:7,     /* segments we want in each skb we send */
		idle_restart:1,	     /* restarting after idle? */
		probe_rtt_round_done:1,  /* a BBR_PROBE_RTT round at 4 pkts? */
		unused:5,
		lt_is_sampling:1,    /* taking long-term ("LT") samples now? */
		lt_rtt_cnt:7,	     /* round trips in long-term interval */
		lt_use_bw:1;	     /* use lt_bw as our bw estimate? */
	u32	lt_bw;		     /* LT est delivery rate in pkts/uS << 24 */
	u32	lt_last_delivered;   /* LT intvl start: tp->delivered */
	u32	lt_last_stamp;	     /* LT intvl start: tp->delivered_mstamp */
	u32	lt_last_lost;	     /* LT intvl start: tp->lost */
	u32	pacing_gain:10,	/* current gain for setting pacing rate */
		cwnd_gain:10,	/* current gain for setting cwnd */
		full_bw_cnt:3,	/* number of rounds without large bw gains */
		cycle_idx:3,	/* current index in pacing_gain cycle array */
		unused_b:6;
	u32	prior_cwnd;	/* prior cwnd upon entering loss recovery */
	u32	full_bw;	/* recent bw, to estimate if pipe is full */
};

#define CYCLE_LEN	8	/* number of phases in a pacing gain cycle */

/* Window length of bw filter (in rounds): */
static const int bbr_bw_rtts = CYCLE_LEN + 2;
/* Window length of min_rtt filter (in sec): */
static const u32 bbr_min_rtt_win_sec = 10;
/* Minimum time (in ms) spent at bbr_cwnd_min_target in BBR_PROBE_RTT mode: */
static const u32 bbr_probe_rtt_mode_ms = 200;
/* Skip TSO below the following bandwidth (bits/sec): */
static const int bbr_min_tso_rate = 1200000;

/* We use a high_gain value of 2/ln(2) because it's the smallest pacing gain
 * that will allow a smoothly increasing pacing rate that will double each RTT
 * and send the same number of packets per RTT that an un-paced, slow-starting
 * Reno or CUBIC flow would:
 */
/*
	为什么high_gain为2/ln(2)可以让每个rtt的发送速率翻倍？

	2/ln(2)从哪里来？
*/
static const int bbr_high_gain  = BBR_UNIT * 2885 / 1000 + 1;
/* The pacing gain of 1/high_gain in BBR_DRAIN is calculated to typically drain
 * the queue created in BBR_STARTUP in a single round:
 */
static const int bbr_drain_gain = BBR_UNIT * 1000 / 2885;
/* The gain for deriving steady-state cwnd tolerates delayed/stretched ACKs: */
static const int bbr_cwnd_gain  = BBR_UNIT * 2;
/* The pacing_gain values for the PROBE_BW gain cycle, to discover/share bw: */
static const int bbr_pacing_gain[] = {
	BBR_UNIT * 5 / 4,	/* probe for more available bw */
	BBR_UNIT * 3 / 4,	/* drain queue and/or yield bw to other flows */
	BBR_UNIT, BBR_UNIT, BBR_UNIT,	/* cruise at 1.0*bw to utilize pipe, */
	BBR_UNIT, BBR_UNIT, BBR_UNIT	/* without creating excess queue... */
};
/* Randomize the starting gain cycling phase over N phases: */
static const u32 bbr_cycle_rand = 7;

/* Try to keep at least this many packets in flight, if things go smoothly. For
 * smooth functioning, a sliding window protocol ACKing every other packet
 * needs at least 4 packets in flight:
 */
static const u32 bbr_cwnd_min_target = 4;

/* To estimate if BBR_STARTUP mode (i.e. high_gain) has filled pipe... */
/* If bw has increased significantly (1.25x), there may be more bw available: */
static const u32 bbr_full_bw_thresh = BBR_UNIT * 5 / 4;
/* But after 3 rounds w/o significant bw growth, estimate pipe is full: */
static const u32 bbr_full_bw_cnt = 3;

/* "long-term" ("LT") bandwidth estimator parameters... */
/* The minimum number of rounds in an LT bw sampling interval: */
static const u32 bbr_lt_intvl_min_rtts = 4;
/* If lost/delivered ratio > 20%, interval is "lossy" and we may be policed: */
static const u32 bbr_lt_loss_thresh = 50;
/* If 2 intervals have a bw ratio <= 1/8, their bw is "consistent": */
static const u32 bbr_lt_bw_ratio = BBR_UNIT / 8;
/* If 2 intervals have a bw diff <= 4 Kbit/sec their bw is "consistent": */
static const u32 bbr_lt_bw_diff = 4000 / 8;
/* If we estimate we're policed, use lt_bw for this many round trips: */
static const u32 bbr_lt_bw_max_rtts = 48;

/* Do we estimate that STARTUP filled the pipe? */
/* 启动阶段是否填满链路 */
static bool bbr_full_bw_reached(const struct sock *sk)
{
	const struct bbr *bbr = inet_csk_ca(sk);

	return bbr->full_bw_cnt >= bbr_full_bw_cnt;
}

/* Return the windowed max recent bandwidth sample, in pkts/uS << BW_SCALE. */
static u32 bbr_max_bw(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return minmax_get(&bbr->bw);
}

/* Return the estimated bandwidth of the path, in pkts/uS << BW_SCALE. */
/* 返回链路的估算带宽，注意单位 */
static u32 bbr_bw(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	/* 如果使用long-term带宽，则返回long-term带宽；反之则返回当前最大的采样带宽 */
	return bbr->lt_use_bw ? bbr->lt_bw : bbr_max_bw(sk);
}

/* Return rate in bytes per second, optionally with a gain.
 * The order here is chosen carefully to avoid overflow of u64. This should
 * work for input rates of up to 2.9Tbit/sec and gain of 2.89x.
 */
/* 以每秒字节数为单位返回速率 */
static u64 bbr_rate_bytes_per_sec(struct sock *sk, u64 rate, int gain)
{
	/*
		MTU: Maxitum Transmission Unit 最大传输单元
		MSS: Maxitum Segment Size 最大数据包大小，TCP数据包每次能够传输的最大数据数据包
	*/
	rate *= tcp_mss_to_mtu(sk, tcp_sk(sk)->mss_cache);
	rate *= gain;
	rate >>= BBR_SCALE;
	rate *= USEC_PER_SEC;
	return rate >> BW_SCALE;
}

/* Pace using current bw estimate and a gain factor. In order to help drive the
 * network toward lower queues while maintaining high utilization and low
 * latency, the average pacing rate aims to be slightly (~1%) lower than the
 * estimated bandwidth. This is an important aspect of the design. In this
 * implementation this slightly lower pacing rate is achieved implicitly by not
 * including link-layer headers in the packet size used for the pacing rate.
 */
/*
	Pace使用当前估算带宽和一个增益参数。
	为了能让网络在保持高利用率和低延迟的情况下减少出现排队，平均速率的目标值要稍低于估算带宽。
	用来计算速率的数据包大小没有包含链路层头部，一定程度上拉低了平均速率，隐式实现了该速率。

	更新sock结构体中sk_pacing_rate

	The FQ scheduler

	That transmission time is used to implement the TCP pacing support. 
	If a given socket has a pace specified for it, 
	FQ will calculate how far the packets should be spaced in time to conform to that pace. 
	If a flow's next transmission time is in the future, 
	that flow is added to another red-black tree with the transmission time used as the key; 
	that tree, thus, allows the kernel to track delayed flows and quickly find the one whose next packet is due to go out the soonest. 
	A single timer is then used, if needed, to ensure that said packet is transmitted at the right time.

	sch_fq.c
    Transport (eg TCP) can set in sk->sk_pacing_rate a rate, enqueue a
	bunch of packets, and this packet scheduler adds delay between packets to respect rate limitation.
*/
static void bbr_set_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u64 rate = bw;

	rate = bbr_rate_bytes_per_sec(sk, rate, gain);

	/* 不能超过最大发送速率 */
	rate = min_t(u64, rate, sk->sk_max_pacing_rate);

	/* 非启动阶段 或者 速率大于sock结构体中sk_pacing_rate 更新 */
	if (bbr->mode != BBR_STARTUP || rate > sk->sk_pacing_rate)
		sk->sk_pacing_rate = rate;
}

/* Return count of segments we want in the skbs we send, or 0 for default. */
static u32 bbr_tso_segs_goal(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return bbr->tso_segs_goal;
}

static void bbr_set_tso_segs_goal(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 min_segs;

	min_segs = sk->sk_pacing_rate < (bbr_min_tso_rate >> 3) ? 1 : 2;
	bbr->tso_segs_goal = min(tcp_tso_autosize(sk, tp->mss_cache, min_segs),
				 0x7FU);
}

/* Save "last known good" cwnd so we can restore it after losses or PROBE_RTT */
/*
	prior_cwnd 进入丢包恢复前的拥塞窗口

	保存当前的拥塞窗口值（当前发送拥塞窗口 或者 之前的拥塞窗口值）

	Recovery
	After a sufficient amount of successive duplicate ACKs arrive at the sender, it retransmits the first
	unacknowledged segment and enters the Recovery state. By default, the threshold for entering
	Recovery is three successive duplicate ACKs, a value recommended by the TCP congestion
	control specification. During the Recovery state, the congestion window size is reduced by one
	segment for every second incoming acknowledgement, similar to the CWR state. The window
	reduction ends when the congestion window size is equal to ssthresh, i.e. half of the window
	size when entering the Recovery state. The congestion window is not increased during the
	recovery state, and the sender either retransmits the segments marked lost, or makes forward
	transmissions on new data according to the packet conservation principle. The sender stays in
	the Recovery state until all of the segments outstanding when the Recovery state was entered
	are successfully acknowledged. After this the sender goes back to the Open state. A retrans-
	mission timeout can also interrupt the Recovery state.

	TCP_CA_Open: normal state
	TCP_CA_Recovery: Loss Recovery after a Fast Transmission
	TCP_CA_Loss: Loss Recovery after a  Timeout
	TCP_CA_Disorder: duplicate packets detected, but haven't reach the threshold. So TCP  shall assume that  packet reordering is happening.
	TCP_CA_CWR: the state that congestion window is decreasing (after local congesiton in NIC, or ECN and etc).
*/
static void bbr_save_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	if (bbr->prev_ca_state < TCP_CA_Recovery && bbr->mode != BBR_PROBE_RTT)
		bbr->prior_cwnd = tp->snd_cwnd;  /* this cwnd is good enough */
	else  /* loss recovery or BBR_PROBE_RTT have temporarily cut cwnd */
		bbr->prior_cwnd = max(bbr->prior_cwnd, tp->snd_cwnd);
}

static void bbr_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	/*
		CA_EVENT_TX_START
		first transmit when no packets in flight
		当发送一个数据包时，如果网络中无发送且未确认的数据包，则触发此事件

		bbr->idle_restart
		restarting after idle?
			1）After idle event (CA_EVENT_TX_START)
			2）app限定
	*/
	if (event == CA_EVENT_TX_START && tp->app_limited) {
		bbr->idle_restart = 1;
		/* Avoid pointless buffer overflows: pace at est. bw if we don't
		 * need more speed (we're restarting from idle and app-limited).
		 */
		/*
			避免缓冲区溢出：如果不需要更快，则以估算带宽作为发送速率
		*/

		/* 如果当前状态为探测带宽，则更新发送速率 */
		if (bbr->mode == BBR_PROBE_BW)
			bbr_set_pacing_rate(sk, bbr_bw(sk), BBR_UNIT);
	}
}

/* Find target cwnd. Right-size the cwnd based on min RTT and the
 * estimated bottleneck bandwidth:
 *
 * cwnd = bw * min_rtt * gain = BDP * gain
 *
 * The key factor, gain, controls the amount of queue. While a small gain
 * builds a smaller queue, it becomes more vulnerable to noise in RTT
 * measurements (e.g., delayed ACKs or other ACK compression effects). This
 * noise may cause BBR to under-estimate the rate.
 *
 * To achieve full performance in high-speed paths, we budget enough cwnd to
 * fit full-sized skbs in-flight on both end hosts to fully utilize the path:
 *   - one skb in sending host Qdisc,
 *   - one skb in sending host TSO/GSO engine
 *   - one skb being received by receiver host LRO/GRO/delayed-ACK engine
 * Don't worry, at low rates (bbr_min_tso_rate) this won't bloat cwnd because
 * in such cases tso_segs_goal is 1. The minimum cwnd is 4 packets,
 * which allows 2 outstanding 2-packet sequences, to try to keep pipe
 * full even with ACK-every-other-packet delayed ACKs.
 */
/*
	计算拥塞窗口

	增益控制着排队数量。但是对于RTT测量，较小的增益意味着对噪声更敏感。噪声容易让BBR低估速率。
*/
static u32 bbr_target_cwnd(struct sock *sk, u32 bw, int gain)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 cwnd;
	u64 w;

	/* If we've never had a valid RTT sample, cap cwnd at the initial
	 * default. This should only happen when the connection is not using TCP
	 * timestamps and has retransmitted all of the SYN/SYNACK/data packets
	 * ACKed so far. In this case, an RTO can cut cwnd to 1, in which
	 * case we need to slow-start up toward something safe: TCP_INIT_CWND.
	 */
	if (unlikely(bbr->min_rtt_us == ~0U))	 /* no valid RTT samples yet? */
		return TCP_INIT_CWND;  /* be safe: cap at default initial cwnd*/

	w = (u64)bw * bbr->min_rtt_us;

	/* Apply a gain to the given value, then remove the BW_SCALE shift. */
	cwnd = (((w * gain) >> BBR_SCALE) + BW_UNIT - 1) / BW_UNIT;

	/* Allow enough full-sized skbs in flight to utilize end systems. */
	cwnd += 3 * bbr->tso_segs_goal;

	/* Reduce delayed ACKs by rounding up cwnd to the next even number. */
	cwnd = (cwnd + 1) & ~1U;

	return cwnd;
}

/* An optimization in BBR to reduce losses: On the first round of recovery, we
 * follow the packet conservation principle: send P packets per P packets acked.
 * After that, we slow-start and send at most 2*P packets per P packets acked.
 * After recovery finishes, or upon undo, we restore the cwnd we had when
 * recovery started (capped by the target cwnd based on estimated BDP).
 *
 * TODO(ycheng/ncardwell): implement a rate-based approach.
 */
/* 
	计算进入Recovery状态，以及退出Recovery或Loss状态时的拥塞窗口大小
	默认初始为当前发送拥塞窗口

	进入Recovery状态时，根据数据包守恒原则，为在途数据包数目加上已确认的数据包数目
	退出退出Recovery或Loss状态时，恢复为之前的窗口大小（当前发送拥塞窗口与之前的窗口大小的较大值）
 */
static bool bbr_set_cwnd_to_recover_or_restore(
	struct sock *sk, const struct rate_sample *rs, u32 acked, u32 *new_cwnd)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u8 prev_state = bbr->prev_ca_state, state = inet_csk(sk)->icsk_ca_state;
	u32 cwnd = tp->snd_cwnd;

	/* An ACK for P pkts should release at most 2*P packets. We do this
	 * in two steps. First, here we deduct the number of lost packets.
	 * Then, in bbr_set_cwnd() we slow start up toward the target cwnd.
	 */

	/* 有丢包，拥塞窗口更新为发送窗口减去丢包数之后的值与1之间的较大值 */
	if (rs->losses > 0)
		cwnd = max_t(s32, cwnd - rs->losses, 1);

	/* 当前状态为Recovery，之前状态不是Recovery */
	if (state == TCP_CA_Recovery && prev_state != TCP_CA_Recovery) {
		/* Starting 1st round of Recovery, so do packet conservation. */
		bbr->packet_conservation = 1;
		bbr->next_rtt_delivered = tp->delivered;  /* start round now */
		/* Cut unused cwnd from app behavior, TSQ, or TSO deferral: */
		cwnd = tcp_packets_in_flight(tp) + acked;

	/* 之前状态为Recovery或者Loss，当前已退出之前状态 */
	} else if (prev_state >= TCP_CA_Recovery && state < TCP_CA_Recovery) {
		/* Exiting loss recovery; restore cwnd saved before recovery. */
		bbr->restore_cwnd = 1;
		bbr->packet_conservation = 0;
	}
	bbr->prev_ca_state = state;

	if (bbr->restore_cwnd) {
		/* Restore cwnd after exiting loss recovery or PROBE_RTT. */
		cwnd = max(cwnd, bbr->prior_cwnd);
		bbr->restore_cwnd = 0;
	}

	if (bbr->packet_conservation) {
		*new_cwnd = max(cwnd, tcp_packets_in_flight(tp) + acked);
		return true;	/* yes, using packet conservation */
	}
	*new_cwnd = cwnd;
	return false;
}

/* Slow-start up toward target cwnd (if bw estimate is growing, or packet loss
 * has drawn us down below target), or snap down to target if we're above it.
 */
/*
	设置发送端拥塞窗口

	新确认的数据包数量为0，则不更新发送端拥塞窗口

*/
static void bbr_set_cwnd(struct sock *sk, const struct rate_sample *rs,
			 u32 acked, u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 cwnd = 0, target_cwnd = 0;

	if (!acked)
		return;

	/*
		计算进入Recovery状态和离开Recovery状态时的拥塞窗口值

		与丢包还是有一定关系的，拥塞窗口首先被减去丢包数

		如果刚进入Recovery状态，需遵循数据包守恒原则，在途+acked，并返回true
		如果离开Recovery状态，则恢复为max(cwnd - rs->losses, bbr->prior_cwnd)，并返回false
	*/
	if (bbr_set_cwnd_to_recover_or_restore(sk, rs, acked, &cwnd))
		goto done;

	/*
		拥塞窗口调整机制：
		1）达到链路最大带宽时，新的拥塞窗口为当前拥塞窗口加上已确认的数据包数目和实时计算出的拥塞窗口之间的较小值
		2）当前拥塞窗口小于目标值，或者发送了较少的数据包时，需增加窗口，没有必要限制拥塞窗口在目标值以下
	*/
	/* If we're below target cwnd, slow start cwnd toward target cwnd. */
	target_cwnd = bbr_target_cwnd(sk, bw, gain);
	if (bbr_full_bw_reached(sk))  /* only cut cwnd if we filled the pipe */
		cwnd = min(cwnd + acked, target_cwnd);
	/* 
		tp->delivered: Total data packets delivered incl. rexmits(Retransmitted TCP Segments)
	*/
	else if (cwnd < target_cwnd || tp->delivered < TCP_INIT_CWND)
		cwnd = cwnd + acked;
	cwnd = max(cwnd, bbr_cwnd_min_target);

done:
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);	/* apply global cap */
	if (bbr->mode == BBR_PROBE_RTT)  /* drain queue, refresh min_rtt */
		tp->snd_cwnd = min(tp->snd_cwnd, bbr_cwnd_min_target);
}

/* End cycle phase if it's time and/or we hit the phase's in-flight target. */
/*
	本阶段是否结束

	时间长度满足要求，并且（或者）在途数据包数量达到目标值
*/
static bool bbr_is_next_cycle_phase(struct sock *sk,
				    const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	bool is_full_length =
		skb_mstamp_us_delta(&tp->delivered_mstamp, &bbr->cycle_mstamp) >
		bbr->min_rtt_us;
	u32 inflight, bw;

	/* 增益为1，稳定阶段 间隔时间超过min_rtt_us */

	/* The pacing_gain of 1.0 paces at the estimated bw to try to fully
	 * use the pipe without increasing the queue.
	 */
	if (bbr->pacing_gain == BBR_UNIT)
		return is_full_length;		/* just use wall clock time */

	inflight = rs->prior_in_flight;  /* what was in-flight before ACK? */
	bw = bbr_max_bw(sk);

	/*
		增益大于1，探测带宽阶段
		间隔时间超过min_rtt_us的条件下，如果有丢包或者inflight已经达到目标拥塞窗口
	*/
	/* A pacing_gain > 1.0 probes for bw by trying to raise inflight to at
	 * least pacing_gain*BDP; this may take more than min_rtt if min_rtt is
	 * small (e.g. on a LAN). We do not persist if packets are lost, since
	 * a path with small buffers may not hold that much.
	 */
	if (bbr->pacing_gain > BBR_UNIT)
		return is_full_length &&
			(rs->losses ||  /* perhaps pacing_gain*BDP won't fit */
			 inflight >= bbr_target_cwnd(sk, bw, bbr->pacing_gain));

	/* A pacing_gain < 1.0 tries to drain extra queue we added if bw
	 * probing didn't find more bw. If inflight falls to match BDP then we
	 * estimate queue is drained; persisting would underutilize the pipe.
	 */
	/*
		增益小于1，探测RTT，排空队列
		间隔时间超过min_rtt_us或者inflight小于目标拥塞窗口（如果小于对应的BDP，可判断为队列已排空）
	*/
	return is_full_length ||
		inflight <= bbr_target_cwnd(sk, bw, BBR_UNIT);
}

/* 进入到下个周期 */
static void bbr_advance_cycle_phase(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->cycle_idx = (bbr->cycle_idx + 1) & (CYCLE_LEN - 1);
	bbr->cycle_mstamp = tp->delivered_mstamp;
	bbr->pacing_gain = bbr_pacing_gain[bbr->cycle_idx];
}

/* Gain cycling: cycle pacing gain to converge to fair share of available bw. */
static void  bbr_update_cycle_phase(struct sock *sk,
				   const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);

	/*
		当前为probe_bw状态，没有使用long-term带宽作为计算基准，并且本阶段结束，则进入下个阶段
	*/
	if ((bbr->mode == BBR_PROBE_BW) && !bbr->lt_use_bw &&
	    bbr_is_next_cycle_phase(sk, rs))
		bbr_advance_cycle_phase(sk);
}

static void bbr_reset_startup_mode(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->mode = BBR_STARTUP;
	bbr->pacing_gain = bbr_high_gain;
	bbr->cwnd_gain	 = bbr_high_gain;
}

static void bbr_reset_probe_bw_mode(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->mode = BBR_PROBE_BW;
	bbr->pacing_gain = BBR_UNIT;
	bbr->cwnd_gain = bbr_cwnd_gain;
	bbr->cycle_idx = CYCLE_LEN - 1 - prandom_u32_max(bbr_cycle_rand);
	bbr_advance_cycle_phase(sk);	/* flip to next phase of gain cycle */
}

static void bbr_reset_mode(struct sock *sk)
{
	/*
		未达最大带宽，则重置为startup状态，反之则重置为probe_bw状态，并随机挑选一个阶段

		startup状态的速率增益和拥塞窗口增益均设置为较高增益
		probe_bw状态的拥塞窗口增益为2，速率增益则由其所处阶段所定
	 */
	if (!bbr_full_bw_reached(sk))
		bbr_reset_startup_mode(sk);
	else
		bbr_reset_probe_bw_mode(sk);
}

/* Start a new long-term sampling interval. */
/*
	开启一个新的long-term带宽采样周期，重新开始计时
*/
static void bbr_reset_lt_bw_sampling_interval(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->lt_last_stamp = tp->delivered_mstamp.stamp_jiffies;
	bbr->lt_last_delivered = tp->delivered;
	bbr->lt_last_lost = tp->lost;
	bbr->lt_rtt_cnt = 0;
}

/* Completely reset long-term bandwidth sampling. */
static void bbr_reset_lt_bw_sampling(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->lt_bw = 0;
	bbr->lt_use_bw = 0;
	bbr->lt_is_sampling = false;
	bbr_reset_lt_bw_sampling_interval(sk);
}

/* Long-term bw sampling interval is done. Estimate whether we're policed. */
/*
	bw 为一个long-term带宽采样周期内的bw（deliverd / interval）

	long-term带宽采样周期结束，重新开始计时

	判断是否被限速
	判断条件：如果本采样周期的带宽与上一个采样周期的带宽之间变化不明显，则判定为被限速
	如果被限速，则设置bbr->lt_bw为这两个采样周期带宽的平均值，
	并设置lt_use_bw为1，标志着之后一段时间内（bbr_lt_bw_max_rtts）将使用这个bbr->lt_bw作为基准计算发送速率和拥塞窗口

	保存最新的long-term带宽采样值，重置采样周期进而开启下一个long-term带宽采样周期
*/
static void bbr_lt_bw_interval_done(struct sock *sk, u32 bw)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 diff;

	if (bbr->lt_bw) {  /* do we have bw from a previous interval? */
		/* Is new bw close to the lt_bw from the previous interval? */
		diff = abs(bw - bbr->lt_bw);

		/* If 2 intervals have a bw ratio <= 1/8, their bw is "consistent": */
		/* If 2 intervals have a bw diff <= 4 Kbit/sec their bw is "consistent": */

		if ((diff * BBR_UNIT <= bbr_lt_bw_ratio * bbr->lt_bw) ||
		    (bbr_rate_bytes_per_sec(sk, diff, BBR_UNIT) <=
		     bbr_lt_bw_diff)) {
			/* All criteria are met; estimate we're policed. */
			bbr->lt_bw = (bw + bbr->lt_bw) >> 1;  /* avg 2 intvls */
			bbr->lt_use_bw = 1;
			bbr->pacing_gain = BBR_UNIT;  /* try to avoid drops */
			bbr->lt_rtt_cnt = 0;
			return;
		}
	}
	bbr->lt_bw = bw;
	bbr_reset_lt_bw_sampling_interval(sk);
}

/* Token-bucket traffic policers are common (see "An Internet-Wide Analysis of
 * Traffic Policing", SIGCOMM 2016). BBR detects token-bucket policers and
 * explicitly models their policed rate, to reduce unnecessary losses. We
 * estimate that we're policed if we see 2 consecutive sampling intervals with
 * consistent throughput and high packet loss. If we think we're being policed,
 * set lt_bw to the "long-term" average delivery rate from those 2 intervals.
 */
/*
	进行long-term带宽采样
	
	如果本采样周期结束，则计算本采样周期的带宽（一个采样周期内的平均带宽值）

	long-term带宽采样周期开始：当前不处于采样状态，且出现丢包，则开始计时
	long-term带宽采样周期结束条件：
		1）采样周期时间长度合适（bbr_lt_intvl_min_rtts, 4 * bbr_lt_intvl_min_rtts)
		2）出现丢包
		3）丢包率（lost/delivered）大于20%
	以上条件，如果有一个不满足，则需继续等待，直至满足

	long-term带宽采样周期被中断，清空采样值，重新开始：
		1）出现app限定
		2）采样周期时间过长

	在使用long-term带宽值作为基准计算pacing rate和cwnd的情况下，
	long-term带宽值（限速情况下两个连续采样周期内的平均带宽值）最长有效期为bbr_lt_bw_max_rtts，超过则清空long-term带宽值，重新采样

	对于long-term带宽采样，可能存在3个状态：1）等待开始采样；2）采样中；3）long-term带宽值被使用中（限速情况下的稳态）

	令牌桶限速 如果发现2个连续采样周期满足：1）吞吐量恒定；2）丢包率较高，即认为被监管。
	如果被限速，则将带宽设置为这两个周期内的平均发送速率
*/
static void bbr_lt_bw_sampling(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 lost, delivered;
	u64 bw;
	s32 t;

	/*
		lt_use_bw 在判定被限速的情况下，lt_use_bw为1，即使用long-term带宽

		判断是否需要重新采样long-term带宽

		稳态状态下，使用long-term带宽不超过bbr_lt_bw_max_rtts个RTT，超过则清空long-term采样值，并随机从8个阶段的挑选一个阶段重新开始采样
	*/
	if (bbr->lt_use_bw) {	/* already using long-term rate, lt_bw? */
		if (bbr->mode == BBR_PROBE_BW && bbr->round_start &&
		    ++bbr->lt_rtt_cnt >= bbr_lt_bw_max_rtts) {
			bbr_reset_lt_bw_sampling(sk);    /* stop using lt_bw */
			bbr_reset_probe_bw_mode(sk);  /* restart gain cycling */
		}
		return;
	}

	/*
		采样开始需等到出现丢包，这样可以让限速器耗尽令牌，并能估算出限速器所允许的最大速率。
		如果采样早了，估算的带宽值将会偏大，因为包含了突发流量

		开始采样，重置采样周期

		路由器 流控 最大突发 突发处理能力
		突发处理能力是以最小帧间隔发送数据包而不引起丢失的最大发送速率来衡量的
	*/
	/* Wait for the first loss before sampling, to let the policer exhaust
	 * its tokens and estimate the steady-state rate allowed by the policer.
	 * Starting samples earlier includes bursts that over-estimate the bw.
	 */
	if (!bbr->lt_is_sampling) {
		if (!rs->losses)
			return;
		bbr_reset_lt_bw_sampling_interval(sk);
		bbr->lt_is_sampling = true;
	}

	/* To avoid underestimates, reset sampling if we run out of data. */
	/*
		当出现app限定时，为了避免低估，清空当前采样值，重新采样

		https://patchwork.ozlabs.org/patch/671061/
		Upon each transmit, we store in the is_app_limited field in the skb a
		boolean bit indicating whether there is a known "bubble in the pipe":
		a point in the rate sample interval where the sender was
		application-limited, and did not transmit even though the cwnd and
		pacing rate allowed it.

		This logic marks the flow app-limited on a write if *all* of the
		following are true:
		1) There is less than 1 MSS of unsent data in the write queue
		available to transmit.
		2) There is no packet in the sender's queues (e.g. in fq or the NIC
		tx queue).
		3) The connection is not limited by cwnd.

	*/
	if (rs->is_app_limited) {
		bbr_reset_lt_bw_sampling(sk);
		return;
	}

	/*
		判断采样周期时长是否合适

		采样周期内rtt计数+1
		采样周期rtt计数不小于bbr_lt_intvl_min_rtts，不满足则继续等待
		采样周期rtt计数不大于4 * bbr_lt_intvl_min_rtts，时间过长则清空采样值，重新采样
	*/
	if (bbr->round_start)
		bbr->lt_rtt_cnt++;	/* count round trips in this interval */
	if (bbr->lt_rtt_cnt < bbr_lt_intvl_min_rtts)
		return;		/* sampling interval needs to be longer */
	if (bbr->lt_rtt_cnt > 4 * bbr_lt_intvl_min_rtts) {
		bbr_reset_lt_bw_sampling(sk);  /* interval is too long */
		return;
	}

	/*
		没有丢包则继续等待（也就是long-term采样尽可能等到限速器的令牌桶被耗尽）

		当出现丢包时，我们猜测限速器令牌已被耗尽。在令牌消耗完前停止采样
	*/
	/* End sampling interval when a packet is lost, so we estimate the
	 * policer tokens were exhausted. Stopping the sampling before the
	 * tokens are exhausted under-estimates the policed rate.
	 */
	if (!rs->losses)
		return;

	/*
		计算本采样周期内的丢包数和发送数

		如果已发送的包数量为0或者丢包率较低（低于20%）则等待

		丢包率高则说明被限速了

		BBR无视了20%以下的丢包率
		BBR在无视丢包的情况下，会竞争吃掉CUBIC和其他BBR的带宽
	*/
	/* Calculate packets lost and delivered in sampling interval. */
	lost = tp->lost - bbr->lt_last_lost;
	delivered = tp->delivered - bbr->lt_last_delivered;
	/* Is loss rate (lost/delivered) >= lt_loss_thresh? If not, wait. */
	if (!delivered || (lost << BBR_SCALE) < bbr_lt_loss_thresh * delivered)
		return;

	/*
		计算本采样周期内的带宽：发送（成功）的数据包数量与本周期时间长度的比值
	*/
	/* Find average delivery rate in this sampling interval. */
	t = (s32)(tp->delivered_mstamp.stamp_jiffies - bbr->lt_last_stamp);
	if (t < 1)
		return;		/* interval is less than one jiffy, so wait */
	t = jiffies_to_usecs(t);
	/* Interval long enough for jiffies_to_usecs() to return a bogus 0? */
	if (t < 1) {
		bbr_reset_lt_bw_sampling(sk);  /* interval too long; reset */
		return;
	}
	bw = (u64)delivered * BW_UNIT;
	do_div(bw, t);
	bbr_lt_bw_interval_done(sk, bw);
}

/* Estimate the bandwidth based on how fast packets are delivered */
/*
	估算带宽

	判断是否进入了下一个RTT阶段（round）
	long-term带宽采样
	估算实时带宽
*/
static void bbr_update_bw(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 bw;

	bbr->round_start = 0;
	if (rs->delivered < 0 || rs->interval_us <= 0)
		return; /* Not a valid observation */

	/* See if we've reached the next RTT */
	/*
		是否到达下一个RTT，等同于当前RTT结束？

		bbr->next_rtt_delivered 一个周期开始时，记录当前已确认数据包数目

		下一个round开始：
		当前确认的数据包在其发送时刻记录的已确认数据包数目 大于等于 bbr->next_rtt_delivered

		tcp_rate_skb_delivered()
		When an skb is sacked or acked, we fill in the rate sample with the (prior)
		delivery information when the skb was last transmitted.

		rs->prior_delivered
	 	pkts S/ACKed so far upon tx of skb, incl retrans:
	 	当前确认的skb（数据包）在被发送的时候，已确认的数据包数目

		tp->delivered
	 	Total data packets delivered incl. rexmits
	 	当前确认的数据包数目
	 	它会被赋值给紧接着被发送的数据包的scb，赋值给scb的delivered字段
	 	当前被ACK或者SACK的数据包的scb中保存有delivered值，赋值给rs->prior_delivered

		tcp_ack()
		This routine deals with incoming acks, but not outgoing ones.

		tcp_rate_gen()
	 	rs->delivered   = tp->delivered - rs->prior_delivered;

		rs->delivered
	 	number of packets delivered over interval
	*/

	/*
		时间1：待发送数据包被发送时，发送端已确认的数据包数目为23456，
		时间2：发送端不断接受ACK/SACK，一旦确认的报文所对应的发送时已确认数据包数目大于或等于23456，则说明刚好经过一个往返周期

		RTT = 时间2-时间1
		当前发送的包开始的时间到此包被ACK或者SACK的时间之间的差


		round结束时
	*/
	if (!before(rs->prior_delivered, bbr->next_rtt_delivered)) {
		bbr->next_rtt_delivered = tp->delivered;
		bbr->rtt_cnt++;
		bbr->round_start = 1;
		bbr->packet_conservation = 0;
	}

	bbr_lt_bw_sampling(sk, rs);

	/* Divide delivered by the interval to find a (lower bound) bottleneck
	 * bandwidth sample. Delivered is in packets and interval_us in uS and
	 * ratio will be <<1 for most connections. So delivered is first scaled.
	 */
	/*
		计算实时带宽
	*/
	bw = (u64)rs->delivered * BW_UNIT;
	do_div(bw, rs->interval_us);

	/* If this sample is application-limited, it is likely to have a very
	 * low delivered count that represents application behavior rather than
	 * the available network rate. Such a sample could drag down estimated
	 * bw, causing needless slow-down. Thus, to continue to send at the
	 * last measured network rate, we filter out app-limited samples unless
	 * they describe the path bw at least as well as our bw model.
	 *
	 * So the goal during app-limited phase is to proceed with the best
	 * network rate no matter how long. We automatically leave this
	 * phase when app writes faster than the network can deliver :)
	 */
	/*
		如果当前被app限定，发送数值很可能非常小，这代表着app的行为而不是可用的网络速率
		像这样的采样会拖低估算带宽，引起不变要的降速。
		因此，为了能保证发送速率维持在上一次测量的网络速率，我们过滤掉app限定的采样值，除非他们至少像我们的带宽模型一样描述了链路带宽。

		所以在app限定阶段的目标是不管多长时间一直以最佳的网络速率进行处理。
		当app写入的比网络能发送的更快时，我们自动离开这个阶段。
	*/

	/*
		如果没有被app限定或者当前实时带宽值大于之前的最大采样值，则保存该实时带宽值

		struct minmax bw 保存一个时间窗口内的最有意义的最大值或者最小值
		win_minmax 很久之前(比如时间局部性之外的5分钟之前)的最大值或者最小值对于一个控制系统(比如TCP)来讲是没有意义的
	*/
	if (!rs->is_app_limited || bw >= bbr_max_bw(sk)) {
		/* Incorporate new sample into our max bw filter. */
		minmax_running_max(&bbr->bw, bbr_bw_rtts, bbr->rtt_cnt, bw);
	}
}

/* Estimate when the pipe is full, using the change in delivery rate: BBR
 * estimates that STARTUP filled the pipe if the estimated bw hasn't changed by
 * at least bbr_full_bw_thresh (25%) after bbr_full_bw_cnt (3) non-app-limited
 * rounds. Why 3 rounds: 1: rwin autotuning grows the rwin, 2: we fill the
 * higher rwin, 3: we get higher delivery rate samples. Or transient
 * cross-traffic or radio noise can go away. CUBIC Hystart shares a similar
 * design goal, but uses delay and inter-ACK spacing instead of bandwidth.
 */
/*
	检查是否已达最大带宽（startup状态），计数达到最大带宽的次数

	达到链路最大带宽：连续3个round过滤窗口内（10个rounds）实时带宽的最大值的增长率不超过25%

	未开始下一个round_start则等待
	app限定则等待
*/
static void bbr_check_full_bw_reached(struct sock *sk,
				      const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bw_thresh;

	if (bbr_full_bw_reached(sk) || !bbr->round_start || rs->is_app_limited)
		return;

	/* 如果当前时间窗口内（当前实时带宽更新后的）最大带宽相较于之前最大带宽有较大增长（25%），则说明还未填满链路 */
	bw_thresh = (u64)bbr->full_bw * bbr_full_bw_thresh >> BBR_SCALE;
	if (bbr_max_bw(sk) >= bw_thresh) {
		bbr->full_bw = bbr_max_bw(sk);
		bbr->full_bw_cnt = 0;
		return;
	}
	++bbr->full_bw_cnt;
}

/*
	判断是否进入drain状态，判断是否离开drain状态

	拥塞窗口增益控制了可进入FQ的数据包数量

	http://blog.csdn.net/dog250/article/details/72042516
	BBR核心模块按照拥塞窗口即inflight的限制，将N个数据包注入到Pacing发送引擎的发送缓冲区中，
	这些包会在这个缓冲区内部排队，最终在轮到自己的时候被发送出去。由于这个缓冲区里有足够的数据包，
	所以即使是ACK丢失了多个，或者接收端有LRO导致ACK被大面积聚集且延迟，发送缓冲区里面的数据包也足够发送一阵子了。

	进入drain状态条件：
		1）当前为startup状态
		2）已达最大带宽，
	满足以上条件则进入drain状态，速率增益变小（降速排空，因startup阶段发送速度较快可能导致了排队），拥塞窗口增益不变（并不是可发送数据包数目引起的）

	离开drain状态条件：
		1）在途数据包数量（网络上未确认的）小于目标拥塞窗口（窗口增益为1，相当于BDP）
	满足以上条件则说明已排空队列，进入稳态（probe_bw）状态（probe_bw状态下的拥塞窗口增益为2）
*/
/* If pipe is probably full, drain the queue and then enter steady-state. */
static void bbr_check_drain(struct sock *sk, const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);

	if (bbr->mode == BBR_STARTUP && bbr_full_bw_reached(sk)) {
		bbr->mode = BBR_DRAIN;	/* drain queue we created */
		bbr->pacing_gain = bbr_drain_gain;	/* pace slow to drain */
		bbr->cwnd_gain = bbr_high_gain;	/* maintain cwnd */
	}	/* fall through to check if in-flight is already small: */
	if (bbr->mode == BBR_DRAIN &&
	    tcp_packets_in_flight(tcp_sk(sk)) <=
	    bbr_target_cwnd(sk, bbr_max_bw(sk), BBR_UNIT))
		bbr_reset_probe_bw_mode(sk);  /* we estimate queue is drained */
}

/* The goal of PROBE_RTT mode is to have BBR flows cooperatively and
 * periodically drain the bottleneck queue, to converge to measure the true
 * min_rtt (unloaded propagation delay). This allows the flows to keep queues
 * small (reducing queuing delay and packet loss) and achieve fairness among
 * BBR flows.
 *
 * The min_rtt filter window is 10 seconds. When the min_rtt estimate expires,
 * we enter PROBE_RTT mode and cap the cwnd at bbr_cwnd_min_target=4 packets.
 * After at least bbr_probe_rtt_mode_ms=200ms and at least one packet-timed
 * round trip elapsed with that flight size <= 4, we leave PROBE_RTT mode and
 * re-enter the previous mode. BBR uses 200ms to approximately bound the
 * performance penalty of PROBE_RTT's cwnd capping to roughly 2% (200ms/10s).
 *
 * Note that flows need only pay 2% if they are busy sending over the last 10
 * seconds. Interactive applications (e.g., Web, RPCs, video chunks) often have
 * natural silences or low-rate periods within 10 seconds where the rate is low
 * enough for long enough to drain its queue in the bottleneck. We pick up
 * these min RTT measurements opportunistically with our min_rtt filter. :-)
 */
/*
	更新最小rtt

	为了能探测到最小rtt，需要将在途数据包数量限制在bbr_cwnd_min_target（4个）以下，并持续max(200 ms, 1 round)
	这个阶段被称为probe_rtt状态
	
	在probe_rtt状态下，速率增益为1，窗口增益为1，拥塞窗口将会被设置为一个很小的值（bbr_cwnd_min_target）
*/
static void bbr_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	bool filter_expired;

	/* 更新最小rtt */
	/* Track min RTT seen in the min_rtt_win_sec filter window: */
	filter_expired = after(tcp_time_stamp,
			       bbr->min_rtt_stamp + bbr_min_rtt_win_sec * HZ);
	/*
		1) 在bbr_min_rtt_win_sec（10s）内，冒泡取最小值更新bbr->min_rtt_us；
		2) 一旦超过了bbr_min_rtt_win_sec（10s），无条件用新值更新bbr->min_rtt_us，开启新一轮冒泡。
	*/
	if (rs->rtt_us >= 0 &&
	    (rs->rtt_us <= bbr->min_rtt_us || filter_expired)) {
		bbr->min_rtt_us = rs->rtt_us;
		bbr->min_rtt_stamp = tcp_time_stamp;
	}

	/*
		进入probe_rtt状态的4个必要条件：
			1）probe_rtt状态最低维持时间大于0
			2）超过了bbr_min_rtt_win_sec（10s）
			3）不是从idle中重启
			4）当前不是probe_rtt状态

		速率增益为1，窗口增益为1，并保存当前拥塞窗口
	*/
	if (bbr_probe_rtt_mode_ms > 0 && filter_expired &&
	    !bbr->idle_restart && bbr->mode != BBR_PROBE_RTT) {
		bbr->mode = BBR_PROBE_RTT;  /* dip, drain queue */
		bbr->pacing_gain = BBR_UNIT;
		bbr->cwnd_gain = BBR_UNIT;
		bbr_save_cwnd(sk);  /* note cwnd so we can restore it */
		bbr->probe_rtt_done_stamp = 0;
	}

	if (bbr->mode == BBR_PROBE_RTT) {
		/* Ignore low rate samples during this mode. */
		/*
			tp->app_limited
			limited until "delivered" reaches this val

			通过设置tp->app_limited，实现忽略该状态下的速率采样（速率太低）
		*/
		tp->app_limited =
			(tp->delivered + tcp_packets_in_flight(tp)) ? : 1;
		/* Maintain min packets in flight for max(200 ms, 1 round). */
		/*
			维持在途数据包数量在最少状态，并持续max(200 ms, 1 round)

			probe_rtt开始，且当前在途数据包数量小于4，则计算并记录probe_rtt阶段的结束时间

			至少一个rtt，并判断是否已到达结束时间
			如果结束则重置状态（根据当前是否达到过最大带宽，判断进入startup或者probe_bw）
		*/
		if (!bbr->probe_rtt_done_stamp &&
		    tcp_packets_in_flight(tp) <= bbr_cwnd_min_target) {
			bbr->probe_rtt_done_stamp = tcp_time_stamp +
				msecs_to_jiffies(bbr_probe_rtt_mode_ms);
			bbr->probe_rtt_round_done = 0;
			bbr->next_rtt_delivered = tp->delivered;
		} else if (bbr->probe_rtt_done_stamp) {
			if (bbr->round_start)
				bbr->probe_rtt_round_done = 1;
			if (bbr->probe_rtt_round_done &&
			    after(tcp_time_stamp, bbr->probe_rtt_done_stamp)) {
				bbr->min_rtt_stamp = tcp_time_stamp;
				bbr->restore_cwnd = 1;  /* snap to prior_cwnd */
				bbr_reset_mode(sk);
			}
		}
	}
	bbr->idle_restart = 0;
}

/*
	rs->losses作用：
		bbr_set_cwnd_to_recover_or_restore 
			有丢包，拥塞窗口更新为发送窗口减去丢包数之后的值与1之间的较大值 
		bbr_is_next_cycle_phase 
			增益大于1，探测带宽阶段 间隔时间超过min_rtt_us的条件下，如果有丢包或者inflight已经达到目标拥塞窗口
	 	bbr_lt_bw_sampling 
	   		采样开始需等到出现丢包，这样可以让限速器耗尽令牌，并能估算出限速器所允许的最大速率。
	    	当出现丢包时，我们猜测限速器令牌已被耗尽。在令牌消耗完前停止采样

    rs->acked_sacked作用
		更新拥塞窗口，合适的条件下拥塞窗口增加该值

	long-term带宽采样会计算在一个round内的丢包率
*/

static void bbr_update_model(struct sock *sk, const struct rate_sample *rs)
{
	/*
		后续计算都会以bw为计算基准，因此需首先更新bw

		根据rs，计算实时bw。每次调用都会计算得到一个bw，根据当前是否被app限制和是否大于目前最大实时带宽决定是否使用该实时带宽更新带宽最大值

		同时根据rs->prior_delivered判断是否为一个新round(RTT)

		tcp_rate_gen()产生rate采样时，会判断本次采样的间隔时间是否大于了最小RTT，如果没有大于最小RTT，则本次rate采样无效。
		如果rate采样无效（该时间间隔内没有报文到达，或者间隔时间无效），bbr_update_bw()也就不会计算实时bw。
	*/
	bbr_update_bw(sk, rs);

	/* BBR_PROBE_BW阶段 更新cycle */
	bbr_update_cycle_phase(sk, rs);

	/* BBR_STARTUP阶段 */
	bbr_check_full_bw_reached(sk, rs);
	
	/* BBR_DRAIN阶段 */
	bbr_check_drain(sk, rs);

	/*
		会判断最小RTT是否有效，如果无效则进入BBR_PROBE_RTT阶段
		最小RTT用来计算目标拥塞窗口、判断当前cycle是否结束（必要条件：cycle持续时间必须不小于一个最小RTT）
	*/
	bbr_update_min_rtt(sk, rs);
}

static void bbr_main(struct sock *sk, const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bw;

	bbr_update_model(sk, rs);

	/* 首先判断当前是否使用long-term带宽，是则返回lt_bw，否则使用实时带宽（上一个round的带宽） */
	bw = bbr_bw(sk);

	/*
		BBR_STARTUP启动阶段用大增益发现带宽最大值

		bbr_high_gain  = BBR_UNIT * 2885 / 1000 + 1; 约为3
		bbr_drain_gain = BBR_UNIT * 1000 / 2885; 约为1/3
		bbr_cwnd_gain  = BBR_UNIT * 2;

		                    bbr->pacing_gain        bbr->cwnd_gain
		BBR_STARTUP         bbr_high_gain           bbr_high_gain
		BBR_DRAIN           bbr_drain_gain          bbr_high_gain

		BBR_PROBE_BW        各cycle不同             bbr_cwnd_gain
		BBR_PROBE_RTT       BBR_UNIT                BBR_UNIT


		BBR_PROBE_RTT阶段的cwnd会减为4

		实时更新发送速率
		bbr_set_pacing_rate() 人为的根据增益调整发送速率，估算的带宽并不受影响
	*/
	bbr_set_pacing_rate(sk, bw, bbr->pacing_gain);
	bbr_set_tso_segs_goal(sk);

	/* 根据带宽，计算目标拥塞窗口，设置发送窗口（是否达到最大带宽、是否需要恢复等，当前拥塞窗口的基础上增加或者减小） */
	bbr_set_cwnd(sk, rs, rs->acked_sacked, bw, bbr->cwnd_gain);
}

static void bbr_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 bw;

	bbr->prior_cwnd = 0;
	bbr->tso_segs_goal = 0;	 /* default segs per skb until first ACK */
	bbr->rtt_cnt = 0;
	bbr->next_rtt_delivered = 0;
	bbr->prev_ca_state = TCP_CA_Open;
	bbr->packet_conservation = 0;

	bbr->probe_rtt_done_stamp = 0;
	bbr->probe_rtt_round_done = 0;
	bbr->min_rtt_us = tcp_min_rtt(tp);
	bbr->min_rtt_stamp = tcp_time_stamp;

	minmax_reset(&bbr->bw, bbr->rtt_cnt, 0);  /* init max bw to 0 */

	/* Initialize pacing rate to: high_gain * init_cwnd / RTT. */
	bw = (u64)tp->snd_cwnd * BW_UNIT;
	do_div(bw, (tp->srtt_us >> 3) ? : USEC_PER_MSEC);
	sk->sk_pacing_rate = 0;		/* force an update of sk_pacing_rate */
	bbr_set_pacing_rate(sk, bw, bbr_high_gain);

	bbr->restore_cwnd = 0;
	bbr->round_start = 0;
	bbr->idle_restart = 0;
	bbr->full_bw = 0;
	bbr->full_bw_cnt = 0;
	bbr->cycle_mstamp.v64 = 0;
	bbr->cycle_idx = 0;
	bbr_reset_lt_bw_sampling(sk);
	bbr_reset_startup_mode(sk);
}

static u32 bbr_sndbuf_expand(struct sock *sk)
{
	/* Provision 3 * cwnd since BBR may slow-start even during recovery. */
	return 3;
}

/* In theory BBR does not need to undo the cwnd since it does not
 * always reduce cwnd on losses (see bbr_main()). Keep it for now.
 */
static u32 bbr_undo_cwnd(struct sock *sk)
{
	return tcp_sk(sk)->snd_cwnd;
}

/* Entering loss recovery, so save cwnd for when we exit or undo recovery. */
static u32 bbr_ssthresh(struct sock *sk)
{
	bbr_save_cwnd(sk);
	return TCP_INFINITE_SSTHRESH;	 /* BBR does not use ssthresh */
}

static size_t bbr_get_info(struct sock *sk, u32 ext, int *attr,
			   union tcp_cc_info *info)
{
	if (ext & (1 << (INET_DIAG_BBRINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct bbr *bbr = inet_csk_ca(sk);
		u64 bw = bbr_bw(sk);

		bw = bw * tp->mss_cache * USEC_PER_SEC >> BW_SCALE;
		memset(&info->bbr, 0, sizeof(info->bbr));
		info->bbr.bbr_bw_lo		= (u32)bw;
		info->bbr.bbr_bw_hi		= (u32)(bw >> 32);
		info->bbr.bbr_min_rtt		= bbr->min_rtt_us;
		info->bbr.bbr_pacing_gain	= bbr->pacing_gain;
		info->bbr.bbr_cwnd_gain		= bbr->cwnd_gain;
		*attr = INET_DIAG_BBRINFO;
		return sizeof(info->bbr);
	}
	return 0;
}

static void bbr_set_state(struct sock *sk, u8 new_state)
{
	struct bbr *bbr = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		/* When an RTO expires, the sender enters the Loss state. */
		struct rate_sample rs = { .losses = 1 };

		bbr->prev_ca_state = TCP_CA_Loss;

		/*
			为什么要将full_bw清零？？？？？？
			startup检查是否达到最大带宽时，会使用full_bw计算带宽增长率
			将full_bw清零，则可将记录到达过最大带宽的计数清零，重新计数
		*/
		bbr->full_bw = 0;
		bbr->round_start = 1;	/* treat RTO like end of a round */
		bbr_lt_bw_sampling(sk, &rs);
	}
}

static struct tcp_congestion_ops tcp_bbr_cong_ops __read_mostly = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "bbr",
	.owner		= THIS_MODULE,
	.init		= bbr_init,
	.cong_control	= bbr_main, /* call when packets are delivered to update cwnd and pacing rate, after all the ca_state processing. (optional) */
	.sndbuf_expand	= bbr_sndbuf_expand, /* returns the multiplier used in tcp_sndbuf_expand (optional) */
	.undo_cwnd	= bbr_undo_cwnd, /* new value of cwnd after loss (optional) */
	.cwnd_event	= bbr_cwnd_event, /* call when cwnd event occurs (optional) */
	.ssthresh	= bbr_ssthresh, /* return slow start threshold (required) */
	.tso_segs_goal	= bbr_tso_segs_goal, /* suggest number of segments for each skb to transmit (optional) */
	.get_info	= bbr_get_info, /* get info for inet_diag (optional) */
	.set_state	= bbr_set_state, /* call before changing ca_state (optional) */
};

static int __init bbr_register(void)
{
	BUILD_BUG_ON(sizeof(struct bbr) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_bbr_cong_ops);
}

static void __exit bbr_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_bbr_cong_ops);
}

module_init(bbr_register);
module_exit(bbr_unregister);

MODULE_AUTHOR("Van Jacobson <vanj@google.com>");
MODULE_AUTHOR("Neal Cardwell <ncardwell@google.com>");
MODULE_AUTHOR("Yuchung Cheng <ycheng@google.com>");
MODULE_AUTHOR("Soheil Hassas Yeganeh <soheil@google.com>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP BBR (Bottleneck Bandwidth and RTT)");
