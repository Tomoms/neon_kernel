/*
 * TCP Ascarex: end-to-end bandwidth estimation for TCP
 *
 * Based on Reno, Westwood and High speed
 * 
 * Ascarex employs end-to-end bandwidth measurement to set cwnd and
 * ssthresh after packet loss. The probing phase is as the original Reno.
 *
 * For the XPerience Project all credits to his creators
 *
 * - Carlos "Klozz" Jesus (TeamMex)
 *      klozz707@gmail.com
 *
 * Angelo Dell'Aera: author of the first version of TCP Westwood+ in Linux 2.4
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>
#include <net/tcp.h>

/* From AIMD tables from RFC 3649 appendix B,
 * with fixed-point MD scaled <<8.
 */
static const struct ascarex_aimd_val {
	unsigned int cwnd;
	unsigned int md;
} ascarex_aimd_vals[] = {
	{     38,  128, /*  0.50 */ },
	{    118,  112, /*  0.44 */ },
	{    221,  104, /*  0.41 */ },
	{    347,   98, /*  0.38 */ },
	{    495,   93, /*  0.37 */ },
	{    663,   89, /*  0.35 */ },
	{    851,   86, /*  0.34 */ },
	{   1058,   83, /*  0.33 */ },
	{   1284,   81, /*  0.32 */ },
	{   1529,   78, /*  0.31 */ },
	{   1793,   76, /*  0.30 */ },
	{   2076,   74, /*  0.29 */ },
	{   2378,   72, /*  0.28 */ },
	{   2699,   71, /*  0.28 */ },
	{   3039,   69, /*  0.27 */ },
	{   3399,   68, /*  0.27 */ },
	{   3778,   66, /*  0.26 */ },
	{   4177,   65, /*  0.26 */ },
	{   4596,   64, /*  0.25 */ },
	{   5036,   62, /*  0.25 */ },
	{   5497,   61, /*  0.24 */ },
	{   5979,   60, /*  0.24 */ },
	{   6483,   59, /*  0.23 */ },
	{   7009,   58, /*  0.23 */ },
	{   7558,   57, /*  0.22 */ },
	{   8130,   56, /*  0.22 */ },
	{   8726,   55, /*  0.22 */ },
	{   9346,   54, /*  0.21 */ },
	{   9991,   53, /*  0.21 */ },
	{  10661,   52, /*  0.21 */ },
	{  11358,   52, /*  0.20 */ },
	{  12082,   51, /*  0.20 */ },
	{  12834,   50, /*  0.20 */ },
	{  13614,   49, /*  0.19 */ },
	{  14424,   48, /*  0.19 */ },
	{  15265,   48, /*  0.19 */ },
	{  16137,   47, /*  0.19 */ },
	{  17042,   46, /*  0.18 */ },
	{  17981,   45, /*  0.18 */ },
	{  18955,   45, /*  0.18 */ },
	{  19965,   44, /*  0.17 */ },
	{  21013,   43, /*  0.17 */ },
	{  22101,   43, /*  0.17 */ },
	{  23230,   42, /*  0.17 */ },
	{  24402,   41, /*  0.16 */ },
	{  25618,   41, /*  0.16 */ },
	{  26881,   40, /*  0.16 */ },
	{  28193,   39, /*  0.16 */ },
	{  29557,   39, /*  0.15 */ },
	{  30975,   38, /*  0.15 */ },
	{  32450,   38, /*  0.15 */ },
	{  33986,   37, /*  0.15 */ },
	{  35586,   36, /*  0.14 */ },
	{  37253,   36, /*  0.14 */ },
	{  38992,   35, /*  0.14 */ },
	{  40808,   35, /*  0.14 */ },
	{  42707,   34, /*  0.13 */ },
	{  44694,   33, /*  0.13 */ },
	{  46776,   33, /*  0.13 */ },
	{  48961,   32, /*  0.13 */ },
	{  51258,   32, /*  0.13 */ },
	{  53677,   31, /*  0.12 */ },
	{  56230,   30, /*  0.12 */ },
	{  58932,   30, /*  0.12 */ },
	{  61799,   29, /*  0.12 */ },
	{  64851,   28, /*  0.11 */ },
	{  68113,   28, /*  0.11 */ },
	{  71617,   27, /*  0.11 */ },
	{  75401,   26, /*  0.10 */ },
	{  79517,   26, /*  0.10 */ },
	{  84035,   25, /*  0.10 */ },
	{  89053,   24, /*  0.10 */ },
};

/* TCP Ascarex structure */
struct ascarex {
	u32    bw_ns_est;        /* first bandwidth estimation..not too smoothed 8) */
	u32    bw_est;           /* bandwidth estimate */
	u32    rtt_win_sx;       /* here starts a new evaluation... */
	u32    bk;
	u32    snd_una;          /* used for evaluating the number of acked bytes */
	u32    cumul_ack;
	u32    accounted;
	u32    ai;
	u32    rtt;
	u32    rtt_min;          /* minimum observed RTT */
	u8     first_ack;        /* flag which infers that this is the first ack */
	u8     reset_rtt_min;    /* Reset RTT min to next RTT sample*/
};

/* TCP Ascarex functions and constants */
#define TCP_ASCAREX_RTT_MIN   (HZ/30)	/* 30ms */
#define TCP_ASCAREX_INIT_RTT  (30*HZ)	/* maybe too conservative?! */
#define ASCAREX_AIMD_MAX	ARRAY_SIZE(ascarex_aimd_vals) /* Set the array size */

/*
 * @tcp_ascarex_create
 * This function initializes fields used in TCP Ascarex,
 * it is called after the initial SYN, so the sequence numbers
 * are correct but new passive connections we have no
 * information about RTTmin at this time so we simply set it to
 * TCP_ASCAREX_INIT_RTT. This value was chosen to be too conservative
 * since in this way we're sure it will be updated in a consistent
 * way as soon as possible. It will reasonably happen within the first
 * RTT period of the connection lifetime.
 */
static void tcp_ascarex_init(struct sock *sk)
{
	struct ascarex *w = inet_csk_ca(sk);

	w->bk = 0;
	w->bw_ns_est = 0;
	w->bw_est = 0;
	w->accounted = 0;
	w->cumul_ack = 0;
	w->reset_rtt_min = 1;
	w->rtt_min = w->rtt = TCP_ASCAREX_INIT_RTT;
	w->rtt_win_sx = tcp_time_stamp;
	w->snd_una = tcp_sk(sk)->snd_una;
	w->first_ack = 1;
}

/*
 * @ascarex_do_filter
 * Low-pass filter. Implemented using constant coefficients.
 */
static inline u32 ascarex_do_filter(u32 a, u32 b)
{
	return ((7 * a) + b) >> 3;
}

static void ascarex_filter(struct ascarex *w, u32 delta)
{
	/* If the filter is empty fill it with the first sample of bandwidth  */
	if (w->bw_ns_est == 0 && w->bw_est == 0) {
		w->bw_ns_est = w->bk / delta;
		w->bw_est = w->bw_ns_est;
	} else {
		w->bw_ns_est = ascarex_do_filter(w->bw_ns_est, w->bk / delta);
		w->bw_est = ascarex_do_filter(w->bw_est, w->bw_ns_est);
	}
}

/*
 * @ascarex_pkts_acked
 * Called after processing group of packets.
 * but all ascarex needs is the last sample of srtt.
 */
static void tcp_ascarex_pkts_acked(struct sock *sk, u32 cnt, s32 rtt)
{
	struct ascarex *w = inet_csk_ca(sk);

	if (rtt > 0)
		w->rtt = usecs_to_jiffies(rtt);
}

/*
 * @ascarex_update_window
 * It updates RTT evaluation window if it is the right moment to do
 * it. If so it calls filter for evaluating bandwidth.
 */
static void ascarex_update_window(struct sock *sk)
{
	struct ascarex *w = inet_csk_ca(sk);
	s32 delta = tcp_time_stamp - w->rtt_win_sx;

	/* Initialize w->snd_una with the first acked sequence number in order
	 * to fix mismatch between tp->snd_una and w->snd_una for the first
	 * bandwidth sample
	 */
	if (w->first_ack) {
		w->snd_una = tcp_sk(sk)->snd_una;
		w->first_ack = 0;
	}

	/*
	 * See if a RTT-window has passed.
	 * Be careful since if RTT is less than
	 * 30ms we don't filter but we continue 'building the sample'.
	 * This minimum limit was chosen since an estimation on small
	 * time intervals is better to avoid...
	 * Obviously on a LAN we reasonably will always have
	 * right_bound = left_bound + ASCAREX_RTT_MIN
	 */
	if (w->rtt && delta > max_t(u32, w->rtt, TCP_ASCAREX_RTT_MIN)) {
		ascarex_filter(w, delta);

		w->bk = 0;
		w->rtt_win_sx = tcp_time_stamp;
	}
}

static inline void update_rtt_min(struct ascarex *w)
{
	if (w->reset_rtt_min) {
		w->rtt_min = w->rtt;
		w->reset_rtt_min = 0;
	} else
		w->rtt_min = min(w->rtt, w->rtt_min);
}

/*
 * @ascarex_fast_bw
 * It is called when we are in fast path. In particular it is called when
 * header prediction is successful. In such case in fact update is
 * straight forward and doesn't need any particular care.
 */
static inline void ascarex_fast_bw(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct ascarex *w = inet_csk_ca(sk);

	ascarex_update_window(sk);

	w->bk += tp->snd_una - w->snd_una;
	w->snd_una = tp->snd_una;
	update_rtt_min(w);
}

/*
 * @ascarex_acked_count
 * This function evaluates cumul_ack for evaluating bk in case of
 * delayed or partial acks.
 */
static inline u32 ascarex_acked_count(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct ascarex *w = inet_csk_ca(sk);

	w->cumul_ack = tp->snd_una - w->snd_una;

	/* If cumul_ack is 0 this is a dupack since it's not moving
	 * tp->snd_una.
	 */
	if (!w->cumul_ack) {
		w->accounted += tp->mss_cache;
		w->cumul_ack = tp->mss_cache;
	}

	if (w->cumul_ack > tp->mss_cache) {
		/* Partial or delayed ack */
		if (w->accounted >= w->cumul_ack) {
			w->accounted -= w->cumul_ack;
			w->cumul_ack = tp->mss_cache;
		} else {
			w->cumul_ack -= w->accounted;
			w->accounted = 0;
		}
	}

	w->snd_una = tp->snd_una;

	return w->cumul_ack;
}

/*
 * TCP Ascarex
 * Here limit is evaluated as Bw estimation*RTTmin (for obtaining it
 * in packets we use mss_cache). Rttmin is guaranteed to be >= 2
 * so avoids ever returning 0.
 */
static u32 tcp_ascarex_bw_rttmin(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct ascarex *w = inet_csk_ca(sk);

	return max_t(u32, (w->bw_est * w->rtt_min) / tp->mss_cache, 2);
}

static void tcp_ascarex_ack(struct sock *sk, u32 ack_flags)
{
	if (ack_flags & CA_ACK_SLOWPATH) {
		struct ascarex *w = inet_csk_ca(sk);

		ascarex_update_window(sk);
		w->bk += ascarex_acked_count(sk);

		update_rtt_min(w);
		return;
	}

	ascarex_fast_bw(sk);
}

static void tcp_ascarex_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ascarex *w = inet_csk_ca(sk);

	switch (event) {
	case CA_EVENT_COMPLETE_CWR:
		tp->snd_cwnd = tp->snd_ssthresh = tcp_ascarex_bw_rttmin(sk);
		break;
	case CA_EVENT_LOSS:
		tp->snd_ssthresh = tcp_ascarex_bw_rttmin(sk);
		/* Update RTT_min when next ack arrives */
		w->reset_rtt_min = 1;
		break;
	default:
		/* don't care */
		break;
	}
}

/* Extract info for Tcp socket info provided via netlink. */
static void tcp_ascarex_info(struct sock *sk, u32 ext,
			      struct sk_buff *skb)
{
	const struct ascarex *ca = inet_csk_ca(sk);

	if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcpvegas_info info = {
			.tcpv_enabled = 1,
			.tcpv_rtt = jiffies_to_usecs(ca->rtt),
			.tcpv_minrtt = jiffies_to_usecs(ca->rtt_min),
		};

		nla_put(skb, INET_DIAG_VEGASINFO, sizeof(info), &info);
	}
}

static struct tcp_congestion_ops tcp_ascarex __read_mostly = {
	.init		= tcp_ascarex_init,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.cwnd_event	= tcp_ascarex_event,
	.in_ack_event	= tcp_ascarex_ack,
	.get_info	= tcp_ascarex_info,
	.pkts_acked	= tcp_ascarex_pkts_acked,

	.owner		= THIS_MODULE,
	.name		= "ascarex"
};

static int __init tcp_ascarex_register(void)
{
	BUILD_BUG_ON(sizeof(struct ascarex) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_ascarex);
}

static void __exit tcp_ascarex_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_ascarex);
}

module_init(tcp_ascarex_register);
module_exit(tcp_ascarex_unregister);

MODULE_AUTHOR("Stephen Hemminger, Angelo Dell'Aera, klozz jesus (TEAMMEX)");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP Ascarex");
