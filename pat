diff --git a/net/dccp/ipv6.c b/net/dccp/ipv6.c
--- a/net/dccp/ipv6.c
+++ b/net/dccp/ipv6.c
@@ -426,6 +426,9 @@ static struct sock *dccp_v6_request_recv_sock(const struct sock *sk,
 		newsk->sk_backlog_rcv = dccp_v4_do_rcv;
 		newnp->pktoptions  = NULL;
 		newnp->opt	   = NULL;
+		newnp->ipv6_mc_list = NULL;
+		newnp->ipv6_ac_list = NULL;
+		newnp->ipv6_fl_list = NULL;
 		newnp->mcast_oif   = inet6_iif(skb);
 		newnp->mcast_hops  = ipv6_hdr(skb)->hop_limit;
 
@@ -490,6 +493,9 @@ static struct sock *dccp_v6_request_recv_sock(const struct sock *sk,
 	/* Clone RX bits */
 	newnp->rxopt.all = np->rxopt.all;
 
+	newnp->ipv6_mc_list = NULL;
+	newnp->ipv6_ac_list = NULL;
+	newnp->ipv6_fl_list = NULL;
 	newnp->pktoptions = NULL;
 	newnp->opt	  = NULL;
 	newnp->mcast_oif  = inet6_iif(skb);
diff --git a/net/ipv6/tcp_ipv6.c b/net/ipv6/tcp_ipv6.c
index aeb9497..df5a9ff 100644
--- a/net/ipv6/tcp_ipv6.c
+++ b/net/ipv6/tcp_ipv6.c
@@ -1062,6 +1062,7 @@ static struct sock *tcp_v6_syn_recv_sock(const struct sock *sk, struct sk_buff *
 		newtp->af_specific = &tcp_sock_ipv6_mapped_specific;
 #endif
 
+		newnp->ipv6_mc_list = NULL;
 		newnp->ipv6_ac_list = NULL;
 		newnp->ipv6_fl_list = NULL;
 		newnp->pktoptions  = NULL;
@@ -1131,6 +1132,7 @@ static struct sock *tcp_v6_syn_recv_sock(const struct sock *sk, struct sk_buff *
 	   First: no IPv4 options.
 	 */
 	newinet->inet_opt = NULL;
+	newnp->ipv6_mc_list = NULL;
 	newnp->ipv6_ac_list = NULL;
 	newnp->ipv6_fl_list = NULL;
