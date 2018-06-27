#include "ping.h" 

struct proto proto_v4 = { proc_v4, send_v4, NULL, NULL, 0, IPPROTO_ICMP };

#ifdef IPV6
struct proto proto_v6 = { proc_v6, send_v6, NULL, NULL, 0, IPPROTO_ICMPV6 };
#endif

int main(int argc, char **argv)
{
	int c = 0;
	int hex = 0x0;
	char str[5];
	memset(str, 0, sizeof(str));

	/*ping Usage: 
	Usage: ping [-aAbBdDfhLnOqrRUvV] [-c count] [-i interval] [-I interface]
            [-m mark] [-M pmtudisc_option] [-l preload] [-p pattern] [-Q tos]
            [-s packetsize] [-S sndbuf] [-t ttl] [-T timestamp_option]
            [-w deadline] [-W timeout] [hop1 ...] destination
	*/


	//getopt()
	//optind-cursor of next parameter
	//opterr-whether or not output error information into stderr
	//optopt-choice not declared in optstring
	
	(void)signal(SIGINT,proc_rtt);//CTRL+C

	opterr = 0;
	while ((c = getopt(argc, argv, "bfhnqrUvc:i:p:Q:s:S:t:w:W:")) != -1) {
		switch (c) {
		//WITH NO PARAMETER
		case 'b':
			b_broadcast = TRUE;
			printf("WARNING: pinging broadcast address.\n");
			break;
		case 'd':
			b_debug = TRUE;
			printf("\n");
			break;
		case 'f':
			b_flood = TRUE;
			interval = FLOOD_INTERVAL;
			break;
		case 'h':
			printf("Usage: ping [-aAbBdDfhLnOqrRUvV] [-c count] [-i interval] [-I interface]\n            [-m mark] [-M pmtudisc_option] [-l preload] [-p pattern] [-Q tos]\n            [-s packetsize] [-S sndbuf] [-t ttl] [-T timestamp_option]\n            [-w deadline] [-W timeout] [hop1 ...] destination\n");
			break;
		case 'n':
			b_nonhostname = TRUE;
			break;
		case 'q':
			b_quiet = TRUE;
			break;
		case 'r':
			b_direct_routing = TRUE;
			ttl = 2;
			break;
		case 'v':
			verbose++;
			b_verbose = TRUE;
			break;
		case 'V':
			printf("ping utility, iputils-s20180702.\n");
			break;
		case 'U':
			b_full_latency = TRUE;
			break;
		//WITH PARAMETERS
		case 'c':
			count = atoi(optarg);
			if(count <= 0)
				err_quit("ping: bad number of packets to transmit.\n");
			break;
		case 'i':
			interval = atof(optarg);
			if(interval < 0.2)
				err_quit("ping: cannot flood; minimal interval allowed for user is 200ms.\n");
			break;
		case 'p':
			strcat(str,"0x");
			strcat(str,optarg);
			hex = htoi(str);
			pattern = hex & 0x00ff;
			break;
		case 'Q':
			tos = atoi(optarg);
			break;
		case 'S':
			sndbuf = atoi(optarg);
			if(sndbuf <= 0)
				err_quit("ping: bad sndbuf value.\n");
			break;
		case 's':
			packetsize = atoi(optarg);
			datalen = packetsize;
			if(packetsize < 0 || packetsize > 65507)
				err_quit("ping: illegal negative packet size -1.\n");
			break;
		case 't':
			ttl = atoi(optarg);
			if(ttl < 1)
				err_quit("ping: can't set unicast time-to-live: Invalid argument.\n");
			if(ttl == 1)
				b_loopback = TRUE;
			break;
		case 'w':
			deadline = atof(optarg);
			if(deadline < 0)
				err_quit("ping: bad wait time.\n");
			break;
		case 'W':
			timeout = atof(optarg);
			if(timeout < 0)
				err_quit("ping: bad wait time.\n");
			break;
		//UNSPEC
		case '?':
			err_quit("unrecognized option: %c\n", c);
		}
	}

	if (optind != argc - 1)
		err_quit("usage: ping [ -v ] <hostname>");
	host = argv[optind];
	
	pid = getpid();
	//signal(SIGALRM, sig_alrm);

	ai = host_serv(host, NULL, 0, 0);
	if(b_nonhostname == FALSE)
		printf("ping %s (%s): %d data bytes\n", ai->ai_canonname, Sock_ntop_host(ai->ai_addr, ai->ai_addrlen), datalen);
	else 
		printf("ping %s: %d data bytes\n",  Sock_ntop_host(ai->ai_addr, ai->ai_addrlen), datalen);
	
	if (ai->ai_family == AF_INET) {
		pr = &proto_v4;
#ifdef IPV6
	}
	else if (ai->ai_family == AF_INET6) {
		pr = &proto_v6;
		if (IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr)))
			err_quit("cannot ping IPv4-mapped IPv6 address");
#endif
	}
	else
		err_quit("unknown address family %d", ai->ai_family);

	pr->sasend = ai->ai_addr;
	pr->sarecv = calloc(1, ai->ai_addrlen);
	pr->salen = ai->ai_addrlen;//IPV4 16

	readloop();

	exit(0);
}

void readloop(void)
{
	int size;
	char recvbuf[BUFSIZE];
	socklen_t len;
	ssize_t n;
	struct timeval tval;
	struct timeval tval_curr;
	struct timeval tval_last;
	int tmp_nsent;

	gettimeofday(&tval_start, NULL);
	gettimeofday(&tval_last, NULL);

	sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);
	setuid(getuid());  /* don't need special permissions any more */

	size = 60 * 1024;  /* OK if setsockopt fails */
	setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (const char *)&b_broadcast, sizeof(b_broadcast));//[-b]
	setsockopt(sockfd, SOL_SOCKET, SO_DEBUG, (const char *)&b_debug, sizeof(b_debug));//[-d]
	setsockopt(sockfd, IPPROTO_IP, IP_TOS, (const char *)&tos, sizeof(tos));//[-Q tos]
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char *)&size, sizeof(size));//[-s packetsize]
	setsockopt(sockfd, IPPROTO_IP, IP_TTL, (const char *)&ttl, sizeof(ttl));//[-t ttl]
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char *)&sndbuf, sizeof(int));//[-S sndbuf]
	
	init_sigaction();
	init_timer(interval);	
	//sig_alrm(SIGALRM);  /* send first packet */

	for(;;){//[-c count]
		len = pr->salen;
		gettimeofday(&tval, NULL);
		n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
		gettimeofday(&tval_end, NULL);

		//[-w deadline]
		gettimeofday(&tval_curr, NULL);
		tv_sub(&tval_curr, &tval_start);
		if(((&tval_curr)->tv_sec * 1000.0 + (&tval_curr)->tv_usec / 1000.0) > deadline * 1000.0)
			break;

		if (n < 0) {
			if (errno == EINTR)
			{	
				gettimeofday(&tval_recv, NULL);
				tv_sub(&tval_recv, &tval_send);
				if(((&tval_curr)->tv_sec * 1000.0 + (&tval_curr)->tv_usec / 1000.0) > timeout * 1.0) {
					printf("ping: request timeout.\n");
				}
				continue;
			}
			else
				err_sys("recvfrom error");
		}

		if(b_full_latency == TRUE)
			gettimeofday(&tval, NULL);

		(*pr->fproc)(recvbuf, n, &tval);//Output: icmp_sec & ttl & time
		
		received += 1;

		if(nsent >= count)
			break;
	}

	proc_rtt(0);//Output: ping statistics
}

void proc_v4(char *ptr, ssize_t len, struct timeval *tvrecv)
{
	int hlen1, icmplen;
	double rtt, time;
	struct ip  *ip;
	struct icmp  *icmp;
	struct timeval *tvsend;

	ip = (struct ip *) ptr;  /* start of IP header */
	hlen1 = ip->ip_hl << 2;  /* length of IP header */

	icmp = (struct icmp *) (ptr + hlen1); /* start of ICMP header */
	if ((icmplen = len - hlen1) < 8)
		err_quit("icmplen (%d) < 8", icmplen);

	if (icmp->icmp_type == ICMP_ECHOREPLY || b_verbose == TRUE) {//[-v]
		if (icmp->icmp_id != pid && b_verbose == FALSE)
			return; /* not a response to our ECHO_REQUEST */
		if (icmplen < 16)
			err_quit("icmplen (%d) < 16", icmplen);

		tvsend = (struct timeval *) icmp->icmp_data;
		tv_sub(tvrecv, tvsend);
		rtt = time = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;//Round-Trip time
		rtt_list[icmp->icmp_seq] = rtt;
		
		if(b_quiet == FALSE) {//[-q]
			if(b_flood == FALSE) {
				if(b_full_latency == FALSE){
					printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n", icmplen, Sock_ntop_host(pr->sarecv, pr->salen), icmp->icmp_seq, ip->ip_ttl, rtt);
				}
				else {
					printf("%d bytes from %s: seq=%u, ttl=%d, time=%.3f ms\n", icmplen, Sock_ntop_host(pr->sarecv, pr->salen), icmp->icmp_seq, ip->ip_ttl, time);
				}
			}
			else {
				putchar('\b');
				putchar(' ');	
				putchar('\b');
			}
		}
	}
	else if (verbose) {
		if(b_quiet == FALSE)//[-q]
			printf("  %d bytes from %s: type = %d, code = %d\n",
			icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
			icmp->icmp_type, icmp->icmp_code);
	}
}


void proc_v6(char *ptr, ssize_t len, struct timeval* tvrecv)
{
#ifdef IPV6
	int  hlen1, icmp6len;
	double rtt;
	struct ip6_hdr  *ip6;
	struct icmp6_hdr *icmp6;
	struct timeval  *tvsend;

	/*
	ip6 = (struct ip6_hdr *) ptr;  // start of IPv6 header
	hlen1 = sizeof(struct ip6_hdr);
	if (ip6->ip6_nxt != IPPROTO_ICMPV6)
	err_quit("next header not IPPROTO_ICMPV6");

	icmp6 = (struct icmp6_hdr *) (ptr + hlen1);
	if ( (icmp6len = len - hlen1) < 8)
	err_quit("icmp6len (%d) < 8", icmp6len);
	*/

	icmp6 = (struct icmp6_hdr *)ptr;
	if ((icmp6len = len) < 8)   //len-40
		err_quit("icmp6len (%d) < 8", icmp6len);

	if (icmp6->icmp6_type == ICMP6_ECHO_REPLY || b_verbose == TRUE) {//[-v]
		if (icmp6->icmp6_id != pid && b_verbose == FALSE)
			return; /* not a response to our ECHO_REQUEST */
		if (icmp6len < 16)
			err_quit("icmp6len (%d) < 16", icmp6len);

		tvsend = (struct timeval *) (icmp6 + 1);
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;
		//rtt_list[icmp6->icmp_seq] = rtt;

		sleep(interval);

		printf("%d bytes from %s: seq=%u, hlim=%d, rtt=%.3f ms\n",
			icmp6len, Sock_ntop_host(pr->sarecv, pr->salen),
			icmp6->icmp6_seq, ip6->ip6_hlim, rtt);
	}
	else if (verbose) {
		printf("  %d bytes from %s: type = %d, code = %d\n",
			icmp6len, Sock_ntop_host(pr->sarecv, pr->salen),
			icmp6->icmp6_type, icmp6->icmp6_code);
	}
#endif /* IPV6 */
}

void proc_rtt(int sig)
{
	int i = 0;
	double rtt = 0.0;
	double sum = 0.0;

	tv_sub(&tval_end, &tval_start);
	totaltime = tval_end.tv_sec * 1000.0 + tval_end.tv_usec / 1000.0;
	loss = ((double)(transmitted - received)/(double)transmitted) * 100.0;
	min = max = rtt_list[0];

	for(i = 0;i < received;i++){
		rtt = rtt_list[i];
		sum += rtt;
		if(rtt < min)
			min = rtt;
		else if (rtt > max)
			max = rtt;
	}

	avg = sum / received;
	mdev = max - min;

	printf("\n--- %s ping statistics ---\n",Sock_ntop_host(pr->sarecv, pr->salen));
	printf("%d packets transmitted, %d received, %.3f%% packet loss, time %.3lf ms\n",transmitted, received, loss, totaltime);
	printf("rtt min/avg/max/mdev = %.3lf/%.3lf/%.3lf/%.3lf\n\n", min, avg, max, mdev);

	exit(0);
}

unsigned short in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short  *w = addr;
	unsigned short  answer = 0;

	/*
	* Our algorithm is simple, using a 32 bit accumulator (sum), we add
	* sequential 16 bit words to it, and at the end, fold back all the
	* carry bits from the top 16 bits into the lower 16 bits.
	*/
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* 4mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(unsigned char *)w;
		sum += answer;
	}

	/* 4add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);  /* add hi 16 to low 16 */
	sum += (sum >> 16);  /* add carry */
	answer = ~sum; /* truncate to 16 bits */
	return(answer);
}

void send_v4(void)
{
	int len;
	struct icmp *icmp;

	icmp = (struct icmp *) sendbuf;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = pattern;//[-p pattern]
	//icmp->icmp_code = 0;
	icmp->icmp_id = pid;
	icmp->icmp_seq = nsent++;
	gettimeofday((struct timeval *) icmp->icmp_data, NULL);

	len = 8 + datalen;  /* checksum ICMP header and data */
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_short *)icmp, len);

	sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
}

void send_v6()
{
#ifdef IPV6
	int  len;
	struct icmp6_hdr *icmp6;

	icmp6 = (struct icmp6_hdr *) sendbuf;
	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_id = pid;
	icmp6->icmp6_seq = nsent++;
	gettimeofday((struct timeval *) (icmp6 + 1), NULL);

	len = 8 + datalen;  /* 8-byte ICMPv6 header */

	sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
	/* kernel calculates and stores checksum for us */
#endif /* IPV6 */
}

void sig_alrm(int signo)
{
	static int i = 0;

	(*pr->fsend)();

	gettimeofday(&tval_send, NULL);

	transmitted += 1;

	if(b_flood == TRUE) {
		putchar('.');
		
	}

	if(b_loopback == TRUE) {
		printf("From localhost (%s): seq=%u Time to live exceeded\n", Sock_ntop_host(ai->ai_addr, ai->ai_addrlen), i++);
	}
	else if(b_direct_routing == TRUE && received == 0) {
		printf("ping: sendmsg: Network is unreachable.\n");
	}

	//alarm(interval);//[-i interval]
	//alarm(1);
	
	return; /* probably interrupts recvfrom() */
}

void tv_sub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) { /* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

char *sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
	static char str[128];  /* Unix domain is largest */

	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *) sa;

		if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
			return(NULL);
		return(str);
	}

#ifdef  IPV6
	case AF_INET6: {
		struct sockaddr_in6  *sin6 = (struct sockaddr_in6 *) sa;

		if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL)
			return(NULL);
		return(str);
	}
#endif

#ifdef  HAVE_SOCKADDR_DL_STRUCT
	case AF_LINK: {
		struct sockaddr_dl *sdl = (struct sockaddr_dl *) sa;

		if (sdl->sdl_nlen > 0)
			snprintf(str, sizeof(str), "%*s",
				sdl->sdl_nlen, &sdl->sdl_data[0]);
		else
			snprintf(str, sizeof(str), "AF_LINK, index=%d", sdl->sdl_index);
		return(str);
	}
#endif
	default:
		snprintf(str, sizeof(str), "sock_ntop_host: unknown AF_xxx: %d, len %d", sa->sa_family, salen);
		return(str);
}
	return (NULL);
}

char *Sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
	char *ptr;

	if ((ptr = sock_ntop_host(sa, salen)) == NULL)
		err_sys("sock_ntop_host error");  /* inet_ntop() sets errno */
	return(ptr);
}

struct addrinfo *host_serv(const char *host, const char *serv, int family, int socktype)
{
	int n;
	struct addrinfo hints, *res;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;  /* always return canonical name */
	hints.ai_family = family;  /* AF_UNSPEC, AF_INET, AF_INET6, etc. */
	hints.ai_socktype = socktype; /* 0, SOCK_STREAM, SOCK_DGRAM, etc. */

	if ((n = getaddrinfo(host, serv, &hints, &res)) != 0)
		return(NULL);

	return(res); /* return pointer to first on linked list */
}

static void err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
	int errno_save, n;
	char buf[MAXLINE];

	errno_save = errno;  /* value caller might want printed */
#ifdef  HAVE_VSNPRINTF
	vsnprintf(buf, sizeof(buf), fmt, ap); /* this is safe */
#else
	vsprintf(buf, fmt, ap);  /* this is not safe */
#endif
	n = strlen(buf);
	if (errnoflag)
		snprintf(buf + n, sizeof(buf) - n, ": %s", strerror(errno_save));
	strcat(buf, "\n");

	if (daemon_proc) {
		;//syslog(level, buf);
	}
	else {
		fflush(stdout); /* in case stdout and stderr are the same */
		fputs(buf, stderr);
		fflush(stderr);
	}
	return;
}

/* Fatal error unrelated to a system call.
 * Print a message and terminate. */

void err_quit(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_doit(0, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

/* Fatal error related to a system call.
 * Print a message and terminate. */

void err_sys(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_doit(1, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

/*Self-defined*/
void init_timer(double interval)
{
	struct itimerval value;
	memset(&value, 0, sizeof(value));

	value.it_value.tv_sec = 0;
	value.it_value.tv_usec = 1000;

	value.it_interval.tv_sec = (int)interval;//(int)interval;
	value.it_interval.tv_usec = (int)((interval - (double)(value.it_interval.tv_sec)) * 1000000);

	setitimer(ITIMER_REAL, &value, NULL);
}

void init_sigaction(void)
{
	struct sigaction tact;
	tact.sa_handler = sig_alrm;
	tact.sa_flags = 0;
	sigemptyset(&tact.sa_mask);
	sigaction(SIGALRM, &tact, NULL);
}

int tolower(int c)  
{  
    if (c >= 'A' && c <= 'Z')
        return c + 'a' - 'A';
    else
        return c;
}
  
int htoi(char s[])  
{  
    int i;  
    int n = 0;  
    if (s[0] == '0' && (s[1]=='x' || s[1]=='X'))
        i = 2;
    else
        i = 0;
    for (; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >='A' && s[i] <= 'Z');++i)  
    {  
        if (tolower(s[i]) > '9')
            n = 16 * n + (10 + tolower(s[i]) - 'a');
        else
            n = 16 * n + (tolower(s[i]) - '0');
    }  
    return n;  
}  









