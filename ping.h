#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <sys/types.h> /* basic system data types */
#include <sys/socket.h> /* basic socket definitions */
#include <sys/time.h> /* timeval{} for select() */
#include <time.h> /* timespec{} for pselect() */
#include <netinet/in.h> /* sockaddr_in{} and other Internet defns */
#include <arpa/inet.h> /* inet(3) functions */
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/un.h> /* for Unix domain sockets */
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdarg.h>
#include <syslog.h>
#ifdef HAVE_SOCKADDR_DL_STRUCT
#include <net/if_dl.h>
#endif

#define IPV6

#define BUFSIZE 1500
#define MAXLINE  4096

/* globals */
char recvbuf[BUFSIZE];
char sendbuf[BUFSIZE];

int datalen = 56; /* #bytes of data, following ICMP header */
char *host;
int nsent = 0;  /* add 1 for each sendto() */
pid_t pid;  /* our PID */
int sockfd;
int verbose;
int daemon_proc;  /* set nonzero by daemon_init() */

struct addrinfo *ai;

/* function prototypes */
void proc_v4(char *, ssize_t, struct timeval *);
void proc_v6(char *, ssize_t, struct timeval *);
void send_v4(void);
void send_v6(void);
void readloop(void);
void sig_alrm(int);
void tv_sub(struct timeval *, struct timeval *);

char * Sock_ntop_host(const struct sockaddr *sa, socklen_t salen);
struct addrinfo* host_serv(const char *host, const char *serv, int family, int socktype);
static void err_doit(int errnoflag, int level, const char *fmt, va_list ap);
void err_quit(const char *fmt, ...);
void err_sys(const char *fmt, ...);

struct proto {
 void (*fproc)(char *, ssize_t, struct timeval *);  /* icmp_seq ttl time */
 void (*fsend)(void);  /* send packet */
 struct sockaddr *sasend; /* sockaddr{} for send, from getaddrinfo */
 struct sockaddr *sarecv; /* sockaddr{} for receiving */
 socklen_t salen; /* length of sockaddr{}s */
 int  icmpproto; /* IPPROTO_xxx value for ICMP */
} *pr;


/*Self-defined*/

/*Constants*/
#define bool int
const int TRUE = 1;
const int FALSE = 0;

/*Constant Parameters*/
#define SNAPSHOT "s20180702"
#define FLOOD_INTERVAL 0.01

/*ping option*/
int opt = 0;
#define	OPTION_AUDIBLE		0x0001
#define	OPTION_BROADCAST	0x0002
#define	OPTION_STRICTSOURCE	0x0004
#define	OPTION_SO_DEBUG		0x0008
#define	OPTION_PTIMEOFDAY	0x0010
#define	OPTION_FLOOD		0x0020
#define	OPTION_INTERVAL		0x0040
#define	OPTION_NUMERIC		0x0080
#define	OPTION_FILLED		0x0100
#define	OPTION_QUIET		0x0200
#define	OPTION_DIRECTROUTE	0x0400
#define	OPTION_PROUTE		0x0800
#define	OPTION_LOOPBACK		0x1000
#define	OPTION_TIMESTAMP	0x2000
#define	OPTION_FULLLATENCY	0x4000
#define	OPTION_VERBOSE		0x8000

/*ping With-No-Parameter*/
int route_option = 0;
int timestamp_type = 0;

/*ping With-Parameters*/
int count = 4096;//[-c count] (time)
double interval = 1.0;//[-i interval] (s)
unsigned char pattern = 0xff;//[-p pattern] (hex)
int tos = 0;//[-Q tos] (degree)
int sndbuf = BUFSIZE;//[-S sndbuf] (byte)
int packetsize = 56;//[-s packetsize] (byte)
int ttl = 64;//[-t ttl](time)
int timeout = 65535;//[-W timeout] (ms)
double deadline = 65535;//[-w deadline] (ms)

/*ping statistics*/
struct timeval tval_start;
struct timeval tval_end;
struct timeval tval_send;
struct timeval tval_recv;
int transmitted = 0;
int received = 0;
double loss = 0.0;
double totaltime = 0.0;
double timestamp = 0.0;

double rtt_list[BUFSIZE];
double min = 0.0;
double avg = 0.0;
double max = 0.0;
double mdev = 0.0;

/*Functions*/
void print_usage(void);
void proc_rtt(int);
void init_timer(double interval);
void init_sigaction(void);
int tolower(int c);
int htoi(char s[]);










