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
#define TRUE 1
#define FALSE 0
#define bool int
#define FLOOD_INTERVAL 0.01

void proc_rtt(int);
void init_timer(double interval);
void init_sigaction(void);
int tolower(int c);
int htoi(char s[]);

/*ping statistics*/
struct timeval tval_start;
struct timeval tval_end;
struct timeval tval_send;
struct timeval tval_recv;
int transmitted = 0;
int received = 0;
double loss = 0.0;
double totaltime = 0.0;

double rtt_list[BUFSIZE];
double min = 0.0;
double avg = 0.0;
double max = 0.0;
double mdev = 0.0;

/*ping With-No-Parameter*/
bool b_broadcast = FALSE;
bool b_debug = FALSE;
bool b_flood = FALSE;
bool b_loopback = FALSE;
bool b_nonhostname = FALSE;
bool b_quiet = FALSE;
bool b_direct_routing = FALSE;
bool b_verbose = FALSE;
bool b_full_latency = FALSE;

/*ping With-Parameters*/
int count = 4096;//[-c count] (time)
double interval = 1.0;//[-i interval] (s)
unsigned char pattern = 0x00;//[-p pattern] (hex)
int tos = 100;//[-Q tos] (degree)
int sndbuf = BUFSIZE;//[-S sndbuf] (byte)
int packetsize = 56;//[-s packetsize] (byte)
int ttl = 64;//[-t ttl](time)
int timeout = 65535;//[-W timeout] (ms)
double deadline = 65535;//[-w deadline] (ms)











