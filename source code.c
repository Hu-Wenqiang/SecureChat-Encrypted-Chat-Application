/* 

***************************
** S E C U R E   C H A T **
***************************

TCP IP based chat application with added RSA encryption and decryption scheme and Lucas Lehmer Primality test
Created by: Rahul Agrawal 

Department of Computer Science and Engineering- Class of 2013
National Institute of Technology Karnataka, Surathkal

IMPORTANT: read the file 'readme.txt' in the parent folder before executing this code

*/

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define PHI(p,q) (p-1)*(q-1)
#define MSG_SIZE 80
#define MAX_CLIENTS 10

int cnt=1;
int pid=-1;
struct protoent *proto=NULL;

///////////////////////////////ENTER RSA FUNCTIONS/////////////////////////

int phi,M,n,e,d,C,e1,n1;
FILE *fp;

/*
Function to check if : a^h = 1 mod p; if h|(p-1)
*/
int checkPoint1(unsigned long int a, unsigned long int p)
{
	unsigned long int i, x=1,h,j;
	for(i=2; i<(p-1); i++)
    	{
           	if((p-1)%i==0)
           	{
                     h=i; x=1;
                     for(j=1;j<=h;j++)
                     {
                                x=(x*a)%p;
                     }
           	}
           	if( x==1) break;
           	else continue;
    	}
    	if(x==1) return 0;
    	else return 1;
}
    
/*
Function to check if : gcd(d, phi)=1
*/
int checkPoint2()
{
	int i, FLAG;
	for(i=3;(i<phi) && (d%i==0) && (phi%i==0);i+2)
	{
      		FLAG = 1;
      		printf("\ngcd(d, PHI(n))!=1 .. Re-enter d.."); 
      		return FLAG;
	}
	FLAG = 0;
	return FLAG;
}


int lucas(unsigned long int p)
{
    	unsigned long int x=1, j, i;
    	int y=0;
    	for(i=2; i<=p-1; i++)
    	{
           	x=1;
           	// calculate: x^(p-1) mod p
           	for(j=1;j<=p-1;j++)
           	{
                 	x=(x*i)%p;
           	}
           	if(x==1) 
           	{
                    	y=checkPoint1(i,p);
                    	if(y==1) 
				break;
           	}
           	else continue;
         }
    	if(y==1) return 1; // For Prime
    	else return 0;     // Not Prime
}


/*
Encrypt using: C=M^e (mod n)
*/
int encrypt(int msgWord, unsigned long int n)
{
	int i;
	C = 1;
	for(i=0;i< e1;i++)
	{  
	        C=(C*msgWord)%n;
           	fprintf(fp,"i= %d, C= %d\n",i+1,C);
	}
	C = C%n;
	//printf("\nEncrypted keyword : %d",C);
	return C;
}

/*
Decrypt using: M= C^d (mod n)
*/
int decrypt(int cipherWord, unsigned long int n )
{
	int i;
	M = 1;
	for(i=0;i< d;i++)
	{
           	M=(M*(cipherWord))%n;
           	fprintf(fp,"i= %d, M= %d\n",i+1,M);
	}
	M = M%n;
	//printf("\n\tDecrypted keyword : %d",M);
	return M;
}


/*
Function to map character plain-text into numbers
*/
int mapChartoInt(char pt)
{
    	int i=0;
    	if(pt>='A' && pt <= 'Z')
         	i= pt -64;
    	else if(pt>='a' && pt <='z')
         	i= pt -96;
    	return i;
}

/*
Function to map numbered cipher-text into character value
*/
char mapInttoChar(int ct)
{
    	int i=0;
    	if(ct>=1 && ct <=26)
    	{
		i= ct+96;
	        return (char)i;
    	}
    	else 
    	{     
          	i= 0;
          	return (char)(32);
    	}
}

///////////////////////////////END RSA FUNCTIONS///////////////////////////

void exitClient(int fd, fd_set *readfds, char fd_array[], int *num_clients)
{
	int i;
	close(fd);
    	FD_CLR(fd, readfds);
    	for (i = 0; i < (*num_clients) - 1; i++)
        	if (fd_array[i] == fd)
            		break;
    	for (; i < (*num_clients) - 1; i++)
        	(fd_array[i]) = (fd_array[i + 1]);
    	(*num_clients)--;
}

////////////////////////////MAIN BELOW////////////////////////////////////// 

int main(int argc, char *argv[])
{

   	struct hostent *hname;
   	struct sockaddr_in addr;

   	int i=0,ch,port,num_clients=0,fd, j=0;
   	int server_sockfd, client_sockfd;
   	struct sockaddr_in server_address;
   	int addresslen = sizeof(struct sockaddr_in);
   	char fd_array[MAX_CLIENTS];
   	fd_set readfds, testfds, clientfds;
   	char msg[MSG_SIZE + 1];
   	char kb_msg[MSG_SIZE + 10];
	unsigned long int msgi[MSG_SIZE+1],kb_msgi[MSG_SIZE+10]; // Sending values as numbers instead of characters
   	int sockfd;
   	int result;
   	char hostname[MSG_SIZE];
   	struct hostent *hostinfo;
   	struct sockaddr_in address;
   	char alias[MSG_SIZE];
   	int clientid;
   	char ip[100];
	unsigned long int p, q, n;
	int checkP=0, checkQ=0, FLAG=0, s;
	int try,cipheri[100];


	printf("Enter a choice:\n\t1.ENCRYPTED CHAT CLIENT\n\t2.ENCRYPTED CHAT SERVER\n\t3.QUIT\n");
	scanf("%d",&ch);

	if(ch==3)
	{	
		printf("Shutting Down !!");
		exit(0);
	}
        else if(ch==1) // CLIENT SIDE CODE
	{
         	printf("Enter port no.\n");
         	scanf("%d",&port);
         	printf("Enter IP address of server\n");
	 	scanf("%s",ip);
      		strcpy(hostname,ip);

     		printf("\nNOTE: Client program starting\n");
     		fflush(stdout);
		printf("\nEnter a prime number 'p'\t ");
		while (1)
		{
      			scanf("%ld",&p);
      			checkP= lucas(p);
      			if(checkP!=1) 
      			{
           			printf("\nWarning: Not a prime number. Re-enter 'p'..\n");
      			}
      			else break;
		}

		printf("\nEnter a second prime number 'q'\t ");
		while (1)
		{
      			scanf("%ld",&q);
      			checkQ= lucas(q);
      			if(checkQ!=1) 
      			{
           			printf("\nWarning: Not a prime number. Re-enter 'q'..\n");
      			}
  	    		else break;
		}

		n = p*q;

		phi= PHI(p,q);

		printf("\nPHI(n) = %d \n",phi);

		do
		{
      			printf("\nEnter d such that gcd (d, PHI(n)) =1\t ");
      			scanf("%d",&d);
      			FLAG= checkPoint2();
		}	while(FLAG==1);

		e = 1;
		do
		{
      			s = (d*e)%phi;
      			e++;
		}while(s!=1);
		e = e-1;

		printf("\nPublic Key  (e,n) = (%d,%ld)",e,n);
		printf("\nPrivate Key (d,n) = (%d,%ld)",d,n);
		printf("\nEnter Public Key of Server (e1,n1)\n"); // This can be made available by a Key exchange algorithm
		scanf("%d %d",&e1,&n1);

		printf("\nSTARTING CHAT -- enter quit to stop client process \n");
		

     		sockfd = socket(AF_INET, SOCK_STREAM, 0);

     		hostinfo = gethostbyname(hostname);
     		address.sin_addr = *(struct in_addr *)*hostinfo -> h_addr_list;
     		address.sin_family = AF_INET;
     		address.sin_port = htons(port);

     		if(connect(sockfd, (struct sockaddr *)&address, sizeof(address)) < 0)  // connect to the server
		{
       			perror("connecting");
       			exit(1);
     		}

     	fflush(stdout);
	printf("CHECK 1: client \n");

     	FD_ZERO(&clientfds);
     	FD_SET(sockfd,&clientfds);
     	FD_SET(0,&clientfds);
	
	int k,ct,pt;
	fp=fopen("encryption_logs_client.txt","w");

     	while (1) // infinite loop
	{
       		testfds=clientfds;
       		select(FD_SETSIZE,&testfds,NULL,NULL,NULL);

       		for(fd=0;fd<FD_SETSIZE;fd++)
		{
          		if(FD_ISSET(fd,&testfds)){
             		if(fd==sockfd)
			{
				fflush(stdout);

				bzero(&cipheri,sizeof(int)*100);
				result = read(sockfd, &cipheri, sizeof(int)*100);	//read message from socket in a loop
				printf("\nCipher-Text Received:\t");
				for(k=0;cipheri[k]!=-1;k++)
       					printf(" %d ", (int)cipheri[k]);	
				printf("\n");
				
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
				//DECRYPT HERE THE MESSAGE IN cipheri BUFFER
				for(k=0;cipheri[k]!=-1;k++)
				{
				      //C=mapChartoInt(cipher[k]);
				      C=cipheri[k];
				      if(C!=0)
				      {
				      	pt=decrypt(C,n);
				      	printf("k= %d, pt= %d\n",k,pt);
				      	msg[k]= mapInttoChar(pt);
				      }
				      else
				      {
					printf(" ");
					msg[k]= 32; //space
				      }
				}
				msg[k]='\0';
				
				// Display Plain Text and Cipher Text
				printf("Cipher Text : ");
				for(k=0;cipheri[k]!=-1;k++)
				{
				      printf("%d ",cipheri[k]);
				}
				printf("\n");
				printf("Server : %s \n",  msg);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////

                		if (msg[0] == 'x' || msg[0]==(int)('x'))	//If Server has shut down
				{
					printf("\nServer Shut Down !!\n");
					//fclose(fp);                    			
					close(sockfd);
    			                exit(0);
                		}
             		}
             		else if(fd == 0) //Client writes here
			{
 		           	fgets(kb_msg, MSG_SIZE+1, stdin); //get message from user to send to server
                                if (strcmp(kb_msg, "quit\n")==0)  // If client wants to quit
				{
					printf("\nClient Shutting down !!\n");                    			
					bzero(&msg,sizeof(char)*(MSG_SIZE+1));  	                                
					sprintf(msg, "x%s", kb_msg);
					bzero(&cipheri,sizeof(int)*100);
					//ENCRYPT HERE USING SERVER'S PUBLIC KEY
					for(k=0;msg[k]!='\0';k++)
					{
      						M=mapChartoInt(msg[k]);
						if(M!=32)
      						{      
      							ct=encrypt(M,n1); 
							cipheri[k]= ct;
      						}
      						else if(M=32)
							cipheri[k]=0;
					}
					cipheri[k]= -1;
                   	 		write(sockfd, &cipheri, 100*sizeof(int)); //write cipheri[k] inside loop
					printf("\nShutting Client !!\n");
					fclose(fp);	
                    			close(sockfd);
                    			exit(0);
                		}
                		else
				{
					bzero(&msg,sizeof(char)*(MSG_SIZE+1));  	                                
					sprintf(msg, "%s", kb_msg);
					bzero(&cipheri,sizeof(int)*100);
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
					//ENCRYPT HERE USING SERVER'S PUBLIC KEY
					printf("\nSTARTING ENCRYPTION\n");
					printf("Message is : %s", msg);
					
					for(k=0;msg[k]!='\0';k++)
					{
      						M=mapChartoInt(msg[k]);
						printf("m %d = %d, ",k,M);
      						if(M!=32)
      						{      
      							ct=encrypt(M,n1); 
							printf("ct %d = %d\n",k,ct);
      							cipheri[k]= ct;
      						}
      						else if(M=32)
							cipheri[k]=0;
					}
					cipheri[k]= -1;
					printf("\nCipher Text :  ");
					for(k=0;cipheri[k]!=-1;k++)
					{
      						printf("%d ",cipheri[k]);
					}
					printf("\n");
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
                   	 		write(sockfd, &cipheri, 100*sizeof(int)); //write cipheri[k] inside loop
                		}
             		}
          	}
       	}
 	}
   	}

   	else		//SERVER SIDE CODE
	{
       		printf("Enter port no.\n");
       		scanf("%d",&port);
            	printf("\nNOTE : Server program starting\n");
     		fflush(stdout);

		printf("\nEnter a prime number 'p'\t ");
		while (1)
		{
      			scanf("%ld",&p);
      			checkP= lucas(p);
      			if(checkP!=1) 
      			{
           			printf("\nWarning: Not a prime number. Re-enter 'p'..\n");
      			}
      			else break;
		}

		printf("\nEnter a second prime number 'q'\t ");
		while (1)
		{
      			scanf("%ld",&q);
      			checkQ= lucas(q);
      			if(checkQ!=1) 
      			{
           			printf("\nWarning: Not a prime number. Re-enter 'q'..\n");
      			}
  	    		else break;
		}

		n = p*q;

		phi= PHI(p,q);

		printf("\nPHI(n) = %d \n",phi);

		do
		{
      			printf("\nEnter d such that gcd (d, PHI(n)) =1\t ");
      			scanf("%d",&d);
      			FLAG= checkPoint2();
		}     while(FLAG==1);

		e = 1;
		do
		{
      			s = (d*e)%phi;
      			e++;
		}while(s!=1);
		e = e-1;

		printf("\nPublic Key  (e,n) = (%d,%ld)",e,n);
		printf("\nPrivate Key (d,n) = (%d,%ld)",d,n);
		printf("\nEnter Public Key of Client (e1,n1)\n");
		scanf("%d %d",&e1,&n1);

		printf("\nSTARTING CHAT - Enter quit to stop the server process \n");

     		server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
     		server_address.sin_family = AF_INET;
     		server_address.sin_addr.s_addr = htonl(INADDR_ANY);
     		server_address.sin_port = htons(port);
     		bind(server_sockfd, (struct sockaddr *)&server_address, addresslen);

     		listen(server_sockfd, 1);
     		FD_ZERO(&readfds);
     		FD_SET(server_sockfd, &readfds);
     		FD_SET(0, &readfds);
		
		int k,ct,pt;
		fp=fopen("encryption_logs_server.txt","w");

     		while (1)
		{
        		testfds = readfds;
        		select(FD_SETSIZE, &testfds, NULL, NULL, NULL);
         		for (fd = 0; fd < FD_SETSIZE; fd++)
			{
           			if (FD_ISSET(fd, &testfds))
				{
              				if (fd == server_sockfd)
					{
                 				client_sockfd = accept(server_sockfd, NULL, NULL);

                 				if (num_clients < MAX_CLIENTS)
						{
				               		FD_SET(client_sockfd, &readfds);
                    					fd_array[num_clients]=client_sockfd;
							int temp=num_clients+1;
                    					printf("Client %d joined chat\n",temp);
							num_clients++;
                    					fflush(stdout);
							printf("Check 1: Server\n");

                    					//sprintf(msg,"MClient id = %2d \n",client_sockfd-3);
							//msgi[0]=77;//msgi[1]=46;msgi[2]=1;msgi[3]=50;msgi[4]=21;msgi[5]=12; //encrypted message for test
							//bzero(&try,sizeof(try));							
							//try=50;
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
							//ENCRYPT HERE USING CLIENTS PUBLIC KEY
///////////////////////////////////////////////////////////////////////////////////////////////////////////////                    					
							//send(client_sockfd,&try,sizeof(try),0);
                 				}
                 				else
						{
							printf("New Client trying to bind. No free ports for new client\n");
                    					//sprintf(msg, "XNo Free Ports.\n");
                    					//write(client_sockfd, msg, strlen(msg));
                    					close(client_sockfd);
                 				}
              				}
              				else if (fd == 0)
					{
                 				fgets(kb_msg, MSG_SIZE + 1, stdin);

                 				if (strcmp(kb_msg, "quit\n")==0) // If Server wants to quit
						{
                    					printf("Server Shutting Down !!");
							sprintf(msg, "x%s",kb_msg);
							for(k=0;msg[k]!='\0';k++)
							{
      								M=mapChartoInt(msg[k]);
								if(M!=32)
      								{      
      									ct=encrypt(M,n1); 
									cipheri[k]= ct;
      								}
      								else if(M=32)
								cipheri[k]=0;
							}
							cipheri[k]= -1;
							
							for (i = 0; i < num_clients ; i++) // Write message to all the clients
 	                      				{
								write(fd_array[i], &cipheri, 100*sizeof(int)); //write cipheri[k] inside loop
							}                    					
							/*for (i = 0; i < num_clients ; i++)
							{
                       						write(fd_array[i], msg, strlen(msg));
                       						close(fd_array[i]);
                    					}*/
							fclose(fp);                    					
							close(server_sockfd);
                    					exit(0);
                 				}
                 				else
						{
                    					sprintf(msg, "%s", kb_msg);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
							//ENCRYPT HERE WITH CLIENTS PUBLIC KEY
							printf("\nSTARTING ENCRYPTION\n");
							printf("MESSAGE IS : %s", msg);
							for(k=0;msg[k]!='\0';k++)
							{
      								M=mapChartoInt(msg[k]);
								printf("m %d = %d, ",k,M);
      								if(M!=32)
      								{      
      									ct=encrypt(M,n1); 
									printf("ct %d = %d\n",k,ct);
      									cipheri[k]= ct;
      								}
      								else if(M=32)
								cipheri[k]=0;
							}
							cipheri[k]= -1;
							printf("\nCipher Text :  ");
							for(k=0;cipheri[k]!=-1;k++)
							{
      								printf("%d ",cipheri[k]);
							}
							printf("\n");
							
///////////////////////////////////////////////////////////////////////////////// //////////////////////////////
							for (i = 0; i < num_clients ; i++) // Write message to all the clients
 	                      				{
								write(fd_array[i], &cipheri, 100*sizeof(int)); //write cipheri[k] inside loop
							}
                 				}
              				}
              				else if(fd)
					{
                 				fflush(stdout);

						bzero(&cipheri,sizeof(int)*100);
						result = read(fd, &cipheri, sizeof(int)*100);	//read message from socket fd
						printf("\ncipher text received:\t");
						for(k=0; cipheri[k]!=-1; k++)
       							printf(" %d ", (int)cipheri[k] );	
						printf("\n");
						//exit(0);
						
						if(result==-1) perror("read()");
                 				else if(result>0)
						{
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
							//DECRYPT HERE USING SERVER'S PRIVATE KEY
							for(k=0;cipheri[k]!=-1;k++)
							{
							      C=cipheri[k];
							      if(C!=0)
							      {
								      	pt=decrypt(C,n);
								      	printf("k= %d, pt= %d\n",k,pt);
								      	msg[k]= mapInttoChar(pt);
							      }
							      else
							      {
									printf(" ");
									msg[k]= 32; //space
							      }
							}
							msg[k]='\0';
			
							// Display Plain Text and Cipher Text
							printf("\n");
							printf("Client %d: %s \n",fd-3,  msg);
	
///////////////////////////////////////////////////////////////////////////////////////////////////////////////

                 					for(i=0;i<num_clients;i++)
							{
                       						//if (fd_array[i] != fd) 	write(fd_array[i],kb_msg,strlen(kb_msg));
                    					}

                    					if(msg[0] == 'x'||msgi[0]==(int)('x'))
							{
                       						exitClient(fd,&readfds, fd_array,&num_clients);
                    					}
                 				}
              				}
              				else
					{
                 				exitClient(fd,&readfds, fd_array,&num_clients);
              				}
           			}
        		}
     		}
  	}
}

////////////////////////////////////////END MAIN//////////////////////////////////////////////////////////////////

