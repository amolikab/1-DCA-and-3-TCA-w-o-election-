//DCA Code

#include "common.c"
#include "add_client_dca.c"
#include "update_dca.c"
#include "reissue_dca.c"

#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define CAFILE "rootcert.pem"
#define CADIR NULL
#define CERTFILE "clientA.pem"
#define KEYFILE "clientAkey.pem"
#define MYPORT "6001"
#define PORT "7001"

struct client *p;
struct client *lastnode;
int serial_cert = 1;


SSL_CTX *setup_ctx(void)
{
    SSL_CTX *ctx;
    ctx = SSL_CTX_new(SSLv23_method());
    
    if(SSL_CTX_load_verify_locations(ctx,CAFILE,CADIR) != 1)
        int_error("Error loading CA file");
        
    if(SSL_CTX_set_default_verify_paths(ctx) != 1)
        int_error("Error loading default CA file");    
    
    if(SSL_CTX_use_certificate_chain_file(ctx,CERTFILE) != 1)
        int_error("Error loading certificate from file");
        
    if(SSL_CTX_use_PrivateKey_file(ctx,KEYFILE,SSL_FILETYPE_PEM) != 1)
        int_error("Error loading private key from file");
        
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
    
    SSL_CTX_set_verify_depth(ctx,4);
    SSL_CTX_set_options(ctx,SSL_OP_ALL|SSL_OP_NO_SSLv2);
    if(SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1)
        int_error("Error setting cipher list (no valid ciphers)");
    return ctx;
}


int do_client_loop (SSL *ssl,char *msg)
{
    int byteswritten,err,bytesread;
    
    //receive welcome from the server
    printf("Recieving from server\n");
    char buffer[500];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    buffer[bytesread] = 0;
    puts(buffer);
    
    //write ur choice
    //char msg[100]; 
    //scanf("%s",msg);
    SSL_write(ssl,msg,strlen(msg));
    char reissue[] = "1";
        
    if(strncmp(msg,reissue,strlen(msg))==0)
    {
        printf("You chose reissue fcn\n");
        reissue_dca(ssl);
    }
    else
        printf("Invalid choice\n");
       
    return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1:0;

}


void *client_thread(SSL_CTX *ctx, char * option, char *port)
{
    //SSL_CTX *ctx = (SSL_CTX *)arg;
    BIO *cbio;
    SSL *c_ssl;
    //char port[] = "7001";
    //printf("This is the client_thread\n");
    char x[] = ":";
    char *site = malloc(strlen(port)+strlen(SERVER)+strlen(x)+1);
    strcpy(site,SERVER);
    strcat(site,x);
    strcat(site,port);
    cbio = BIO_new_connect(site);   //7001
    if(!cbio)
        int_error("Error creating connection BIO for client ");
        
    if(BIO_do_connect(cbio) <= 0)
        int_error("Error connectiong to remote machine ");
    
    if(!(c_ssl = SSL_new(ctx)))
        int_error("Error creating SSL context for client");
            
    SSL_set_bio(c_ssl,cbio,cbio);
        
    //pthread_detach(pthread_self());
        
    if (SSL_connect(c_ssl) <= 0)
        int_error ("Error connecting SSL object");
    
    fprintf(stderr,"SSL Connection Opened \n");
        
    if(do_client_loop(c_ssl,option))
        SSL_shutdown(c_ssl);
    else
        SSL_clear(c_ssl);    
    
    fprintf(stderr,"SSL Connection Closed \n");
    
    SSL_free(c_ssl);
    
    ERR_remove_state(0);
    
}




void * client(void *arg)
{
    SSL_CTX *ctx = (SSL_CTX *)arg;
    client_thread(ctx,"1",PORT);
    /*sleep(5);
    client_thread(ctx,"1");
    sleep(5);
    client_thread(ctx,"2");
    sleep(5);
    client_thread(ctx,"3");
    for(int i = 0;i<2;i++)
    {
        sleep(3);
        client_thread(ctx,"2");        
        for(int j = 0;j<2;j++)
        {
            sleep(3);
            client_thread(ctx,"3");            
        }        
    } */       
}



int do_server_loop(SSL *ssl)
{
    
    int bytesread, err,x,byteswritten,bytesread1;  
    
    //write to client
    char msg[] = "Welcome to the Listening port of DCA!  Choose your option 1. New Client and want a certificate signed 2. Re-issue your cert  3. Update information of neighbours  4. Send Election Request ";     
    SSL_write(ssl,msg,strlen(msg));
    //puts(msg);
      
     //receive choice from the client
    printf("Recieving from client\n");
    char buff[100];
    bytesread1 = SSL_read(ssl,buff,sizeof(buff));
    buff[bytesread1] = 0;
    puts(buff);  
    char new_client[] = "1";
    char reissue[] = "2";
    char update[] = "3";    
    char election[] = "4";
    
    if(strncmp(buff,new_client,bytesread1)==0)
    {
        printf("TCA wants to add_new_client \n");
        add_client_dca(ssl);
    }
    else if(strncmp(buff,reissue,bytesread1)==0)
    {
        printf("Goto reissue fcn\n");
        reissue_dca(ssl);          
    }
    else if (strncmp(buff,update,bytesread1)==0)
    {
        printf("Goto update fcn\n");
        char * a[10] ;//list of all port numbers to reissue
        int x = update_dca(ssl,a);
        printf("the clients to reissue are:\n");
        if(x>0)
        {
            char *port;
            for(int i = 0;i<x;i++)
            {    
                port = a[i];
                puts(port);
                SSL_CTX *ctx = setup_ctx();
                client_thread(ctx,"1",port);
                 
            }       
            /*
            for(int i = 0;i<x;i++)
            {
                printf("%s\n", a[i]);
            }*/    
        }       
    }
     
    else if (strncmp(buff,election,bytesread1)==0)
    {
        printf("Goto election_req fcn\n");
        //listen_election_req(ssl);
    }    
    else
        printf("choose better\n");
        
    
    return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1:0;

}

void *server_thread(void *arg)
{
    pthread_mutex_lock(&lock);
    
    SSL *s_ssl = (SSL *)arg;
    
    if (SSL_accept(s_ssl) <= 0)
        int_error ("Error accepting SSL connection");
    
    fprintf(stderr,"SSL Connection Opened \n");
        
    if(do_server_loop(s_ssl))
        SSL_shutdown(s_ssl);
    else
        SSL_clear(s_ssl);    
    
    fprintf(stderr,"SSL Connection Closed \n");
    
    SSL_free(s_ssl);
    ERR_remove_state(0);
    
    pthread_mutex_unlock(&lock);
}


void *server(void *arg)
{
    BIO *client,*sbio;
    SSL_CTX *ctx = (SSL_CTX *)arg;
    THREAD_TYPE nodes[NUM_CLIENTS];
    
    SSL *s_ssl;
    int i =0;
    
    //printf("This is the server_thread\n");
    
    //MUTEX
    if (pthread_mutex_init(&lock, NULL) != 0)
    {
        printf("\n mutex init failed\n");
    }
    
    sbio = BIO_new_accept(MYPORT);  //6001
    if(!sbio)
        int_error("Error creating server socket");
        
    if(BIO_do_accept(sbio) <= 0)
        int_error("Error binding server socket");
    
    while(i<100)
    {
    if(BIO_do_accept(sbio) <= 0)
        int_error("Error accepting connection");
    
    client = BIO_pop(sbio);
        
    if(!(s_ssl = SSL_new(ctx)))
        int_error("Error creating SSL context for Server");
      
    SSL_set_bio(s_ssl,client,client);    
    
    //Server thread first
    printf("Creating the server_thread\n");   
    pthread_create(&(nodes[i]), NULL,&server_thread, s_ssl); 
    i++;
    }
    
    //make sure thread join the main thread after they are finished
    for(int j = 0; j<i; j++)
        pthread_join((nodes[j]),NULL);
    
    pthread_mutex_destroy(&lock);
}




int main(int argc,char *argv[])
{
    struct client list;
    p = &list;
    p->next = NULL;
    lastnode = p;
    printf("value of p is %p\n",p);
    printf("value of lastnode is %p\n",lastnode);

    SSL_CTX *ctx;
    THREAD_TYPE tid[10];    
    int i = 0;
    init_OpenSSL();  /// initializing the ssl config files
    //seed_prng();   implement for final program refer pg 114 for use
    ctx = setup_ctx();
    
    //Server thread first
    printf("Creating the server_thread\n");   
    pthread_create(&(tid[i]), NULL,&server, ctx); 
    i++;
    /*
    char c;
    printf("Is the server connected?\n");
    scanf("%c",&c);  
    if( c == 'y')
    {
    //Client thread
        //printf("Creating the client_thread\n");
        pthread_create(&(tid[i]), NULL,&client, ctx);
        i++;
     }  */ 
    //make sure thread join the main thread after they are finished
    for(int j = 0; j<i; j++)
        pthread_join((tid[j]),NULL);
    
    SSL_CTX_free(ctx);

    struct client* curr;
    struct client* s = p->next;
    while((curr = s)!= NULL)
    {
        s = s->next;
        free(curr);    
    }    
}


















