//TCA Code

#include "common.c"
#include "add_client_tca.c"
#include "update_tca.c"
#include "reissue_tca.c"

#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define CAFILE "rootcert.pem"
#define CADIR NULL
#define CERTFILE "clientC.pem"       //////////
#define KEYFILE "clientCkey.pem"        ///////////
#define MYPORT "7001"
#define PORT "6001"

struct client *lastnode;

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


int do_server_loop(SSL *ssl)
{
    int bytesread, err,x,byteswritten,bytesread1;  
    
    //write to client
    char msg[] = "Welcome to the Listening port of the TCA!  Choose your option 1. Re-issue my cert ";    
    SSL_write(ssl,msg,strlen(msg));
    //puts(msg);
      
    
    //receive choice from the client
    printf("Recieving from DCA\n");
    char buff[100];
    bytesread1 = SSL_read(ssl,buff,sizeof(buff));
    buff[bytesread1] = 0;
    puts(buff);  
    char reissue[] = "1";
    
     
    if(strncmp(buff,reissue,bytesread1)==0)
    {
        printf("DCA wants to reissue cert\n");
        reissue_tca(ssl);          
    }
    else
        printf("choose better\n");
       
    return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1:0;

}



void *server_thread(void *arg)
{
    BIO *client,*sbio;
    struct thread_arg *arguments = (struct thread_arg*)arg;
    SSL_CTX *ctx = arguments->ctx;
    char *port = arguments->port;
    //SSL_CTX *ctx = (SSL_CTX *)arg;
    //pthread_detach(pthread_self());
    SSL *s_ssl;
    int i =0;
    
    //printf("This is the server_thread\n");
    
    sbio = BIO_new_accept(port);  //7001
    if(!sbio)
        int_error("Error creating server socket");
        
    if(BIO_do_accept(sbio) <= 0)
        int_error("Error binding server socket");
     
     
    while(i<10)
    {
    printf("Creating the server_thread\n");
    if(BIO_do_accept(sbio) <= 0)
        int_error("Error accepting connection");
    
    client = BIO_pop(sbio);
        
    if(!(s_ssl = SSL_new(ctx)))
        int_error("Error creating SSL context for Server");
      
    SSL_set_bio(s_ssl,client,client);    
    
    
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
    i++;
    }
}


int do_client_loop (SSL *ssl,char *msg,char *port)
{
    int byteswritten,err,bytesread;
    
    //receive welcome from the server
    printf("Recieving from server\n");
    char buffer[500];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    buffer[bytesread] = 0;
    //puts(buffer);
    
    
    //write ur choice
    //char msg[100]; 
    //char c = option + '0';
    //char *msg = &c;
    //scanf("%s",msg);
    SSL_write(ssl,msg,strlen(msg));
    char new_client[] = "1";
    char reissue[] = "2";
    char update[] = "3";     
    
    if (strncmp(msg,new_client,strlen(msg))==0)
    {
        //printf("You chose new_client fcn\n");
        add_client_tca(ssl,port);
    } 
    else if(strncmp(msg,reissue,strlen(msg))==0)
    {
        printf("You send reissue request to the DCA\n");
        reissue_tca(ssl);
    }
    else if (strncmp(msg,update,strlen(msg))==0)
    {
        //printf("You chose update fcn\n");
        update_tca(ssl);
    }
    
    else
        printf("Invalid choice\n");
       
    return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1:0;

}


void *client_thread(SSL_CTX *ctx, char *option, char*port)
{
    //SSL_CTX *ctx = (SSL_CTX *)arg;
    BIO *cbio;
    SSL *c_ssl;
    
    //printf("This is the client_thread\n");
    
    cbio = BIO_new_connect( SERVER ":" PORT);   //6001
    if(!cbio)
        int_error("Error creating connection BIO for client ");
        
    if(BIO_do_connect(cbio) <= 0)
        int_error("Error connectiong to remote machine ");
    
    if(!(c_ssl = SSL_new(ctx)))
        int_error("Error creating SSL context for client");
            
    SSL_set_bio(c_ssl,cbio,cbio);
    
    if (SSL_connect(c_ssl) <= 0)
        int_error ("Error connecting SSL object");
    
    fprintf(stderr,"SSL Connection Opened \n");
        
    if(do_client_loop(c_ssl,option,port))
        SSL_shutdown(c_ssl);
    else
        SSL_clear(c_ssl);    
    
    fprintf(stderr,"SSL Connection Closed \n");
    
    SSL_free(c_ssl);    
    ERR_remove_state(0);
    
}


void * client(void *arg)
{
    struct thread_arg *arguments = (struct thread_arg*)arg;
    SSL_CTX *ctx = arguments->ctx;
    char *port = arguments->port;
    //SSL_CTX *ctx = (SSL_CTX *)arg;
    //sleep(5);
    client_thread(ctx,"1",port);
    sleep(10);
    
    for(int i = 0;i<30;i++)
    {
        client_thread(ctx,"3",port);
        sleep(5);
    }
    /*
    client_thread(ctx,"2",port);
    sleep(5);
    client_thread(ctx,"3",port);
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

int main(int argc,char *argv[])
{
    SSL_CTX *ctx;
    char *port = argv[1];
    THREAD_TYPE tid[10]; 
    struct thread_arg arg;   
    int i = 0;
    init_OpenSSL();  /// initializing the ssl config files
    //seed_prng();   implement for final program refer pg 114 for use
    ctx = setup_ctx();
    arg.ctx = ctx;
    arg.port = port;   
    //server thread create
    printf("Creating the server thread\n");
    pthread_create(&(tid[i]), NULL,&server_thread, &arg); 
    i++;
    
    char c;
    printf("Is the server connected?\n");
    scanf("%c",&c);  
    if( c == 'y')
    {
    //Client thread create
    printf("Creating the client_thread\n");   
    pthread_create(&(tid[i]), NULL,&client, &arg);
    i++;
    }
        
    //make sure thread join the main thread after they are finished
    for(int j = 0; j<i; j++)
        pthread_join((tid[j]),NULL);
    
    
    /*
    char c;    
    printf("Is the server connected?\n");
    scanf("%c",&c);  
    if( c == 'y')
    {
        while(i<3)
        {
        client_thread(ctx);
        sleep(5);
        i++;
        }
    }  */  
    SSL_CTX_free(ctx);   
    
    return 0;
}


















