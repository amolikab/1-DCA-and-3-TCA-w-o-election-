#define CERTFILE "clientA.pem"
#define KEYFILE "clientAkey.pem"
#define CLIENT_CSR "client_csr.pem"
#define CLIENT_CERT "client_cert.pem"
#define CERT_CHAIN "cert_chain.pem"
#define CERTIFICATE "clientAcert.pem"

int verify_TCA(void)
{
    //extract TCA cert to check the trust index
    FILE *fp,*fp_tca;
    int i = 0,j=0;
    fp = fopen(CERT_CHAIN,"r");
    char line[256];
    while(fgets(line,sizeof(line),fp))
    {
        if(line[0] == '-')
            i++;
    } 
    fclose(fp);
    fp_tca = fopen("TCA_cert.pem","w+");
    fp = fopen(CERT_CHAIN,"r");
    while(fgets(line,sizeof(line),fp))
    {
        if(line[0] == '-')
            j++;
        if( (j>2)    &&  (j<=4)  )    
            fprintf(fp_tca,"%s",line);         
    } 
    fclose(fp);
    fclose(fp_tca);
    
    char *nid;
    nid = pem_certificate_parse("TCA_cert.pem");
    char x[50];
    strcpy(x,nid);
    printf("nid : %s\n",x);    
    //system("openssl x509 -in TCA_cert.pem -text");
    char a[50] = "..200";
    char b[50] = "..300";
    char c[50] = "..100";
    size_t len = strlen(x) -1; 
    printf("len : %ld\n",len);     
    if ((strncmp(x,a,len)==0 ) || ((strncmp(x,b,len)) ==0) )
        return 1; 
    else if (strncmp(x,c,len) == 0)
        return 0;    
    else
        return -1;  
    
}   



int issue_cert(SSL *ssl, char *port)
{
    FILE *fp;
    int bytesread, bytesread1;
    //read csr from the client
    printf("Recieving csr from the client\n");
    char buffer[800];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    buffer[bytesread] = 0;        
    //Put csr in .pem file
    fp = fopen(CLIENT_CSR,"w+");
    fwrite(buffer,sizeof(char),bytesread,fp);
    fclose(fp);
    puts(buffer);
        
    //send signed cert to the client
    char test[500]; 
    snprintf(test,sizeof(test),"openssl x509 -req -in %s -passin pass:clientakey -sha1 -extfile myopenssl.cnf -extensions usr_cert_grpB -CA %s -CAkey %s -CAcreateserial -out %s",CLIENT_CSR,CERTFILE,KEYFILE,CLIENT_CERT);
    system(test);
        
    printf("sending signed cert to client\n");    
    struct stat st;
    FILE *fp1 = fopen(CLIENT_CERT,"r");
    stat(CLIENT_CERT,&st);
    int buff_size = st.st_size;
    char cert[buff_size];
    if(fp1!=NULL)
    {
        size_t fileread = fread(cert,sizeof(char),buff_size,fp1);
        if(ferror(fp1))
            fprintf(stderr,"Error reading the file");
        else
            cert[fileread++]='\0';
        fclose(fp1);
    }
    
    SSL_write(ssl,cert,buff_size);
    
    //puts(cert);
    
    //sending own cert to client
    
    FILE *fp2 = fopen(CERTIFICATE,"r");
    stat(CERTIFICATE,&st);
    int buff_size1 = st.st_size;
    char selfcert[buff_size1];
    if(fp2!=NULL)
    {
        size_t fileread1 = fread(selfcert,sizeof(char),buff_size1,fp2);
        if(ferror(fp2))
            fprintf(stderr,"Error reading the file");
        else
            selfcert[fileread1++]='\0';
        fclose(fp2);
    }
    
    SSL_write(ssl,selfcert,buff_size1);
    //puts(selfcert);
    
    //get the port number of the client
    
    printf("Recieving port num from client\n");
    char port1[500];
    bytesread1 = SSL_read(ssl,port1,sizeof(port1));
    port1[bytesread1] = 0;
    puts(port1); 
    strcpy(port,port1);
    puts(port);
    printf("check\n"); 
       
    return 1;
}



int add_client_dca(SSL *ssl)
{
    FILE *fp;
    int bytesread;
    //read cert chain from the client
    printf("Recieving CERTFILE from the client\n");
    char buffer[10000];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    buffer[bytesread] = 0;        
    //Put cert chain in .pem file
    fp = fopen(CERT_CHAIN,"w+");
    fwrite(buffer,sizeof(char),bytesread,fp);
    fclose(fp);
    //puts(buffer);
    int i = verify_TCA();
    printf("verify_TCA() id %d\n",i);
    if(i == 1)
    {
        printf("Trusted TCA, will sign and add as client\n");
        //respond to client
        char msg[] = "ok";    
        SSL_write(ssl,msg,strlen(msg));
        puts(msg);
        char port[500];
        issue_cert(ssl,port);
        char serial[100];
        get_serial_from_cert(ssl,serial,"client_cert.pem");
        
        //int x = 123;
        //char serial[100] = x + '0';
        struct client *clientA = addnode(lastnode,serial,200,port);
        //struct client *clientA = addnode(lastnode,"123",100, "7001");  
        //struct client *clientB = addnode(lastnode,"124",30, "7001");  
        //struct client *clientC = addnode(lastnode,"125",79,"7001");
        print_list(p->next);
               
    }
    else if(i == 0)
        printf("Cannot sign as TCA is not trusted enough\n");
    else
        printf("Invalid trust index\n");
    
    
    return 0;
}

