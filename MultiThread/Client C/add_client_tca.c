#define CSR "clientCreq.pem"
#define CERTIFICATE "clientCcert.pem"
#define CA_CERTIFICATE "ca_cert.pem"
#define CAFILE "rootcert.pem"
#define CADIR NULL
#define CERTFILE "clientC.pem"


int verify_add()
{
    //struct stat st1;
    //verify signed cert
    char test[100]; 
    snprintf(test,sizeof(test),"openssl x509 -in %s -pubkey -noout -outform pem | sha256sum > verifycert",CERTIFICATE);
    system(test);
    memset(&test[0],0,sizeof(test));
    snprintf(test,sizeof(test),"openssl req -in %s -pubkey -noout -outform pem | sha256sum > verifycsr",CSR);    
    system(test);
    memset(&test[0],0,sizeof(test));
    
    struct stat st1;
    FILE *fp2 = fopen("verifycert","r");
    stat(CSR,&st1);
    int buff_size = st1.st_size;
    char verifycert[buff_size];
    if(fp2!=NULL)
    {
        size_t fileread = fread(verifycert,sizeof(char),buff_size,fp2);
        if(ferror(fp2))
            fprintf(stderr,"Error reading the file");
        else
            verifycert[fileread++]='\0';
        fclose(fp2);
    }  
    
    
    fp2 = fopen("verifycsr","r");
    stat(CSR,&st1);
    int buff_size1 = st1.st_size;
    char verifycsr[buff_size1];
    if(fp2!=NULL)
    {
        size_t fileread = fread(verifycsr,sizeof(char),buff_size1,fp2);
        if(ferror(fp2))
            fprintf(stderr,"Error reading the file");
        else
            verifycsr[fileread++]='\0';
        fclose(fp2);
    }   
    
    if(strcmp(verifycert,verifycsr) == 0)
    {
        
        return 1;
    }
    else
        return 0;

    
}



int issue_cert (SSL *ssl,char *port)
{
    int bytesread;
    char test[100];
    //send csr to the server
    struct stat st;
    FILE *fp = fopen(CSR,"r");
    stat(CSR,&st);
    int buff_size = st.st_size;
    char buff[buff_size];
    if(fp!=NULL)
    {
        size_t fileread = fread(buff,sizeof(char),buff_size,fp);
        if(ferror(fp))
            fprintf(stderr,"Error reading the file");
        else
            buff[fileread++]='\0';
        fclose(fp);
    }   
    SSL_write(ssl,buff,strlen(buff));
    //puts(buff);
       
    //receive signed cert from server
    printf("Recieving cert from server\n");
    char cert[5000];
    int certread;
    certread = SSL_read(ssl,cert,sizeof(cert));
    cert[certread] = 0;
    puts(cert);

    //Put cert in .pem file
    FILE *fp1 = fopen(CERTIFICATE,"w+");
    //char buffer[certread];
    fwrite(cert,sizeof(char),certread,fp1);
    fclose(fp1);
    
    //recieve server cert from server
    printf("Recieving server cert from server\n");
    char servcert[5000];
    certread = 0;
    certread = SSL_read(ssl,servcert,sizeof(servcert));
    servcert[certread] = 0;
    puts(servcert);

    //Put cert in .pem file
    fp1 = fopen(CA_CERTIFICATE,"w+");
    //char buffer[certread];
    fwrite(servcert,sizeof(char),certread,fp1);
    fclose(fp1);
    
    int z = verify_add();
    if(z==1)
    {
        printf("Verified\n");
        //changing the certfile to include the new CA cert
        snprintf(test,sizeof(test),"cat %s %s %s > %s ",CERTIFICATE, CA_CERTIFICATE, CAFILE, CERTFILE);    
        system(test); 
    }
    else
        printf("Not Verified\n");
    
    //send the port number that u are listening on
    puts(port);
    char msg[500] ; 
    strcpy(msg,port);   
    SSL_write(ssl,msg,strlen(msg));
    puts(msg);
    
    
    printf("check\n");
        
    return 1;
}




int add_client_tca (SSL *ssl, char* port)
{
    printf("requesting to add as new_client \n");
    int bytesread;
    //send CERTFILE to the server
    printf("sending certfile for client to check\n");
    struct stat st;
    FILE *fp = fopen(CERTFILE,"r");
    stat(CERTFILE,&st);
    int buff_size = st.st_size;
    char buff[buff_size];
    if(fp!=NULL)
    {
        size_t fileread = fread(buff,sizeof(char),buff_size,fp);
        if(ferror(fp))
            fprintf(stderr,"Error reading the file");
        else
            buff[fileread++]='\0';
        fclose(fp);
    }   
    SSL_write(ssl,buff,strlen(buff));
    //puts(buff);
    
    //read response from server
    bytesread=0;    
    printf("Recieving response from the server\n");
    char buffer[100];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    printf("bytesread : %d\n",bytesread);
    buffer[bytesread] = 0; 
    char response[]="ok";
    printf("recieved from server : ");
    puts(buffer);
    if(strncmp(buffer,response,bytesread)==0)
    {
        printf("Goto reissue fcn\n");
        issue_cert(ssl,port);          
    }
    else
        printf("rejected\n");
      
    return 0;
}


