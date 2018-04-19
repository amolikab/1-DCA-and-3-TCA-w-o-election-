#define CSR "clientDreq.pem"
#define CERTIFICATE "clientDcert.pem"
#define CA_CERTIFICATE "ca_cert.pem"
#define CAFILE "rootcert.pem"
#define CERTFILE "clientD.pem"

int verify()
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






int reissue_tca (SSL *ssl)
{
    printf("You are in reissue fcn for the TCA\n");
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
    //system("openssl x509 -in Amolikacert1.pem -text");
    
    int z = verify();
    if(z==1)
    {
        printf("Verified\n");
        system("openssl x509 -in clientDcert.pem -text");
        snprintf(test,sizeof(test),"cat %s %s %s > %s ",CERTIFICATE, CA_CERTIFICATE, CAFILE, CERTFILE);    
        system(test); 
    }
    else
        printf("Not Verified\n");
        
    return 1;
    
}


