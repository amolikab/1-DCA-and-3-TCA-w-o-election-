#define CLIENT_CSR "client_csr.pem"
#define CERTFILE "clientA.pem"
#define KEYFILE "clientAkey.pem"
#define CLIENT_CERT "client_cert.pem"

int reissue_dca(SSL *ssl)
{
    FILE *fp;
    int bytesread;
    //read csr from the client
    printf("Recieving from the client\n");
    char buffer[800];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    buffer[bytesread] = 0;        
    //Put csr in .pem file
    fp = fopen(CLIENT_CSR,"w+");
    fwrite(buffer,sizeof(char),bytesread,fp);
    fclose(fp);
    puts(buffer);
       
    //find the serial num
    char serial[500];
    get_serial_of_peer(ssl, serial);
    puts(serial);   
     
    
    //send signed cert to the client
    char test[500]; 
    snprintf(test,sizeof(test),"openssl x509 -req -in %s -passin pass:clientakey -sha1 -extfile myopenssl.cnf -extensions usr_cert_grpC -CA %s -CAkey %s -set_serial 0x%s -out %s",CLIENT_CSR,CERTFILE,KEYFILE,serial,CLIENT_CERT);
    system(test);
        
        
    struct stat st;
    FILE *fp1 = fopen(CLIENT_CERT,"r");
    stat(CLIENT_CERT,&st);
    int buff_size = st.st_size;
    char cert[buff_size];
    if(fp!=NULL)
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
    //system("openssl x509 -in Amolikacert.pem -text");

    printf("You are in the re-issue fcn\n");
    return 1;
}

