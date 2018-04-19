#define LIST "update.txt"

int update_tca(SSL *ssl)
{
    printf("You want to send update info to DCA\n");
    //sending update list to server
    FILE *fp = fopen( LIST,"r");
    struct stat st;
    stat(LIST,&st);
    int buff_size = st.st_size;
    char buffer[buff_size];
    if(fp!=NULL)
    {
        size_t fileread = fread(buffer,sizeof(char),buff_size,fp);
        if(ferror(fp))
            fprintf(stderr,"Error reading the file");
        else
            buffer[fileread++]='\0';
        fclose(fp);
    }
    SSL_write(ssl,buffer,strlen(buffer));
    puts(buffer);
    
    return 1;
}


