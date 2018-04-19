

#define LIST1 "list.txt"



char * update_index(int update,char *serial_to_update,char *informing_serial,struct client* list )
{
    //printf("check begin\n");
    struct client *client_to_update = get_client_from_serial(list,serial_to_update);
                                              // get the struct clientB using serialB
    struct client *informing_client = get_client_from_serial(list,informing_serial);
                                              // get the struct clientA using serial
    //print_list(list);
    //printf("check\n");
    int informing_trust = informing_client->trust;
    int trust_to_update = client_to_update->trust;
    printf("trust_to_update %d\n",trust_to_update);
    
    int old_trust = client_to_update->trust;
    int client_index = (0.8 * trust_to_update) + (0.2 * update) ;
    
    if (  (client_index <10) || (client_index > 95)  )
    {
        client_to_update->trust = old_trust;
        return NULL;
    }    
    else
    {
        client_to_update->trust = client_index;
        if(old_trust<25)
        {
            if(old_trust >= client_index)
                return NULL;
            else
            {
                if(client_index>25)
                {    
                    printf("reissue cert up to grp B\n");
                    client_to_update->trust = client_index + 5;
                    printf("old_trust : %d  client_index : %d client_to_update->trust: %d",old_trust,client_index,client_to_update->trust);
                    char *port = client_to_update->port;
                    puts(port);
                    char test[500]; 
                    snprintf(test,sizeof(test),"echo %s reissued %d old trust %d new trust >> reissued.txt", serial_to_update, old_trust, client_index );
                    system(test);
                    return port;
                }//reissue up to grp B
                else
                    return NULL;    
            }//new > old 
        
        }//old trust 0-25
        else if((old_trust>=25)&&(old_trust<=75))
        {
            if(old_trust >= client_index)
            {
                if(client_index <25)
                {
                    printf("reissue dwn to grp A \n");
                    char *port = client_to_update->port;
                    client_to_update->trust = client_index - 5;
                    printf("old_trust : %d  client_index : %d client_to_update->trust: %d",old_trust,client_index,client_to_update->trust);
                    puts(port);
                    char test[500]; 
                    snprintf(test,sizeof(test),"echo %s reissued >> reissued.txt", serial_to_update);
                    system(test);
                    return port;
                }//reissue dwn to grp A
                else
                    return NULL;
            }//old >= new
            else
            {
                if(client_index > 75)
                {
                    printf("reissue up to grp C \n");
                    char *port = client_to_update->port;
                    client_to_update->trust = client_index + 5;
                    printf("old_trust : %d  client_index : %d client_to_update->trust: %d",old_trust,client_index,client_to_update->trust);
                    puts(port);
                    char test[500]; 
                    snprintf(test,sizeof(test),"echo %s reissued >> reissued.txt", serial_to_update);
                    system(test);
                    return port;
                
                }//reissue up to grp C
                else
                    return NULL;
            }//old < new            
            
        }//old trust 25 - 75
        else
        {
            if(old_trust >= client_index)
            {
                if(client_index < 75)
                {
                    printf("reissue down to grp B\n");
                    char *port = client_to_update->port;
                    client_to_update->trust = client_index - 5;
                    printf("old_trust : %d  client_index : %d client_to_update->trust: %d",old_trust,client_index,client_to_update->trust);
                    puts(port);
                    char test[500]; 
                    snprintf(test,sizeof(test),"echo %s reissued >> reissued.txt", serial_to_update);
                    system(test);
                    return port;
                }//reissue dwn to grp B
                else
                    return NULL;
            }//old > new
            else
                return NULL; // old < new
        
        }// old trust 75 - 100
           
    /*if(old_trust<25)
    {
        if(client_index>25)
        {    
            printf("reissue\n");
            client_to_update->trust = client_index + 5;
            char *port = client_to_update->port;
            puts(port);
            char test[500]; 
            snprintf(test,sizeof(test),"echo %s reissued %d old trust %d new trust >> reissued.txt", serial_to_update, old_trust, client_index );
            system(test);
            return port;
        }
        else
            return NULL;
    }
    else if((old_trust>=26)&&(old_trust<75))
    {
        if((client_index<25)||(client_index>=75))
        {    printf("reissue\n");
            char *port = client_to_update->port;
            puts(port);
            char test[500]; 
            snprintf(test,sizeof(test),"echo %s reissued >> reissued.txt", serial_to_update);
            system(test);
            return port;
        } 
        else
            return NULL;         
    }
    else
    {
        if(client_index<75)
        {
            printf("reissue\n");
            char *port = client_to_update->port;
            puts(port);
            char test[500]; 
            snprintf(test,sizeof(test),"echo %s reissued >> reissued.txt", serial_to_update);
            system(test);
            return port;
        }
        else
            return NULL;
    }*/
    //printf("end\n");
    }
}
  


int update_dca(SSL *ssl, char *result[])
{
    //receive the file from client
    printf("Recieving the file from client\n");
    char buff[1000];
    int bytesread = SSL_read(ssl,buff,sizeof(buff));
    buff[bytesread] = 0;
    puts(buff);  
    //put the contents in a file
    FILE *fp1 = fopen(LIST1,"w+");
    fwrite(buff,sizeof(char),bytesread,fp1);
    fclose(fp1);
     
    FILE *fp = fopen(LIST1,"r");
    int update;
    char serial_to_update[200];
    char informing_serial[200];
    printf("informing_serial before \n");
    informing_serial[0] = '\0';
    puts(informing_serial);
    //get_serial_of_peer(ssl, informing_serial);
    get_serial_from_cert(ssl,informing_serial,"client_cert.pem");
    printf("informing_serial \n");
    puts(informing_serial);
    //printf("Check\n");
    
    char *x[NUM_CLIENTS];
    int j = 0,i = 0;
    
    while(1)
    {
        
        //printf("check in while\n");  
        fscanf(fp,"%s ",serial_to_update);       
        //printf("%s  ",serial_to_update);
        fscanf(fp,"%d ",&update);       
        //printf("%d  \n",update);
        x[i] = update_index(update,serial_to_update,informing_serial,p);     
        if (x[i] != NULL)
        {    
            result[j] = x[i];
            j++; 
        } 
        i++;
        if(feof(fp))
            break;
              
    }
    fclose(fp);
    print_list(p->next);


    return j;
    
}











