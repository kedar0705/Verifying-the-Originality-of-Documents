#include<stdio.h>
#include "sha256.h"
#include "sha256.c"

struct certChain{
    char cname[50];
    BYTE chash[32];
    struct  certChain *next;
};


struct node {
    unsigned int reg_no;
    struct certChain *link;
}certs[10];


BYTE tmpBuf[32];
BYTE buf[SHA256_BLOCK_SIZE];

FILE *fptr;



void sha256_call(const BYTE text[]) {
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx,text,strlen(text));
	sha256_final(&ctx, buf);
}

void createCertificate(unsigned int reg_no, char *certName, char * filename) {

    FILE *file = fopen(filename, "rb");

    if(!file) { printf("File Not Found!!!");
    exit(0); }

    const int bufSize = 32678;
    unsigned char *buffer = malloc(bufSize);
    int bytesRead = 0;

    while((bytesRead = fread(buffer, 1, bufSize, file)));

    sha256_call(buffer);

    addCertNode(reg_no, certName, buf);


}


   void addCertNode(unsigned int reg_no, char * certName, BYTE *tBuf) {
    struct certChain *certificate = (struct certChain *)malloc(sizeof(struct certChain));

    for(int i=0;i<strlen(certName); i++)
       certificate->cname[i]=certName[i];

    for(int i=0;i<32; i++)
           certificate->chash[i] = tBuf[i];
    certificate->next = certs[reg_no%100].link;
    certs[reg_no%100].link = (struct certChain *)certificate;

   }

void verifyCertificate(unsigned int reg_no, char * filename )
{

 FILE *file = fopen(filename, "rb");

    if(!file) { printf("File Not Found!!!");
    exit(0); }

    const int bufSize = 32678;
    unsigned char *buffer = malloc(bufSize);
    int bytesRead = 0;

    while((bytesRead = fread(buffer, 1, bufSize, file)));
    int valid = 1;
    sha256_call(buffer);
    struct certChain *trav = certs[reg_no%100].link;
    while(trav!=NULL)
    {
     valid = 1;
    for(int i=0;i<32; i++)
      {
            if(buf[i] != trav->chash[i])
            {
             valid = 0;
             break;
            }
      }
      trav = trav->next;
    }

    /*for(int i=0;i<32; i++)
     printf("%x", buf[i]);
        for(int i=0;i<32; i++)
     printf("%x", trav->chash[i]);
     */
    if(valid == 1)
     printf("This is Valid Certificate");
    else
     printf("This is invalid Certificate");




}

void registerUser(unsigned int reg_no){
    certs[reg_no%100].reg_no = reg_no;
    certs[reg_no%100].link = NULL;
}

void displayCertChain(unsigned int reg_no) {

   struct certChain *trav = certs[reg_no%100].link;
   printf("\nCertificates of RegNo: %u",reg_no);
    while(trav!=NULL)
    {
        printf("\nCertificate Name: %s",trav->cname);
        printf("\nCertificate Hash: ");
        for (int i=0; i<32; i++)
        printf("%x",trav->chash[i]);
        printf("\n");
        trav= trav->next;
    }

}
void main()
{
    BYTE tBuf[100];

    int option;
    unsigned int rNo;
    char optionIssue;
    char certName[50], certLocation[100];
     printf("This is the Linked List Implementation of Digital Certificate Verification System \n");
    do {


        printf("\n1. Register User \n2. addCertificate \n3. Verifier \n4..Display Certificates \n5. Exit  \n");
        scanf("%d",&option);

        switch (option) {

            case 1:
                        printf("\nEnter the Register No. of user:   ");
                        scanf("%u",&rNo);
                        registerUser(rNo);
                        break;
            case 2:
                            printf("\nEnter the Register No:  ");
                            scanf("%u",&rNo);
                            printf("\nEnter the Name of Certificate:   ");
                            scanf("%s", certName);
                            printf("\nEnter the Certificate Location or Path:  ");
                            scanf("%s", certLocation);
                            createCertificate(rNo, certName, certLocation);
                            break;
            case 3:
                            printf("\nEnter the Register No. of user:   ");
                            scanf("%u",&rNo);
                            printf("\nEnter the Certificate Location/Path:   ");
                            scanf("%s", certLocation);
                            verifyCertificate(rNo, certLocation);
                            break;
            case 4:
                        printf("\nEnter the Register No. of user:   ");
                        scanf("%u",&rNo);
                        displayCertChain(rNo);

            case 5: break;
    }

    }while(option<5);



}
