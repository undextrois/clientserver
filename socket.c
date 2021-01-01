#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <windows.h>
#include <winsock.h>
#include <dir.h>
#include <conio.h>

#define BUFSZ (1024*2)
static char buffer[BUFSZ+1];
static char tbuffer[BUFSZ+1];

#define PORT 13177

static unsigned char digest_key[] =
{
    0xd3,0x2b,0x31,0x10,0xaf,0xc8,0xff,0x89,
    0x8e,0xe3,0x3d,0x7c,0x29,0xd3,0x63,0x00,
    0xb7,0x71,0x68,0xae,0xf1,0x15,0xc4,0x9d,
    0x0e,0x95,0x70,0x65,0xc7,0x4c,0xe4,0x1f,
    0x53,0x10,0x17,0x63,0x6b,0x39,0x81,0x48,
    0x46,0xa0,0x1b,0x67,0x9c,0x9c,0x5d,0xd7,
    0xa7,0x06,0x3e,0x30,0x1c,0x35,0x36,0x8c,
    0x36,0x02,0x3e,0x80,0xaa,0xc4,0xce,0x26,
    0xb3,0x54,0xdd,0x16,0x06,0x0a,0xe3,0x67,
    0xde,0xbd,0xd9,0xb1,0xf0,0xc5,0x36,0x0e,
    0x76,0xfb,0xf3,0x13,0x28,0xb6,0x88,0xda,
    0x3d,0xcf,0xec,0xfb,0x6e,0x9d,0x97,0x8d,
    0xf2,0xf9,0x82,0x29,0x82,0x3a,0x25,0xe6,
    0x55,0x39,0x77,0x5c,0x24,0x4e,0xf0,0xa4,
    0x26,0x4f,0x89,0x56,0x14,0x97,0xba,0x89,
    0x25,0xfc,0x7a,0xd6,0x12,0xd6,0x41,0x54,
    0x12,0xfe,0x08,0x9b,0xde,0xcb,0x46,0xc4,
    0xad,0x16,0xf4,0x67,0x38,0x36,0x8a,0x9b,
    0xb6,0x04,0xff,0xf9,0xe0,0xd8,0xcb,0x98,
    0xed,0x88,0xe7,0x10,0x96,0x6f,0xcb,0x7a,
    0x12,0x63,0x6e,0x6e,0x1a,0xbc,0x48,0x03,
    0xe5,0x53,0x52,0xd2,0x2b,0x7f,0x04,0xf2,
    0x26,0x19,0x55,0xfb,0x8b,0x78,0xbd,0x07,
    0x95,0x75,0x35,0xab,0xf9,0x67,0x35,0x01,
    0xf2,0x27,0xb4,0xa1,0x35,0x0d,0x2a,0xa2,
    0xfd,0xf0,0x90,0x9c,0xff,0x28,0x5d,0xa9,
    0x75,0x8e,0x8a,0x5e,0x17,0x79,0x8f,0xd5,
    0x1c,0xc2,0x63,0xa6,0x3d,0xc0,0x7e,0xe8,
    0xb1,0x4c,0xd9,0x34,0x31,0xbd,0xec,0xa1,
    0xf4,0xec,0xae,0xc7,0xb3,0x31,0x97,0xbf,
    0xa5,0x62,0xa0,0x21,0x83,0xda,0x41,0x04,
    0x84,0x6f,0x71,0x01,0x61,0x79,0xa8,0x2f
};

static unsigned char d_cert[BUFSZ+1];
static int d_cert_length = 0;

int dc_quit = 0;

int l,i;
int running = 0;
char server[80];
unsigned int addr;
unsigned char key;

WORD wVersionRequested;
WSADATA wsaData;
SOCKET sock;
struct sockaddr_in address;
struct hostent *host;

char **dc_get_args(char *cmdstr, int cmdstr_id);
void dc_parse_help(void);
void dc_parse_auth(char *cmdstr,int cmdstr_id);
void dc_parse_pass(char *cmdstr,int cmdstr_id);
void dc_parse_ls();
void dc_parse_put(char *cmdstr,int cmdstr_id);
void dc_parse_get(char *cmdstr,int cmdstr_id);
void dc_parse_quit();
void dc_parse_dir(void);
void dc_parse_clear(void);
int dc_getch(char *cmdstr);
int dc_parse(char *cmdstr);
int dc_prompt(void);
int dc_connect(char *dc_host);
void dc_send(char *cmd);
void dc_get_cert(void);
int dc_recv(char *buf);
void dc_send_en(char *cmd,int length);
int dc_recv_en(char *buf);

#define isvar(c) ((c) == '_' || (c) == '.' || (c) == '-')

char **dc_get_args(char *cmdstr, int cmdstr_id)
{
    char buf[80+1];
    char *args[10 + 1];
    int i_lng = 0, argi = 0;

    while ((*(cmdstr+cmdstr_id)) != NULL)
    {
            if (isspace(*(cmdstr+cmdstr_id)))
            {
                while (isspace(*(cmdstr+cmdstr_id)))
                      cmdstr_id++;
                continue;
            }

            if (isalnum(*(cmdstr+cmdstr_id)) || isvar(*(cmdstr+cmdstr_id)))
            {
                while (isalnum(*(cmdstr+cmdstr_id)) || isvar(*(cmdstr+cmdstr_id)))
                {
                      if (i_lng > 80) i_lng--;
                      buf[i_lng] = *(cmdstr+cmdstr_id);
                      i_lng++;
                      cmdstr_id++;
                }
                buf[i_lng] = NULL;
                if (argi > 10) break;
                args[argi] = strdup(buf);
                argi++;
            }
            else cmdstr_id++;
    }

    return args;
}

void dc_parse_help(void)
{
    char help_str[] =
    "DC Server Version 1.0\n\n"
    "PUT filename\n"
    "    Used for uploading file on a server.\n"
    "GET filename\n"
    "    Used for downloading file from the server.\n"
    "LS\n"
    "    List directory.\n"
    "QUIT\n"
    "    Quit this program.\n"
    "HELP\n"
    "    Displays this help text.\n";
    printf(help_str);
}

void dc_parse_auth(char *cmdstr,int cmdstr_id)
{
    char **argv;
    argv = dc_get_args(cmdstr,cmdstr_id);
    dc_send("AUTH");
}

void dc_parse_pass(char *cmdstr,int cmdstr_id)
{
    char **argv;
    argv = dc_get_args(cmdstr,cmdstr_id);
    dc_send("PASS");
}

void dc_parse_dir(void)
{
    struct ffblk t_fblk;
    int done, l;
    char tmpstr[14];

    printf("Local directory listing\n\n");
    done = findfirst("*.*",&t_fblk,FA_NORMAL|FA_RDONLY);
    while (!done)
    {
        l = 13 - strlen(t_fblk.ff_name);
        memset(tmpstr,0,sizeof(tmpstr));
        while (l--) strcat(tmpstr," ");

        printf("%s%s %10ld\n",t_fblk.ff_name,tmpstr,t_fblk.ff_fsize);
        done = findnext(&t_fblk);
    }
    printf("\n");
}

void dc_parse_ls(void)
{
    int l, i;
    char c;
    char tmpbuf[BUFSZ];
    char tmpstr[BUFSZ];
    printf("Remote directory listing\n\n");
    dc_send_en("LS",2);
    while (dc_recv_en(tmpbuf))
    {
        if (strcmp(tmpbuf,".")==0) { break; }
        printf("%s",tmpbuf);
    }
    printf("\n");
} 

void dc_parse_put(char *cmdstr,int cmdstr_id)
{
    char **argv;
    char buf[80];
    FILE *infp;
    int length;
    argv = dc_get_args(cmdstr,cmdstr_id);
    if (argv[0] == NULL)
    {
        printf("error: filename required!\n");
        return;
    }
    else
    {
        sprintf(buf,"PUT %s\n",argv[0]);
        if ((infp = fopen(argv[0],"r+b")) == NULL)
        {
            printf("error: unable to upload file!\n");
            return;
        }
        dc_send_en(buf,strlen(buf));
        while (!feof(infp))
        {
              memset(buf,0,sizeof(buf));
              length = fread(buf,1,sizeof(buf),infp);
              dc_send_en(buf,length);
        }
        fclose (infp);
        dc_send_en(".",1);       
    }
}

void dc_parse_get(char *cmdstr,int cmdstr_id)
{
    char **argv;
    char buf[80];
    int l;
    FILE *outfp;
    argv = dc_get_args(cmdstr,cmdstr_id);
    if (argv[0] == NULL)
    {
        printf("error: filename required!\n");
        return;
    }
    else
    {
        sprintf(buf,"GET %s\n",argv[0]);
        dc_send_en(buf,strlen(buf));

        if ((outfp = fopen(argv[0],"w+b")) == NULL)
        {
            printf("error: unable to get file!\n");
            return;
        }

        while ((l = dc_recv_en(buf)) > 0)
        {           
            fwrite(buf,1,l,outfp);
        }
        fclose (outfp);
    }
}

void dc_parse_clear(void)
{
    clrscr();
}

void dc_parse_quit()
{
    printf("you have successfully logged out.\n");
    dc_quit = 1;
}

int dc_getch(char *cmdstr)
{
    int cmdstr_id = 0, lng;
    char buf[80 + 1];
    while (*(cmdstr+cmdstr_id) != NULL)
    {
          if (isspace(*(cmdstr+cmdstr_id)))
          {
              while (isspace(*(cmdstr+cmdstr_id)))
                    cmdstr_id++;
              continue;
          }
          if (isalpha(*(cmdstr+cmdstr_id)))
          {
              lng = 0;
              while (isalpha(*(cmdstr+cmdstr_id)))
              {
                    if (lng > 80) lng--;
                    buf[lng] = *(cmdstr+cmdstr_id);
                    lng++;
                    cmdstr_id++;
              }
              buf[lng] = NULL;

              if (strcmp(buf,"AUTH") == 0)
              {
                  dc_parse_auth(cmdstr,cmdstr_id);
                  break;
              }
              else if (strcmp(buf,"PASS") == 0)
              {
                  dc_parse_pass(cmdstr,cmdstr_id);
                  break;
              }
              else if (strcmp(buf,"HELP") == 0 || strcmp(buf,"help") == 0)
              {
                  dc_parse_help();
                  break;
              }
              else if (strcmp(buf,"LS") == 0 || strcmp(buf,"ls") == 0)
              {
                  dc_parse_ls();
                  break;
              }
              else if (strcmp(buf,"DIR") == 0 || strcmp(buf,"dir") == 0)
              {
                  dc_parse_dir();
                  break;
              }
              else if (strcmp(buf,"CLEAR") == 0 || strcmp(buf,"clear") == 0)
              {
                  dc_parse_clear();
                  break;
              }
              else if (strcmp(buf,"PUT") == 0 || strcmp(buf,"put") == 0)
              {
                  dc_parse_put(cmdstr,cmdstr_id);
                  break;
              }
              else if (strcmp(buf,"GET") == 0 || strcmp(buf,"get") == 0)
              {
                  dc_parse_get(cmdstr,cmdstr_id);
                  break;     
              }
              else if (strcmp(buf,"QUIT") == 0 || strcmp(buf,"quit") == 0)
              {
                  dc_parse_quit();
                  break;
              }
              else
              {
                  printf("error: command not found\n");
                  break;
              }
          }
          else
          {
              printf("error: command not found\n");
              break;
          }
    }
    return 0;
}

int dc_parse(char *cmdstr)
{
    dc_getch(cmdstr);
    return 0;
}

int dc_prompt(void)
{
    char buf[256 + 1], c;
    int i_lng;
    while (!dc_quit)
    {
          memset(buf,0,sizeof(buf));
          printf("$ ");
          gets(buf);
          dc_parse(buf);
    }

    return 0;
}

int dc_connect(char *dc_host)
{
    wVersionRequested = MAKEWORD( 1, 1 );

    if (WSAStartup(wVersionRequested,&wsaData) != 0)
    {
      printf("error: unable to initialize winsock\n");
      exit (1);
    }

    if ((sock = socket(AF_INET,SOCK_STREAM,0)) == INVALID_SOCKET)
    {
      printf("error: unable to create socket!\n");
      exit (1);
    }

    if (isalpha(dc_host[0]))
    {
        host = gethostbyname(dc_host);
    }
    else
    {
        addr = inet_addr(dc_host);
        host = gethostbyaddr((char *) &addr, 4, AF_INET);
    }

    address.sin_family = AF_INET;
    address.sin_port = htons(13177);
    address.sin_addr.s_addr = *((unsigned long *)host->h_addr);

    if ((connect(sock,(struct sockaddr *)&address,sizeof(address))) != 0)
    {
      printf("error: unable to connect to remote server!\n");
      exit (1);
    }
    return 0;
}

void dc_send(char *cmd)
{
    send(sock,cmd,strlen(cmd),0);
}

int dc_recv(char *buf)
{
    memset(buf,0,sizeof(buf));
    l = recv(sock,buf,sizeof(buf),0);
    return l;
}

void dc_send_en(char *cmd, int length)
{
    int i;
    for (i = 0; i < length; i++)
    {
        cmd[i] = cmd[i] ^ d_cert[i % d_cert_length];
        cmd[i] = cmd[i] ^ digest_key[(i + 1) % (sizeof(digest_key) + 1)];
    }
    if ((i = send(sock,cmd,length,0)) < 0)
    {
      printf("error: unable to send data!\n");
    }

    if (i != length)
    {
      printf("error: data error!\n");
    }
}

int dc_recv_en(char *buf)
{
    int i;
    char c;

    memset(buf,0,BUFSZ);
    l = recv(sock,buf,BUFSZ,0);
    if (l == INVALID_SOCKET || l < 0) return 0;

    for (i = 0; i < l; i++)
    {
        c = buf[i] ^ d_cert[i % d_cert_length];
        c = c ^ digest_key[(i + 1) % (sizeof(digest_key) + 1)];
        buf[i] = c;
    }
    buf[i] = '\0';

    return l;
}


void dc_get_cert(void)
{
    FILE *infp;

    dc_send("AUTH");
    l = recv(sock,buffer,BUFSZ,0);

    infp = fopen("pubcert/my.cert","w+b");
    fwrite(buffer,l,1,infp);
    fclose (infp);

    memcpy(d_cert,buffer,l);

    d_cert_length = l;

    for (i = 0; i < l - 1; i++)
    {
        key = digest_key[i % sizeof(digest_key)] ^ d_cert[i];
        key = key ^ digest_key[(i + 1) % (sizeof(digest_key) + 1)];
    }
}

int main(int argc, char *argv[])
{
    if (argc > 2) strcpy(server,argv[1]);
    else strcpy(server,"localhost");

    dc_connect(server);
    dc_get_cert();
    dc_prompt();

    WSACleanup();
}
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winsock.h>
#include <dir.h>
#include <time.h>

#define BUFSZ (1024*2)
static char buffer[BUFSZ+1];
static char tbuffer[BUFSZ+1];
static char cmdbuf[BUFSZ+1];

#define PORT 13177

static unsigned char digest_key[] =
{
    0xd3,0x2b,0x31,0x10,0xaf,0xc8,0xff,0x89,
    0x8e,0xe3,0x3d,0x7c,0x29,0xd3,0x63,0x00,
    0xb7,0x71,0x68,0xae,0xf1,0x15,0xc4,0x9d,
    0x0e,0x95,0x70,0x65,0xc7,0x4c,0xe4,0x1f,
    0x53,0x10,0x17,0x63,0x6b,0x39,0x81,0x48,
    0x46,0xa0,0x1b,0x67,0x9c,0x9c,0x5d,0xd7,
    0xa7,0x06,0x3e,0x30,0x1c,0x35,0x36,0x8c,
    0x36,0x02,0x3e,0x80,0xaa,0xc4,0xce,0x26,
    0xb3,0x54,0xdd,0x16,0x06,0x0a,0xe3,0x67,
    0xde,0xbd,0xd9,0xb1,0xf0,0xc5,0x36,0x0e,
    0x76,0xfb,0xf3,0x13,0x28,0xb6,0x88,0xda,
    0x3d,0xcf,0xec,0xfb,0x6e,0x9d,0x97,0x8d,
    0xf2,0xf9,0x82,0x29,0x82,0x3a,0x25,0xe6,
    0x55,0x39,0x77,0x5c,0x24,0x4e,0xf0,0xa4,
    0x26,0x4f,0x89,0x56,0x14,0x97,0xba,0x89,
    0x25,0xfc,0x7a,0xd6,0x12,0xd6,0x41,0x54,
    0x12,0xfe,0x08,0x9b,0xde,0xcb,0x46,0xc4,
    0xad,0x16,0xf4,0x67,0x38,0x36,0x8a,0x9b,
    0xb6,0x04,0xff,0xf9,0xe0,0xd8,0xcb,0x98,
    0xed,0x88,0xe7,0x10,0x96,0x6f,0xcb,0x7a,
    0x12,0x63,0x6e,0x6e,0x1a,0xbc,0x48,0x03,
    0xe5,0x53,0x52,0xd2,0x2b,0x7f,0x04,0xf2,
    0x26,0x19,0x55,0xfb,0x8b,0x78,0xbd,0x07,
    0x95,0x75,0x35,0xab,0xf9,0x67,0x35,0x01,
    0xf2,0x27,0xb4,0xa1,0x35,0x0d,0x2a,0xa2,
    0xfd,0xf0,0x90,0x9c,0xff,0x28,0x5d,0xa9,
    0x75,0x8e,0x8a,0x5e,0x17,0x79,0x8f,0xd5,
    0x1c,0xc2,0x63,0xa6,0x3d,0xc0,0x7e,0xe8,
    0xb1,0x4c,0xd9,0x34,0x31,0xbd,0xec,0xa1,
    0xf4,0xec,0xae,0xc7,0xb3,0x31,0x97,0xbf,
    0xa5,0x62,0xa0,0x21,0x83,0xda,0x41,0x04,
    0x84,0x6f,0x71,0x01,0x61,0x79,0xa8,0x2f
};

static unsigned char d_cert[BUFSZ+1];
static int d_cert_length = 0;

int dc_quit = 0;

int l,i;
int running = 0;
char server_name[80];
unsigned int addr;
unsigned char key;

unsigned logged_in = 0;
int tries = 0;

WORD wVersionRequested;
WSADATA wsaData;
SOCKET sock;
struct sockaddr_in address;
struct hostent *host;

SOCKET server;
SOCKET remote;
struct sockaddr_in in;

struct passwd
{
  char userid[32];
  char passwd[32];
};

struct passwd pwd[10];
static int last_id = 0;

char **dc_get_args(char *cmdstr, int cmdstr_id);
void dc_parse_help(void);
void dc_parse_auth(char *cmdstr,int cmdstr_id);
void dc_parse_pass(char *cmdstr,int cmdstr_id);
void dc_parse_ls();
void dc_parse_put(char *cmdstr,int cmdstr_id);
void dc_parse_get(char *cmdstr,int cmdstr_id);
void dc_parse_quit();
int dc_getch(char *cmdstr);
int dc_parse(char *cmdstr);
int dc_prompt(void);
int dc_connect(char *dc_host);
void dc_send(char *cmd);
void dc_get_cert(void);
int dc_recv(char *buf);
void dc_send_en(char *cmd,int length);
int dc_recv_en(char *buf);


#define isvar(c) ((c) == '_' || (c) == '.' || (c) == '-')

char **dc_get_args(char *cmdstr, int cmdstr_id)
{
    char buffer[80+1];
    char *args[10 + 1];
    int i_lng = 0, argi = 0;

    while ((*(cmdstr+cmdstr_id)) != NULL)
    {
            if (isspace(*(cmdstr+cmdstr_id)))
            {
                while (isspace(*(cmdstr+cmdstr_id)))
                      cmdstr_id++;
                continue;
            }

            if (isalnum(*(cmdstr+cmdstr_id)) || isvar(*(cmdstr+cmdstr_id)))
            {
                while (isalnum(*(cmdstr+cmdstr_id)) || isvar(*(cmdstr+cmdstr_id)))
                {
                      if (i_lng > 80) i_lng--;
                      buffer[i_lng] = *(cmdstr+cmdstr_id);
                      i_lng++;
                      cmdstr_id++;
                }
                buffer[i_lng] = NULL;
                if (argi > 10) break;
                args[argi] = strdup(buffer);
                argi++;
            }
            else cmdstr_id++;
    }

    return args;
}

void dc_parse_help(void)
{
    char help_str[] =
    "DC Server Version 1.0\n\n"
    "PUT filename\n"
    "    Used for uploading file on a server.\n"
    "GET filename\n"
    "    Used for downloading file from the server.\n"
    "LS\n"
    "    List directory.\n"
    "QUIT\n"
    "    Quit this program.\n"
    "HELP\n"
    "    Displays this help text.\n";
    printf(help_str);
}

void dc_parse_auth(char *cmdstr,int cmdstr_id)
{
    char **argv;
    argv = dc_get_args(cmdstr,cmdstr_id);
}

void dc_parse_pass(char *cmdstr,int cmdstr_id)
{
    char **argv;
    argv = dc_get_args(cmdstr,cmdstr_id);
}

void dc_parse_ls()
{
    struct ffblk t_fblk;
    int done, l;
    char tmpstr[14];
    done = findfirst("*.*",&t_fblk,FA_NORMAL|FA_RDONLY);
    while (!done)
    {
        l = 13 - strlen(t_fblk.ff_name);
        memset(tmpstr,0,sizeof(tmpstr));
        while (l--) strcat(tmpstr," ");

        sprintf(buffer,"%s%s %10ld\n",t_fblk.ff_name,tmpstr,t_fblk.ff_fsize);
        printf("Sending: %s",buffer);
        dc_send_en(buffer,strlen(buffer));

        done = findnext(&t_fblk);
    }
    dc_send_en(".",1);
} 

void dc_parse_put(char *cmdstr,int cmdstr_id)
{
    char **argv;
    FILE *outfp;
    int l;
    argv = dc_get_args(cmdstr,cmdstr_id);

    if (argv[0] == NULL)
    {
        strcpy(buffer,"-ERR 1001");
        dc_send_en(buffer,strlen(buffer));
        return;
    }

    outfp = fopen(argv[0],"w+b");
    while ((l = dc_recv_en(buffer)) > 0)
    {
          if (buffer[0] == '.') { break; }
          printf("%d %s",l,buffer);
          fwrite(buffer,l,1,outfp);
    }
    fclose (outfp);
}

void dc_parse_get(char *cmdstr,int cmdstr_id)
{
    char **argv;
    FILE *infp;
    int length;
    argv = dc_get_args(cmdstr,cmdstr_id);
    if (argv[0] == NULL)
    {
        strcpy(buffer,"-ERR 1001");
        dc_send_en(buffer,strlen(buffer));
        return;
    }

    if ((infp = fopen(argv[0],"r+b"))==NULL)
    {
        strcpy(buffer,"-ERR 1002");
        dc_send_en(buffer,strlen(buffer));
        return;
    }
    while (!feof(infp))
    {
        memset(buffer,0,sizeof(buffer));
        length = fread(buffer,sizeof(buffer),1,infp);
        dc_send_en(buffer,length);
    }
    fclose (infp);
}

void dc_parse_quit()
{
    printf("you have successfully logged out.\n");
    dc_quit = 1;
}

int dc_getch(char *cmdstr)
{
    int cmdstr_id = 0,lng;
    char buf[80 + 1];
    while (*(cmdstr+cmdstr_id) != NULL)
    {
          if (isspace(*(cmdstr+cmdstr_id)))
          {
              while (isspace(*(cmdstr+cmdstr_id)))
                    cmdstr_id++;
              continue;
          }
          if (isalpha(*(cmdstr+cmdstr_id)))
          {
              lng = 0;
              while (isalpha(*(cmdstr+cmdstr_id)))
              {
                    if (lng > 80) lng--;
                    buf[lng] = *(cmdstr+cmdstr_id);
                    lng++;
                    cmdstr_id++;
              }
              buf[lng] = NULL;

              if (strcmp(buf,"AUTH") == 0)
              {
                  dc_parse_auth(cmdstr,cmdstr_id);
                  break;
              }
              else if (strcmp(buf,"PASS") == 0)
              {
                  dc_parse_pass(cmdstr,cmdstr_id);
                  break;
              }
              else if (strcmp(buf,"HELP") == 0 || strcmp(buf,"help") == 0)
              {
                  dc_parse_help();
                  break;
              }
              else if (strcmp(buf,"LS") == 0 || strcmp(buf,"ls") == 0)
              {
                  dc_parse_ls();
                  break;
              }
              else if (strcmp(buf,"PUT") == 0 || strcmp(buf,"put") == 0)
              {
                  dc_parse_put(cmdstr,cmdstr_id);
                  break;
              }
              else if (strcmp(buf,"GET") == 0 || strcmp(buf,"get") == 0)
              {
                  dc_parse_get(cmdstr,cmdstr_id);
                  break;     
              }
              else if (strcmp(buf,"QUIT") == 0 || strcmp(buf,"quit") == 0)
              {
                  dc_parse_quit();
                  break;
              }
              else
              {
                  printf("error: command not found\n");
                  break;
              }
          }
          else
          {
              printf("error: command not found\n");
              break;
          }
    }
    return 0;
}

int dc_parse(char *cmdstr)
{
    dc_getch(cmdstr);
    return 0;
}

int dc_prompt(void)
{
    char buf[256 + 1], c;
    while (!dc_quit)
    {
          memset(buf,0,sizeof(buf));
          printf("$ ");
          gets(buf);
          dc_parse(buf);
    }

    return 0;
}

int dc_connect(char *dc_host)
{
    wVersionRequested = MAKEWORD( 1, 1 );

    if (WSAStartup(wVersionRequested,&wsaData) != 0)
    {
      printf("error: unable to initialize winsock\n");
      exit (1);
    }

    if ((sock = socket(AF_INET,SOCK_STREAM,0)) == INVALID_SOCKET)
    {
      printf("error: unable to create socket!\n");
      exit (1);
    }

    if (isalpha(dc_host[0]))
    {
        host = gethostbyname(dc_host);
    }
    else
    {
        addr = inet_addr(dc_host);
        host = gethostbyaddr((char *) &addr, 4, AF_INET);
    }

    address.sin_family = AF_INET;
    address.sin_port = htons(13177);
    address.sin_addr.s_addr = *((unsigned long *)host->h_addr);

    if ((connect(sock,(struct sockaddr *)&address,sizeof(address))) != 0)
    {
      printf("error: unable to connect to remote server!\n");
      exit (1);
    }
    return 0;
}

void dc_send(char *cmd)
{
    send(remote,cmd,strlen(cmd),0);
}

void dc_send_en(char *cmd,int length)
{
    int i;
    for (i = 0; i < length; i++)
    {
        cmd[i] = cmd[i] ^ d_cert[i % d_cert_length];
        cmd[i] = cmd[i] ^ digest_key[(i + 1) % (sizeof(digest_key) + 1)];
    }

    if (send(remote,cmd,length,0) < 0)
    {
      printf("error: unable to send data!\n");
    }
}

int dc_recv_en(char *buf)
{
    int i;
    char c;
    memset(buf,0,BUFSZ);
    l = recv(remote,buf,BUFSZ,0);
    if (l == INVALID_SOCKET || l < 0 || l == 0) return 0;
    for (i = 0; i < l; i++)
    {
        c = buf[i] ^ d_cert[i % d_cert_length];
        c = c ^ digest_key[(i + 1) % (sizeof(digest_key) + 1)];
        buf[i] = c;
    }
    buf[l] = '\0';
    l = i;
    return l;
}

int dc_recv(char *buf)
{
    memset(buf,0,sizeof(buf));
    l = recv(remote,buf,sizeof(buf),0);
    return l;
}

void quit(char *m)
{
  printf("error: %s\n",m);
  WSACleanup();
  exit (1);
}

void load_digital_cert(void)
{
  FILE *certfp;

  printf("Loading digital certificate....");

  memset(d_cert,0,sizeof(d_cert));

  certfp = fopen("pubcert/server.cert","r+b"); 

  d_cert_length = 0;
  while (!feof(certfp))
  {
      d_cert[d_cert_length] = fgetc(certfp);
      d_cert[d_cert_length] = digest_key[(d_cert_length + 1) % (sizeof(digest_key) + 1)];
      d_cert_length++;
  }

  fclose (certfp);
  printf("Ok\n");
}

void tcp_server(void)
{
  int i, len;
  unsigned char c;

  if ((server = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)) == INVALID_SOCKET)
  {
      quit("unable to create socket!");
  }

  in.sin_family = AF_INET;
  in.sin_addr.s_addr = INADDR_ANY;
  in.sin_port = htons(PORT);

  if (bind(server,(struct sockaddr *)&in,sizeof (in)) == SOCKET_ERROR)
  {
      closesocket(server);
      quit("bind!");
  }

  printf("Server started.\n"); 

  if (listen(server,5) == SOCKET_ERROR)
  {
      closesocket(server);
      quit("listen!");
  }

  running = 1;

  while (running)
  {
      len = sizeof(in);
      if ((remote = accept(server,(struct sockaddr *)&in,&len)) == INVALID_SOCKET)
      {
        closesocket(server);
        quit("accept!");
      }

      printf("Received connection from: %s\n",inet_ntoa(in.sin_addr));
      printf("Sending digital certificate....");
      send(remote,d_cert,d_cert_length,0);
      printf("sent\n");

      while (1)
      {
        memset(buffer,0,sizeof(buffer));
        memset(cmdbuf,0,sizeof(cmdbuf));

        if ((len=recv(remote,buffer,sizeof(buffer),0)) == INVALID_SOCKET)
        {
            closesocket(server);
            closesocket(remote);
            WSACleanup();
            exit(1);
        }

        for (i = 0; i < len; i++)
        {
            c = buffer[i] ^ d_cert[i % d_cert_length];
            c = c ^ digest_key[(i + 1) % (sizeof(digest_key) + 1)];
            cmdbuf[i] = c;
        }

        cmdbuf[i+1] = '\n';

        dc_parse(cmdbuf);
      }     
  }

  printf("Server stopped.\n"); 
  closesocket(server);
  closesocket(remote);
}

void ini_user_db(void)
{
  int i, n, stage, p;
  char buf[80];
  FILE *pfp;

  printf("Initializing user database.....");

  if ((pfp = fopen("etc/passwd","r+b")) == NULL)
  {
      printf("error: unable to load password file!\n");
      exit (1);
  }
  i = 0;
  while (!feof(pfp))
  {
      fgets(buf,sizeof(buf),pfp);

      if (i > 10) break;

      n = 0;
      stage = 0;
      while (buf[n] != NULL)
      {
          if (n > sizeof(buf)) break;

          if (isalnum(buf[n]))
          {
              p = 0;
              while (isalnum(buf[n]))
              {
                  if (n > sizeof(buf)) break;

                  if (stage == 0)
                      pwd[i].userid[p] = buf[n];
                  else
                      pwd[i].passwd[p] = buf[n];

                  n++;
                  p++;
              }

              if (stage == 0) pwd[i].userid[p] = '\0';
              else pwd[i].passwd[p] = '\0';

              if (buf[n] == ':') stage++;
              if (stage > 2) break;
          }
          n++;
      }     
  }

  last_id = i;

  fclose (pfp);

  printf("Ok\n");

  for (i = 0; i < last_id; i++)
  {
        printf("%s %s\n",pwd[i].userid,pwd[i].passwd);
  }
}

int main(void)
{
    wVersionRequested = MAKEWORD( 1, 1 );

    if (WSAStartup(wVersionRequested,&wsaData) != 0)
    {
      printf("error: unable to initialize winsock\n");
      exit (1);
    }

    ini_user_db();
    load_digital_cert();
    tcp_server();

    WSACleanup();
}
