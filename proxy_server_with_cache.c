#include "proxy_parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>

// http://localhost:8080/https://www.cs.princeton.edu/

#define MAX_BYTES 4096					// max allowed size of request/response
#define MAX_CLIENTS 400					// max number of client requests served at a time
#define MAX_SIZE 200 * (1 << 20)		// size of the cache
#define MAX_ELEMENT_SIZE 10 * (1 << 20) // max size of an element in cache
#define MAX_BLOCKED_KEYWORDS 10

const char *blocked_keywords[MAX_BLOCKED_KEYWORDS] = {"blockword1", "blockword2", "blockword3"}; // Add your own keywords
const char *blocked_urls[MAX_BLOCKED_KEYWORDS] = {"www.blockedsite.com", "www.example.com"};

typedef struct cache_element cache_element;
typedef enum
{
	LRU,
	FIFO,
	LFU
} CachePolicy;					  // Supported policies
CachePolicy current_policy = LRU; // Default policy

struct cache_element
{
	char *data;			   // data stores response
	int len;			   // length of data i.e.. sizeof(data)...
	char *url;			   // url stores the request
	int access_count;	   // For LFU: Counts how often the element is accessed
	time_t insertion_time; // For FIFO
	time_t lru_time_track; // lru_time_track stores the latest time the element is  accesed
	cache_element *next;   // pointer to next element
};

cache_element *find(char *url);
int add_cache_element(char *data, int size, char *url);
void remove_cache_element();
int connectRemoteServer(char *host_addr, int port_num);
int sendErrorMessage(int socket, int status_code);

int port_number = 8080;		// Default Port
int proxy_socketId;			// socket descriptor of proxy server
pthread_t tid[MAX_CLIENTS]; // array to store the thread ids of clients
sem_t seamaphore;			// if client requests exceeds the max_clients this seamaphore puts the
							// waiting threads to sleep and wakes them when traffic on queue decreases
// sem_t cache_lock;
pthread_mutex_t lock; // lock is used for locking the cache

cache_element *head; // pointer to the cache
int cache_size;		 // cache_size denotes the current size of the cache

void sendForbiddenResponse(int socket)
{
	const char *response = "HTTP/1.1 403 Forbidden\r\n"
						   "Content-Length: 140\r\n"
						   "Content-Type: text/html\r\n"
						   "Connection: close\r\n"
						   "\r\n"
						   "<HTML><HEAD><TITLE>403 Forbidden</TITLE></HEAD>"
						   "<BODY><H1>403 Forbidden</H1>"
						   "<p>Access to this content is blocked by the proxy server.</p>"
						   "</BODY></HTML>";

	send(socket, response, strlen(response), 0);
}

// void sendForbiddenContentResponse(int socket)
// {
// 	char str[] = "HTTP/1.1 403 Forbidden\r\n"
// 				 "Content-Length: 95\r\n"
// 				 "Connection: close\r\n"
// 				 "Content-Type: text/html\r\n\r\n"
// 				 "<HTML><HEAD><TITLE>403 Forbidden</TITLE></HEAD>\n"
// 				 "<BODY><H1>403 Forbidden</H1>\n"
// 				 "Blocked content detected.\n"
// 				 "</BODY></HTML>";

// 	send(socket, str, strlen(str), 0);
// 	printf("Blocked content detected and forbidden page sent.\n");
// }

int contains_blocked_content(const char *data)
{
	for (int i = 0; i < MAX_BLOCKED_KEYWORDS; i++)
	{
		if (blocked_keywords[i] != NULL && strstr(data, blocked_keywords[i]) != NULL)
		{
			return 1; // Found blocked content
		}
	}
	return 0; // No blocked content found
}

int is_url_blocked(const char *url)
{
	for (int i = 0; i < MAX_BLOCKED_KEYWORDS; i++)
	{
		if (blocked_urls[i] != NULL && strstr(url, blocked_urls[i]) != NULL)
		{
			return 1; // URL is blocked
		}
	}
	return 0; // URL is allowed
}

int sendErrorMessage(int socket, int status_code)
{
	char str[1024];
	char currentTime[50];
	time_t now = time(0);

	struct tm data = *gmtime(&now);
	strftime(currentTime, sizeof(currentTime), "%a, %d %b %Y %H:%M:%S %Z", &data);

	switch (status_code)
	{
	case 400:
		snprintf(str, sizeof(str), "HTTP/1.1 400 Bad Request\r\nContent-Length: 95\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>400 Bad Request</TITLE></HEAD>\n<BODY><H1>400 Bad Rqeuest</H1>\n</BODY></HTML>", currentTime);
		printf("400 Bad Request\n");
		send(socket, str, strlen(str), 0);
		break;

	case 403:
		snprintf(str, sizeof(str), "HTTP/1.1 403 Forbidden\r\nContent-Length: 112\r\nContent-Type: text/html\r\nConnection: keep-alive\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>403 Forbidden</TITLE></HEAD>\n<BODY><H1>403 Forbidden</H1><br>Permission Denied\n</BODY></HTML>", currentTime);
		printf("403 Forbidden\n");
		send(socket, str, strlen(str), 0);
		break;

	case 404:
		snprintf(str, sizeof(str), "HTTP/1.1 404 Not Found\r\nContent-Length: 91\r\nContent-Type: text/html\r\nConnection: keep-alive\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD>\n<BODY><H1>404 Not Found</H1>\n</BODY></HTML>", currentTime);
		printf("404 Not Found\n");
		send(socket, str, strlen(str), 0);
		break;

	case 500:
		snprintf(str, sizeof(str), "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 115\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>500 Internal Server Error</TITLE></HEAD>\n<BODY><H1>500 Internal Server Error</H1>\n</BODY></HTML>", currentTime);
		// printf("500 Internal Server Error\n");
		send(socket, str, strlen(str), 0);
		break;

	case 501:
		snprintf(str, sizeof(str), "HTTP/1.1 501 Not Implemented\r\nContent-Length: 103\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>404 Not Implemented</TITLE></HEAD>\n<BODY><H1>501 Not Implemented</H1>\n</BODY></HTML>", currentTime);
		printf("501 Not Implemented\n");
		send(socket, str, strlen(str), 0);
		break;

	case 505:
		snprintf(str, sizeof(str), "HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 125\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n<HTML><HEAD><TITLE>505 HTTP Version Not Supported</TITLE></HEAD>\n<BODY><H1>505 HTTP Version Not Supported</H1>\n</BODY></HTML>", currentTime);
		printf("505 HTTP Version Not Supported\n");
		send(socket, str, strlen(str), 0);
		break;

	default:
		return -1;
	}
	return 1;
}

void set_cache_policy(CachePolicy policy)
{
	current_policy = policy;
	printf("Cache policy set to: %s\n", (policy == LRU) ? "LRU" : (policy == LFU) ? "LFU"
																				  : "FIFO");
}

int connectRemoteServer(char *host_addr, int port_num)
{
	// Creating Socket for remote server ---------------------------

	int remoteSocket = socket(AF_INET, SOCK_STREAM, 0);

	if (remoteSocket < 0)
	{
		printf("Error in Creating Socket.\n");
		return -1;
	}

	// Get host by the name or ip address provided

	struct hostent *host = gethostbyname(host_addr);
	if (host == NULL)
	{
		fprintf(stderr, "No such host exists.\n");
		return -1;
	}

	// inserts ip address and port number of host in struct `server_addr`
	struct sockaddr_in server_addr;

	bzero((char *)&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port_num);

	bcopy((char *)host->h_addr, (char *)&server_addr.sin_addr.s_addr, host->h_length);

	// Connect to Remote server ----------------------------------------------------

	if (connect(remoteSocket, (struct sockaddr *)&server_addr, (socklen_t)sizeof(server_addr)) < 0)
	{
		fprintf(stderr, "Error in connecting !\n");
		return -1;
	}
	// free(host_addr);
	return remoteSocket;
}

int handle_request(int clientSocket, ParsedRequest *request, char *tempReq)
{
	printf("Handling Request\n");
	char *buf = (char *)malloc(sizeof(char) * MAX_BYTES);
	strcpy(buf, request->method); // Use dynamic method
	strcat(buf, " ");
	strcat(buf, request->path);
	strcat(buf, " ");
	strcat(buf, request->version);
	strcat(buf, "\r\n");

	size_t len = strlen(buf);

	if (ParsedHeader_set(request, "Connection", "close") < 0)
	{
		printf("set header key not work\n");
	}

	if (ParsedHeader_get(request, "Host") == NULL)
	{
		if (ParsedHeader_set(request, "Host", request->host) < 0)
		{
			printf("Set \"Host\" header key not working\n");
		}
	}

	if (ParsedRequest_unparse_headers(request, buf + len, (size_t)MAX_BYTES - len) < 0)
	{
		printf("unparse failed\n");
		// return -1;				// If this happens Still try to send request without header
	}

	int server_port = 80; // Default Remote Server Port
	if (request->port != NULL)
		server_port = atoi(request->port);

	int remoteSocketID = connectRemoteServer(request->host, server_port);

	if (remoteSocketID < 0)
		return -1;

	int bytes_send = send(remoteSocketID, buf, strlen(buf), 0);

	bzero(buf, MAX_BYTES);

	bytes_send = recv(remoteSocketID, buf, MAX_BYTES - 1, 0);
	char *temp_buffer = (char *)malloc(sizeof(char) * MAX_BYTES); // temp buffer
	int temp_buffer_size = MAX_BYTES;
	int temp_buffer_index = 0;

	while (bytes_send > 0)
	{
		// if (contains_blocked_content(buf))
		// {
		// 	sendErrorMessage(clientSocket, 403); // Blocked content detected
		// 	sendForbiddenContentResponse(clientSocket);
		// 	printf("Blocked content in response.\n");
		// 	break;
		// }

		bytes_send = send(clientSocket, buf, bytes_send, 0);

		for (long unsigned int i = 0; i < bytes_send / sizeof(char); i++)
		{
			temp_buffer[temp_buffer_index] = buf[i];
			// printf("%c", buf[i]); // Response Printing
			temp_buffer_index++;
		}
		temp_buffer_size += MAX_BYTES;
		temp_buffer = (char *)realloc(temp_buffer, temp_buffer_size);

		if (bytes_send < 0)
		{
			perror("Error in sending data to client socket.\n");
			break;
		}
		bzero(buf, MAX_BYTES);

		bytes_send = recv(remoteSocketID, buf, MAX_BYTES - 1, 0);
	}
	temp_buffer[temp_buffer_index] = '\0';
	free(buf);
	add_cache_element(temp_buffer, strlen(temp_buffer), tempReq);
	printf("Done\n");
	free(temp_buffer);
	shutdown(clientSocket, SHUT_RDWR);
	close(clientSocket);

	close(remoteSocketID);
	return 0;
}

int checkHTTPversion(char *msg)
{
	int version = -1;

	if (strncmp(msg, "HTTP/1.1", 8) == 0)
	{
		version = 1;
	}
	else if (strncmp(msg, "HTTP/1.0", 8) == 0)
	{
		version = 1; // Handling this similar to version 1.1
	}
	else
		version = -1;

	return version;
}

void handle_https_tunneling(int client_socket, const char *host, int port)
{
	int remote_socket = connectRemoteServer((char *)host, port);
	if (remote_socket < 0)
	{
		sendErrorMessage(client_socket, 502); // Bad Gateway if connection fails
		return;
	}

	// Send HTTP 200 OK to client to start tunneling
	const char *connection_established = "HTTP/1.1 200 Connection Established\r\n\r\n";
	send(client_socket, connection_established, strlen(connection_established), 0);

	// Relay data between client and server
	fd_set read_fds;
	char buffer[4096];
	int max_fd = (client_socket > remote_socket ? client_socket : remote_socket) + 1;

	while (1)
	{
		FD_ZERO(&read_fds);
		FD_SET(client_socket, &read_fds);
		FD_SET(remote_socket, &read_fds);

		if (select(max_fd, &read_fds, NULL, NULL, NULL) < 0)
			break;

		if (FD_ISSET(client_socket, &read_fds))
		{
			int bytes = recv(client_socket, buffer, sizeof(buffer), 0);
			if (bytes <= 0)
				break;
			send(remote_socket, buffer, bytes, 0);
		}

		if (FD_ISSET(remote_socket, &read_fds))
		{
			int bytes = recv(remote_socket, buffer, sizeof(buffer), 0);
			if (bytes <= 0)
				break;
			send(client_socket, buffer, bytes, 0);
		}
	}

	close(remote_socket);
	close(client_socket);
}

void *thread_fn(void *socketNew)
{
	sem_wait(&seamaphore);
	int p;
	sem_getvalue(&seamaphore, &p);
	printf("semaphore value:%d\n", p);
	int *t = (int *)(socketNew);
	int socket = *t;			// Socket is socket descriptor of the connected Client
	int bytes_send_client, len; // Bytes Transferred

	char *buffer = (char *)calloc(MAX_BYTES, sizeof(char)); // Creating buffer of 4kb for a client

	bzero(buffer, MAX_BYTES);								// Making buffer zero
	bytes_send_client = recv(socket, buffer, MAX_BYTES, 0); // Receiving the Request of client by proxy server

	while (bytes_send_client > 0)
	{
		len = strlen(buffer);
		// loop until u find "\r\n\r\n" in the buffer
		if (strstr(buffer, "\r\n\r\n") == NULL)
		{
			bytes_send_client = recv(socket, buffer + len, MAX_BYTES - len, 0);
		}
		else
		{
			break;
		}
	}

	printf("--------------------------------------------\n");
	// printf("%s\n", buffer);
	printf("----------------------%ld----------------------\n", strlen(buffer));

	char *tempReq = (char *)malloc(strlen(buffer) * sizeof(char) + 1);
	// tempReq, buffer both store the http request sent by client
	for (long unsigned int i = 0; i < strlen(buffer); i++)
	{
		tempReq[i] = buffer[i];
	}

	// checking for the request in cache
	struct cache_element *temp = find(tempReq);

	if (temp != NULL)
	{
		// request found in cache, so sending the response to client from proxy's cache
		int size = temp->len / sizeof(char);
		int pos = 0;
		char response[MAX_BYTES];
		while (pos < size)
		{
			bzero(response, MAX_BYTES);
			for (int i = 0; i < MAX_BYTES; i++)
			{
				response[i] = temp->data[pos];
				pos++;
			}
			send(socket, response, MAX_BYTES, 0);
		}
		printf("Data retrived from the Cache\n\n");
		printf("%s\n\n", response);
		// close(socketNew);
		// sem_post(&seamaphore);
		// return NULL;
	}

	else if (bytes_send_client > 0)
	{
		len = strlen(buffer);
		// Parsing the request
		ParsedRequest *request = ParsedRequest_create();

		// if (is_url_blocked(request->host))
		// {
		// 	sendErrorMessage(socket, 403); // Block access and return 403 Forbidden
		// 	printf("Blocked access to: %s\n", request->host);
		// 	close(socket);
		// 	sem_post(&seamaphore);
		// 	return NULL;
		// }

		// Buffer holds the client's HTTP request
		if (contains_blocked_content(buffer))
		{ // Check request for blocked keywords
			printf("Blocked request containing restricted keywords.\n");
			sendForbiddenResponse(socket); // Send 403 error page
			close(socket);
			sem_post(&seamaphore);
			return NULL;
		}

		// ParsedRequest_parse returns 0 on success and -1 on failure.On success it stores parsed request in
		//  the request
		if (ParsedRequest_parse(request, buffer, len) < 0)
		{
			printf("Parsing failed\n");
		}
		else
		{
			bzero(buffer, MAX_BYTES);
			if (!strcmp(request->method, "CONNECT"))
			{ // Handle HTTPS requests
				handle_https_tunneling(socket, request->host, atoi(request->port));
			}
			else if (!strcmp(request->method, "GET") || !strcmp(request->method, "POST") || !strcmp(request->method, "PUT"))
			{
				if (request->host && request->path && (checkHTTPversion(request->version) == 1))
				{
					bytes_send_client = handle_request(socket, request, tempReq); // Handle request
					if (bytes_send_client == -1)
					{
						sendErrorMessage(socket, 500);
					}
				}
				else
				{
					sendErrorMessage(socket, 500); // 500 Internal Error
				}
			}
			else
			{
				printf("This code doesn't support any method other than GET, POST, or PUT\n");
			}
		}
		// freeing up the request pointer
		ParsedRequest_destroy(request);
	}

	else if (bytes_send_client < 0)
	{
		perror("Error in receiving from client.\n");
	}
	else if (bytes_send_client == 0)
	{
		printf("Client disconnected!\n");
	}

	shutdown(socket, SHUT_RDWR);
	close(socket);
	free(buffer);
	sem_post(&seamaphore);

	sem_getvalue(&seamaphore, &p);
	printf("Semaphore post value:%d\n", p);
	free(tempReq);
	return NULL;
}

int main(int argc, char *argv[])
{
	set_cache_policy(FIFO); // Set desired policy here

	int client_socketId, client_len;			 // client_socketId == to store the client socket id
	struct sockaddr_in server_addr, client_addr; // Address of client and server to be assigned

	sem_init(&seamaphore, 0, MAX_CLIENTS); // Initializing seamaphore and lock
	pthread_mutex_init(&lock, NULL);	   // Initializing lock for cache

	if (argc == 2) // checking whether two arguments are received or not
	{
		port_number = atoi(argv[1]);
	}
	else
	{
		printf("Too few arguments\n");
		exit(1);
	}

	printf("Setting Proxy Server Port : %d\n", port_number);

	// creating the proxy socket
	proxy_socketId = socket(AF_INET, SOCK_STREAM, 0);

	if (proxy_socketId < 0)
	{
		perror("Failed to create socket.\n");
		exit(1);
	}

	int reuse = 1;
	if (setsockopt(proxy_socketId, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) < 0)
		perror("setsockopt(SO_REUSEADDR) failed\n");

	bzero((char *)&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port_number); // Assigning port to the Proxy
	server_addr.sin_addr.s_addr = INADDR_ANY;  // Any available adress assigned

	// Binding the socket
	if (bind(proxy_socketId, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		perror("Port is not free\n");
		exit(1);
	}
	printf("Binding on port: %d\n", port_number);

	// Proxy socket listening to the requests
	int listen_status = listen(proxy_socketId, MAX_CLIENTS);

	if (listen_status < 0)
	{
		perror("Error while Listening !\n");
		exit(1);
	}

	int i = 0;							 // Iterator for thread_id (tid) and Accepted Client_Socket for each thread
	int Connected_socketId[MAX_CLIENTS]; // This array stores socket descriptors of connected clients

	// Infinite Loop for accepting connections
	while (1)
	{

		bzero((char *)&client_addr, sizeof(client_addr)); // Clears struct client_addr
		client_len = sizeof(client_addr);

		// Accepting the connections
		client_socketId = accept(proxy_socketId, (struct sockaddr *)&client_addr, (socklen_t *)&client_len); // Accepts connection
		if (client_socketId < 0)
		{
			fprintf(stderr, "Error in Accepting connection !\n");
			exit(1);
		}
		else
		{
			Connected_socketId[i] = client_socketId; // Storing accepted client into array
		}

		// Getting IP address and port number of client
		struct sockaddr_in *client_pt = (struct sockaddr_in *)&client_addr;
		struct in_addr ip_addr = client_pt->sin_addr;
		char str[INET_ADDRSTRLEN]; // INET_ADDRSTRLEN: Default ip address size
		inet_ntop(AF_INET, &ip_addr, str, INET_ADDRSTRLEN);
		printf("Client is connected with port number: %d and ip address: %s \n", ntohs(client_addr.sin_port), str);
		// printf("Socket values of index %d in main function is %d\n",i, client_socketId);
		pthread_create(&tid[i], NULL, thread_fn, (void *)&Connected_socketId[i]); // Creating a thread for each client accepted
		i++;
	}
	close(proxy_socketId); // Close socket
	return 0;
}

cache_element *find(char *url)
{

	// Checks for url in the cache if found returns pointer to the respective cache element or else returns NULL
	cache_element *site = NULL;
	// sem_wait(&cache_lock);
	int temp_lock_val = pthread_mutex_lock(&lock);
	printf("Remove Cache Lock Acquired %d\n", temp_lock_val);
	if (head != NULL)
	{
		site = head;
		while (site != NULL)
		{
			if (!strcmp(site->url, url))
			{
				printf("LRU Time Track Before : %ld", site->lru_time_track);
				printf("\nurl found\n");
				// Updating the time_track
				site->lru_time_track = time(NULL);
				site->access_count++;
				printf("LRU Time Track After : %ld", site->lru_time_track);
				break;
			}
			site = site->next;
		}
	}
	else
	{
		printf("\nurl not found\n");
	}
	// sem_post(&cache_lock);
	temp_lock_val = pthread_mutex_unlock(&lock);
	printf("Remove Cache Lock Unlocked %d\n", temp_lock_val);
	return site;
}

void remove_cache_element()
{
	// If cache is not empty searches for the node which has the least lru_time_track and deletes it
	cache_element *p;	 // Cache_element Pointer (Prev. Pointer)
	cache_element *q;	 // Cache_element Pointer (Next Pointer)
	cache_element *temp; // Cache element to remove
	// sem_wait(&cache_lock);
	int temp_lock_val = pthread_mutex_lock(&lock);
	printf("Remove Cache Lock Acquired %d\n", temp_lock_val);
	if (head != NULL)
	{ // Cache != empty
		for (q = head, p = head, temp = head; q->next != NULL; q = q->next)
		{
			if (current_policy == LRU)
			{
				if ((q->next->lru_time_track) < (temp->lru_time_track))
				{
					temp = q->next;
					p = q;
				}
			}
			else if (current_policy == LFU)
			{
				if ((q->next->access_count) < (temp->access_count))
				{
					temp = q->next;
					p = q;
				}
			}
			else if (current_policy == FIFO)
			{
				if ((q->next->insertion_time) < (temp->insertion_time))
				{ // Track FIFO insertion time
					temp = q->next;
					p = q;
				}
			}
		}

		if (temp == head)
		{
			head = head->next; /*Handle the base case*/
		}
		else
		{
			p->next = temp->next;
		}
		cache_size = cache_size - (temp->len) - sizeof(cache_element) -
					 strlen(temp->url) - 1; // updating the cache size
		free(temp->data);
		free(temp->url); // Free the removed element
		free(temp);
	}
	// sem_post(&cache_lock);
	temp_lock_val = pthread_mutex_unlock(&lock);
	printf("Remove Cache Lock Unlocked %d\n", temp_lock_val);
}

int add_cache_element(char *data, int size, char *url)
{
	// Adds element to the cache
	// sem_wait(&cache_lock);
	int temp_lock_val = pthread_mutex_lock(&lock);
	printf("Add Cache Lock Acquired %d\n", temp_lock_val);
	int element_size = size + 1 + strlen(url) + sizeof(cache_element); // Size of the new element which will be added to the cache
	if (element_size > MAX_ELEMENT_SIZE)
	{
		// sem_post(&cache_lock);
		//  If element size is greater than MAX_ELEMENT_SIZE we don't add the element to the cache
		temp_lock_val = pthread_mutex_unlock(&lock);
		printf("Add Cache Lock Unlocked %d\n", temp_lock_val);
		// free(data);
		// printf("--\n");
		// free(url);
		return 0;
	}
	else
	{
		while (cache_size + element_size > MAX_SIZE)
		{
			// We keep removing elements from cache until we get enough space to add the element
			remove_cache_element();
		}
		cache_element *element = (cache_element *)malloc(sizeof(cache_element)); // Allocating memory for the new cache element
		element->data = (char *)malloc(size + 1);								 // Allocating memory for the response to be stored in the cache element
		strcpy(element->data, data);
		element->url = (char *)malloc(1 + (strlen(url) * sizeof(char))); // Allocating memory for the request to be stored in the cache element (as a key)
		strcpy(element->url, url);
		element->lru_time_track = time(NULL); // Updating the time_track
		element->next = head;
		element->len = size;
		element->insertion_time = time(NULL); // For FIFO
		element->access_count = 1;			  // Initialize for LFU

		head = element;
		cache_size += element_size;
		temp_lock_val = pthread_mutex_unlock(&lock);
		printf("Add Cache Lock Unlocked %d\n", temp_lock_val);
		// sem_post(&cache_lock);
		//  free(data);
		//  printf("--\n");
		//  free(url);
		return 1;
	}
	return 0;
}