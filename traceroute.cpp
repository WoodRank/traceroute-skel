// --- Fix for Incomplete Type Errors ---
// Include network headers in the correct order *before* traceroute.h
// to resolve the incomplete type errors for 'struct iphdr' and 'struct icmphdr'
// caused by the include order in the provided .h file.
#include <sys/socket.h>   // Core socket definitions
#include <netinet/in.h>   // struct sockaddr_in, INADDR_NONE, etc.
#include <netinet/ip.h>   // struct iphdr
#include <netinet/ip_icmp.h>// struct icmphdr
#include <arpa/inet.h>    // inet_addr, inet_ntop
// --- End Fix ---

#include "traceroute.h"
#include <sys/time.h>     // For gettimeofday(), struct timeval
#include <sys/types.h>    // For getuid()
#include <pwd.h>          // For getuid() (though unistd.h also has it)
#include <unistd.h>       // for getuid(), close(), getopt()

// ****************************************************************************
// * Compute the Internet Checksum over an arbitrary buffer.
// * (from user's traceroute.cpp stub)
// ****************************************************************************
uint16_t checksum(unsigned short *buffer, int size) {
    unsigned long sum = 0;
    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }
    if (size == 1) {
        sum += *(unsigned char *) buffer;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}


int main (int argc, char *argv[]) {
  std::string destIP;

  // ********************************************************************
  // * Process the command line arguments
  // ********************************************************************
  int opt = 0;
  while ((opt = getopt(argc,argv,"t:d:")) != -1) {

    switch (opt) {
    case 't':
      destIP = optarg;
      break;
    case 'd':
      LOG_LEVEL = atoi(optarg); // Fixed double semicolon
      break;
    case ':':
    case '?':
    default:
      std::cout << "useage: " << argv[0] << " -t [target ip] -d [Debug Level]" << std::endl;
      exit(-1);
    }
  }

  // ********************************************************************
  // * Validate input and permissions
  // ********************************************************************

  if (destIP.empty()) {
    std::cout << "Target IP is required." << std::endl;
    std::cout << "useage: " << argv[0] << " -t [target ip] -d [Debug Level]" << std::endl;
    exit(-1);
  }

  // Raw sockets require root privileges
  if (getuid() != 0) {
      ERROR << "This program requires root privileges to create raw sockets." << ENDL;
      exit(-1);
  }


  //Create the destination addresss structure

  struct sockaddr_in destination_addr;
  memset(&destination_addr, 0, sizeof(destination_addr));
  destination_addr.sin_family = AF_INET;
  destination_addr.sin_addr.s_addr = inet_addr(destIP.c_str());

  int sendFd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sendFd < 0){
    perror("send socket");
    exit(-1);
  }

  int recvFd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (recvFd < 0){
    perror("recv socket");
    exit(-1);
  }

  //Create datagram

  int packet_len = 64;
  char packet[packet_len];
  memset(packet, 'A', packet_len);

  struct iphdr *ip_header = (struct iphdr *)packet;
  struct icmphdr *icmp_header = (struct icmphdr *)(packet + sizeof(struct iphdr));

  //Fill in the fields
  ip_header->ihl = 5; //header length
  ip_header->version = 4;
  ip_header->tos = 0;
  ip_header->tot_len = htons(packet_len);
  ip_header -> id = htons(getpid());
  ip_header -> frag_off = 0;
  ip_header -> protocol = IPPROTO_ICMP;
  ip_header -> saddr = 0;
  ip_header->daddr = destination_addr.sin_addr.s_addr; //destination ip

  icmp_header->type = ICMP_ECHO;
  icmp_header-> code = 0;
  icmp_header->un.echo.id = htons(getpid());

  bool reply = false;

  for (int ttl = 2; ttl <= 31 && !reply; ttl++){

    ip_header->ttl = ttl;

    icmp_header->un.echo.sequence = htons(ttl);

    icmp_header->checksum = 0;

    icmp_header->checksum = checksum((unsigned short *) icmp_header, packet_len - sizeof(struct iphdr));

    if (sendto(sendFd, packet, packet_len, 0, (struct sockaddr *)&destination_addr, sizeof(destination_addr)) < 0){
      perror("sendto)");
    }


    bool packet_received = false;
    struct timeval start_time, now_time;
    gettimeofday(&start_time, NULL);
    long time_elapsed_ms = 0;

    while (!packet_received && time_elapsed_ms < 15000){ // up to 15 seconds

    fd_set readFdSet;
    struct timeval timeout;

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    FD_ZERO(&readFdSet);
    FD_SET(recvFd, &readFdSet);

    int selectReturned = select(recvFd + 1, &readFdSet, NULL, NULL, &timeout);

    if (selectReturned < 0){
      perror("select");
      break;
    }
    else if (selectReturned == 0) {
      DEBUG << "5s timeout" << ENDL;
    }
    else if (FD_ISSET(recvFd, &readFdSet)){
      char recv_buffer[512];
      struct sockaddr_in recv_addr;
      socklen_t addr_len = sizeof(recv_addr);

      if (recvfrom(recvFd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&recv_addr, &addr_len) < 0) {
        perror("recvfrom");
      }
      char respondent_ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &recv_addr.sin_addr, respondent_ip, INET_ADDRSTRLEN);

      struct iphdr *recv_ip_header = (struct iphdr *)recv_buffer;
      int ip_header_length = recv_ip_header->ihl * 4;
      struct icmphdr *recv_icmp_header = (struct icmphdr *)(recv_buffer + ip_header_length);

      if (recv_icmp_header->type == ICMP_TIME_EXCEEDED){
        std::cout << "Hop " << ttl << ": " << respondent_ip << std::endl;
        packet_received = true;
      }
      else if (recv_icmp_header -> type == ICMP_ECHOREPLY){
        if (recv_icmp_header->un.echo.id == htons(getpid())){
          std::cout << "Hop " << ttl << ": " << respondent_ip << " (Destination reached)" << std::endl;
          packet_received = true;
          reply = true;
        }
      }



      packet_received = true;
    }
    gettimeofday(&now_time, NULL);
    time_elapsed_ms = (now_time.tv_sec - start_time.tv_sec) * 1000 + (now_time.tv_usec - start_time.tv_usec) / 1000;

  }

  if (!packet_received){
    std::cout << "No response with TTL of " << ttl << std::endl;
  }

  }







}