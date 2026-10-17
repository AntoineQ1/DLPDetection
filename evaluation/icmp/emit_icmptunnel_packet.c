/*
 * Offline adapter for DhavalKapil/icmptunnel's send_icmp_packet().
 * Link this file with the external icmp.c using -Wl,--wrap=sendto.
 * The wrapped sendto writes the generated packet to stdout; no socket opens.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "icmp.h"

ssize_t __wrap_sendto(int fd, const void *buffer, size_t length, int flags,
                      const struct sockaddr *address, socklen_t address_length)
{
  (void)fd;
  (void)flags;
  (void)address;
  (void)address_length;
  return fwrite(buffer, 1, length, stdout) == length ? (ssize_t)length : -1;
}

int main(int argc, char **argv)
{
  unsigned char payload[MTU + 1];
  struct icmp_packet packet = {0};
  size_t length;

  if (argc != 4) {
    fprintf(stderr, "usage: emit_icmptunnel_packet SOURCE DESTINATION SEED\n");
    return 2;
  }
  length = fread(payload, 1, sizeof(payload), stdin);
  if (length == 0 || length > MTU || ferror(stdin)) {
    fprintf(stderr, "input must be one IP packet of 1..%d bytes\n", MTU);
    return 2;
  }
  if (strlen(argv[1]) >= sizeof(packet.src_addr) ||
      strlen(argv[2]) >= sizeof(packet.dest_addr)) {
    fprintf(stderr, "IP address is too long\n");
    return 2;
  }
  strcpy(packet.src_addr, argv[1]);
  strcpy(packet.dest_addr, argv[2]);
  packet.payload = (char *)payload;
  packet.payload_size = (int)length;
  srand((unsigned int)strtoul(argv[3], NULL, 10));
  set_echo_type(&packet);
  send_icmp_packet(-1, &packet);
  return fflush(stdout) == 0 ? 0 : 1;
}
