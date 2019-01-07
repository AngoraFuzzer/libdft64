#include "common.h"

struct sockaddr_un socket_dst;
static int socket_fd = -1;
//extern TagSet tag_set;

void sendData(void *data, int size) {
  if (sendto(socket_fd, data, size, 0, (struct sockaddr *)&socket_dst,
             sizeof(struct sockaddr_un)) < 0) {
    //fprintf(stderr, "failt to call sendto\n");
  }
}

void SocketInit() {
  socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (socket_fd < 0) {
    fprintf(stderr, "failt to creat socket fd\n");
    exit(1);
  }
  /* Construct name of socket to send to. */
  memset(&socket_dst, 0, sizeof(struct sockaddr_un));
  socket_dst.sun_family = AF_UNIX;
  char *dst_id_str = getenv(SOCKET_ENV_VAR);
  //fprintf(stderr, "dst: %s\n", dst_str);
  if (dst_id_str) {
    //has_dst = true;
    snprintf(socket_dst.sun_path, sizeof(socket_dst.sun_path), "/tmp/angora_tracker_%s",
             dst_id_str);
    char data[] = "__STR__";
    sendData(data, sizeof(data));
  }
}

//void MLOG() {}

