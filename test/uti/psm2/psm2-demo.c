/*
 * PSM2 example program.
 * Start two instances of this program from the same working directory.
 * These processes can execute on the same host, or on two hosts connected
 * with OPA.
 * Compile with: gcc psm2-demo.c -o psm2-demo -lpsm2
 *     Run as: ./psm2-demo -s # this is the server process
 *     and: ./psm2-demo    # this is the client process
 *     Copyright(c) 2015 Intel Corporation.
 *     */
#include <stdio.h>
#include <psm2.h>     /* required for core PSM2 functions */
#include <psm2_mq.h>  /* required for PSM2 MQ functions (send, recv, etc) */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#define BUFFER_LENGTH 8000000
#define CONNECT_ARRAY_SIZE 8
void die(char *msg, int rc) {
  fprintf(stderr, "%s: %d\n", msg, rc);
  exit(1);
}

/* Helper functions to find the server's PSM2 endpoint identifier (epid). */
psm2_epid_t find_server() {
  FILE *fp = NULL;
  psm2_epid_t server_epid = 0;
  printf("PSM2 client waiting for epid mapping file to appear...\n");
  while (!fp) {
    sleep(1);
    fp = fopen("psm2-demo-server-epid", "r");
  }
  fscanf(fp, "%lx", &server_epid);
  fclose(fp);
  printf("PSM2 client found server epid = 0x%lx\n", server_epid);
  return server_epid;
}

void write_epid_to_file(psm2_epid_t myepid) {
  FILE *fp;
  fp = fopen("psm2-demo-server-epid", "w");
  if (!fp) {
    fprintf(stderr,
            "Exiting, couldn't write server's epid mapping file: ");
    die(strerror(errno), errno);
  }
  fprintf(fp, "0x%lx", myepid);
  fclose(fp);
  printf("PSM2 server wrote epid = 0x%lx to file.\n", myepid);
  return;
}

int main(int argc, char **argv) {
  struct psm2_ep_open_opts o;
  psm2_uuid_t uuid;
  psm2_ep_t myep;
  psm2_epid_t myepid;
  psm2_epid_t server_epid;
  psm2_epid_t epid_array[CONNECT_ARRAY_SIZE];
  int epid_array_mask[CONNECT_ARRAY_SIZE];
  psm2_error_t epid_connect_errors[CONNECT_ARRAY_SIZE];
  psm2_epaddr_t epaddr_array[CONNECT_ARRAY_SIZE];
  int rc;
  int ver_major = PSM2_VERNO_MAJOR;
  int ver_minor = PSM2_VERNO_MINOR;
  char msgbuf[BUFFER_LENGTH];
  psm2_mq_t q;
  psm2_mq_req_t req_mq;
  int is_server = 0;
  if (argc > 2) {
    die("To run in server mode, invoke as ./psm2-demo -s\n" \
        "or run in client mode, invoke as ./psm2-demo\n" \
        "Wrong number of args", argc);
  }
  is_server = argc - 1; /* Assume any command line argument is -s */
  memset(uuid, 0, sizeof(psm2_uuid_t)); /* Use a UUID of zero */
/* Try to initialize PSM2 with the requested library version.
 *  * In this example, given the use of the PSM2_VERNO_MAJOR and MINOR
 *   * as defined in the PSM2 headers, ensure that we are linking with
 *    * the same version of PSM2 as we compiled against. */

  if ((rc = psm2_init(&ver_major, &ver_minor)) != PSM2_OK) {
    die("couldn't init", rc);
  }
  printf("PSM2 init done.\n");
  /* Setup the endpoint options struct */
  if ((rc = psm2_ep_open_opts_get_defaults(&o)) != PSM2_OK) {
    die("couldn't set default opts", rc);
  }
  printf("PSM2 opts_get_defaults done.\n");
  /* Attempt to open a PSM2 endpoint. This allocates hardware resources. */
  if ((rc = psm2_ep_open(uuid, &o, &myep, &myepid)) != PSM2_OK) {
    die("couldn't psm2_ep_open()", rc);
  }
  printf("PSM2 endpoint open done.\n");
  if (is_server) {
    write_epid_to_file(myepid);
  } else {
    server_epid = find_server();
  }
  if (is_server) {
    /* Server does nothing here. A connection does not have to be
 *      * established to receive messages. */
    printf("PSM2 server up.\n");
  } else {
    /* Setup connection request info */
    /* PSM2 can connect to a single epid per request,
 *      * or an arbitrary number of epids in a single connect call.
 *           * For this example, use part of an array of
 *                * connection requests. */
    memset(epid_array_mask, 0, sizeof(int) * CONNECT_ARRAY_SIZE);
    epid_array[0] = server_epid;
    epid_array_mask[0] = 1;
    /* Begin the connection process.
 *      * note that if a requested epid is not responding,
 *           * the connect call will still return OK.
 *                * The errors array will contain the state of individual
 *                     * connection requests. */
    if ((rc = psm2_ep_connect(myep,
                              CONNECT_ARRAY_SIZE,
                              epid_array,
                              epid_array_mask,
                              epid_connect_errors,
                              epaddr_array,
                              0 /* no timeout */
    )) != PSM2_OK) {
      die("couldn't ep_connect", rc);
    }
    printf("PSM2 connect request processed.\n");
    /* Now check if our connection to the server is ready */
    if (epid_connect_errors[0] != PSM2_OK) {
      die("couldn't connect to server",
          epid_connect_errors[0]);
    }
    printf("PSM2 client-server connection established.\n");
  }
  /* Setup our PSM2 message queue */
  if ((rc = psm2_mq_init(myep, PSM2_MQ_ORDERMASK_NONE, NULL, 0, &q))
      != PSM2_OK) {
    die("couldn't initialize PSM2 MQ", rc);
  }
  printf("PSM2 MQ init done.\n");
  if (is_server) {
    psm2_mq_tag_t t = {0xABCD};
    psm2_mq_tag_t tm = {-1};
    /* Post the receive request */
    if ((rc = psm2_mq_irecv2(q, PSM2_MQ_ANY_ADDR,
                            &t, /* message tag */
                            &tm, /* message tag mask */
                            0, /* no flags */
                            msgbuf, BUFFER_LENGTH,
                            NULL, /* no context to add */
                            &req_mq /* track irecv status */
    )) != PSM2_OK) {
      die("couldn't post psm2_mq_irecv()", rc);
    }
    printf("PSM2 MQ irecv() posted\n");
    /* Wait until the message arrives */
    if ((rc = psm2_mq_wait(&req_mq, NULL)) != PSM2_OK) {
      die("couldn't wait for the irecv", rc);
    }
    printf("PSM2 MQ wait() done.\n");
    printf("Message from client:\n");
    printf("%s", msgbuf);
    unlink("psm2-demo-server-epid");
  } else {
    /* Say hello */
    snprintf(msgbuf, BUFFER_LENGTH,
             "Hello world from epid=0x%lx, pid=%d.\n",
             myepid, getpid());
    psm2_mq_tag_t t = {0xABCD};
    if ((rc = psm2_mq_send2(q,
                           epaddr_array[0], /* destination epaddr */
                           PSM2_MQ_FLAG_SENDSYNC, /* no flags */
                           &t, /* tag */
                           msgbuf, BUFFER_LENGTH
    )) != PSM2_OK) {
      die("couldn't post psm2_mq_isend", rc);
    }
    printf("PSM2 MQ send() done.\n");
  }
/* Close down the MQ */
  if ((rc = psm2_mq_finalize(q)) != PSM2_OK) {
    die("couldn't psm2_mq_finalize()", rc);
  }
  printf("PSM2 MQ finalized.\n");
/* Close our ep, releasing all hardware resources.
 *  * Try to close all connections properly */
  if ((rc = psm2_ep_close(myep, PSM2_EP_CLOSE_GRACEFUL,
                          0 /* no timeout */)) != PSM2_OK) {
    die("couldn't psm2_ep_close()", rc);
  }
  printf("PSM2 ep closed.\n");
  /* Release all local PSM2 resources */
  if ((rc = psm2_finalize()) != PSM2_OK) {
    die("couldn't psm2_finalize()", rc);
  }
  printf("PSM2 shut down, exiting.\n");
  return 0;
}
    








