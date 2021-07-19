
#ifndef SNIFFER_BUF_H_H_
#define SNIFFER_BUF_H_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
    [***************][ \0 ]......
    |<--   used  -->|<-1->|......

    *left = size - 1 - used
    *buf ==> size + 1;
*/

typedef struct sniffer_buf
{
    char * buf;

    uint32_t size;
    uint32_t used;
}SNIFFER_BUF;

#define zmalloc malloc
#define zrealloc realloc
#define zfree   free

sniffer_buf * init_sniffer_buf(uint32_t size = 32);
sniffer_buf * init_sniffer_buf(const char * str);
sniffer_buf * init_sniffer_buf(const char * data,uint32_t len);

uint32_t len_sniffer_buf(sniffer_buf * dest);
uint32_t size_sniffer_buf(sniffer_buf * dest);
uint32_t left_sniffer_buf(sniffer_buf * dest);

uint32_t cat_sniffer_buf(sniffer_buf * dest,const char * str);
uint32_t cat_sniffer_buf(sniffer_buf * dest,const char * data,uint32_t len);

void destroy_sniffer_buf(sniffer_buf * dest);

#endif //SNIFFER_BUF_H_H_
