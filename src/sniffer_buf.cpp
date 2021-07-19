
#include <sniffer_buf.h>

sniffer_buf * init_sniffer_buf(uint32_t size)
{
    sniffer_buf * buf = (sniffer_buf*)zmalloc(sizeof(sniffer_buf));

    buf->buf = (char*)zmalloc(sizeof(char)*(size + 1));
    buf->used = 0;
    buf->size = size;

    memset(buf->buf,0,size + 1);

    return buf;
}

sniffer_buf * init_sniffer_buf(const char * str)
{
    uint32_t len = strlen(str);
    sniffer_buf * buf = init_sniffer_buf(str,len*2);
    buf->used = len;
    
    return buf;
}

sniffer_buf * init_sniffer_buf(const char * data,uint32_t len)
{
    sniffer_buf * buf = init_sniffer_buf(len*2);

    memcpy(buf->buf,data,len);
    buf->used = len;

    return buf;
}

uint32_t len_sniffer_buf(sniffer_buf * dest)
{
    return dest->used;
}

uint32_t size_sniffer_buf(sniffer_buf * dest)
{
    return dest->size;
}

uint32_t left_sniffer_buf(sniffer_buf * dest)
{
    return dest->size - dest->used;
}

void destroy_sniffer_buf(sniffer_buf * dest)
{
    if(dest)
    {
        if(dest->buf)
        {
            zfree(dest->buf);
            dest->buf = nullptr;

            dest->size = dest->used = 0;
        }

        zfree(dest);
        dest = nullptr;
    }
}

uint32_t cat_sniffer_buf(sniffer_buf * dest,const char * str)
{
    return cat_sniffer_buf(dest,str,strlen(str));
}

uint32_t cat_sniffer_buf(sniffer_buf * dest,const char * data,uint32_t len)
{
    if(left_sniffer_buf(dest) > len)
    {
        memcpy(dest->buf + dest->used,data,len);
        dest->used = dest->used + len;
    }
    else
    {
        uint32_t size = size_sniffer_buf(dest) + len + 64;
        char * temp = (char*)zmalloc(sizeof(char)*(size));
        if(temp)
        {
            memcpy(temp,dest->buf,dest->used);
            memcpy(temp + dest->used,data,len);

            dest->used = dest->used + len;
            dest->size = size;

            //释放之前的空间.
            char * p = dest->buf;
            dest->buf = temp;

            if(p)
            {
                zfree(p);
                p = NULL;
            }
        }
    }

    return dest->used;
}
