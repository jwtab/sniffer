
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

char index_sniffer_buf(struct sniffer_buf * buf,uint32_t index)
{
    return buf->buf[index];
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

uint32_t rePosition_sniffer_buf(struct sniffer_buf *buf,uint32_t start)
{
    /*

    */
    uint32_t new_len = buf->used - start;
    char * dest = (char*)zmalloc(sizeof(char)*new_len);
    if(dest)
    {
        memcpy(dest,buf->buf + start,new_len);

        memset(buf->buf,0,buf->size);
        memcpy(buf->buf,dest,new_len);

        buf->used = new_len;

        zfree(dest);
        dest = NULL;

        return new_len;
    }

   return 0;
}

uint32_t reset_sniffer_buf(struct sniffer_buf *buf)
{
    buf->used = 0;
    memset(buf->buf,0,buf->size);

    return buf->size;
}

char * buf_sniffer_buf(struct sniffer_buf * buf,int offset)
{
    return buf->buf + offset;
}

uint32_t pushback_sniffer_buf(struct sniffer_buf *buf,char c)
{
    if(left_sniffer_buf(buf) <= 1)
    {
        uint32_t size = size_sniffer_buf(buf) + 64;

        char * dest = (char*)zmalloc(sizeof(char)*(size));
        if(dest)
        {
            memset(dest,0,size);
            memcpy(dest,buf->buf,len_sniffer_buf(buf));
            
            //释放之前的空间.
            char * temp = buf->buf;
            buf->buf = dest;
            buf->size = size;

            if(temp)
            {
                zfree(temp);
                temp = NULL;
            }
        }
    }

    //放到最后位置.
    buf->buf[buf->used] = c;
    
    buf->used++;

    return buf->used;
}
