#include <stdio.h>
#include "tea.h"
#include <string.h>

//加密时使用的128位密钥
u8 password[16] = { 0x01, 0x09, 0x08, 0x09, 0x00, 0x06, 0x00, 0x04, 0x01, 0x09, 0x08, 0x09, 0x00, 0x06, 0x00, 0x04 };
u8 iv[8] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7};
/*********************************************************************
 *             tea加密
 *参数:v:要加密的数据,长度为8字节
 *     k:加密用的key,长度为16字节
 **********************************************************************/
static void tea_encrypt(u32 *v, u32 *k)
{
    u32 y = v[0], z = v[1], sum = 0, i;
    u32 delta = 0x9e3779b9;
    u32 a = k[0], b = k[1], c = k[2], d = k[3];
    
    for (i = 0; i < 32; i++)
    {
        sum += delta;
        y += ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
        z += ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
    }
    v[0] = y;
    v[1] = z;
}

/*********************************************************************
 *             tea解密
 *参数:v:要解密的数据,长度为8字节
 *     k:解密用的key,长度为16字节
 **********************************************************************/

static void tea_decrypt(u32 *v, u32 *k)
{
    u32 y = v[0], z = v[1], sum = 0xC6EF3720, i;
    u32 delta = 0x9e3779b9;
    u32 a = k[0], b = k[1], c = k[2], d = k[3];
    
    for (i = 0; i < 32; i++)
    {
        z -= ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
        y -= ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
        sum -= delta;
    }
    v[0] = y;
    v[1] = z;
}

/*********************************************************************
 *             加密算法
 *参数:src:源数据,所占空间必须为8字节的倍数.加密完成后密文也存放在这
 *     size_src:源数据大小,单位字节
 *     key:密钥,16字节
 *返回:密文的字节数
 **********************************************************************/

u16 encrypt(u8 *src, u16 size_src, u8 *key)
{
    u8 a = 0;
    u16 i = 0;
    u16 num = 0;
    
    //将明文补足为8字节的倍数
    a = size_src % 8;
    if (a != 0)
    {
        for (i = 0; i < 8 - a; i++)
        {
            src[size_src++] = 0;
        }
    }
    
    //加密
    num = size_src / 8;
    for (i = 0; i < num; i++)
    {
        tea_encrypt((u32 *)(src + i * 8), (u32 *)key);
    }
    
    return size_src;
}

/*********************************************************************
 *             解密算法
 *参数:src:源数据,所占空间必须为8字节的倍数.解密完成后明文也存放在这
 *     size_src:源数据大小,单位字节
 *     key:密钥,16字节
 *返回:明文的字节数,如果失败,返回0
 **********************************************************************/

u16 decrypt(u8 *src, u16 size_src, u8 *key)
{
    u16 i = 0;
    u16 num = 0;
    
    //判断长度是否为8的倍数
    if (size_src % 8 != 0)
    {
        return 0;
    }
    
    //解密
    num = size_src / 8;
    for (i = 0; i < num; i++)
    {
        tea_decrypt((u32 *)(src + i * 8), (u32 *)key);
    }
    
    return size_src;
}

void xor_operate_8byte(u32 *dst, u32 *op1, u32 *op2)
{
    dst[0] = op1[0]^op2[0];
    dst[1] = op1[1]^op2[1];
}
/*
    1.判断输入的字节数。
    2.将字节数分组，packets，剩余字节，remainder
    3.首先将初始化向量iv进行加密。
    4.输出结果与第一组明文进行异或运算得到密文放入iv中，并将iv拷贝到dec内。
    5.再对更新后的iv进行加密。
    6.然后将加密后的iv与第二组明文进行疑惑运算。得到新的iv。
    7.将新的iv放到第一块dec中。
    ...
    8.依次类推直到进行最后一块运算。
    9.这时候最后一个加密后的iv已经计算出来，但是最后一组数据需要进行一下填充。
    10.填充为8个字节的明文再与iv进行异或运算。得到新的iv
    11.这时再将iv拷贝到dec中，但只拷贝没有填充前的数量。
*/
void tea_cfb_encrypt(u8 *dst, u8 *src, u32 len)
{
    u32 packets, remainder, i;
    u8 padding[8] = {0};
    u8 local_iv[8] = {0};

    if (len <= 0)
        return;
    
    packets = len / 8;
    remainder = len % 8;
    memcpy(local_iv, iv, 8);

    for (i = 0; i < packets; i++ ) {
        tea_encrypt((u32 *)local_iv, (u32 *)password);
        xor_operate_8byte((u32*)local_iv, (u32*)(src+i*8), (u32*)local_iv);
        memcpy(dst+i*8, local_iv, 8);
    }

    if (remainder)
    {
       memcpy(padding, src+i*8, remainder);
       memset(padding + remainder, 0, 8 - remainder);
       tea_encrypt((u32 *)local_iv, (u32 *)password);
       xor_operate_8byte((u32*)padding, (u32*)(src+i*8), (u32*)local_iv);
       memcpy(dst+i*8, padding, remainder);
    }
}

void tea_cfb_decrypt(u8 *dst, u8 *src, u32 len)
{
    u32 packets, remainder, i;
    u8 padding[8] = {0};
    u8 local_iv[8] = {0};
    u8 tmp_text[8] = {0};
    
    if (len <= 0)
        return;
    
    packets = len / 8;
    remainder = len % 8;
    memcpy(local_iv, iv, 8);

    for (i = 0; i < packets; i++ ) {
        tea_encrypt((u32 *)local_iv, (u32 *)password);
        memcpy(temp_text, src + i*8, 8);
        xor_operate_8byte((u32*)(dst+i*8), (u32*)(src+i*8), (u32*)local_iv);
        memcpy(local_iv, tmp_text, 8);
    }

    if (remainder)
    {
       memcpy(padding, src+i*8, remainder);
       memset(padding + remainder, 0, 8 - remainder);
       tea_encrypt((u32 *)local_iv, (u32 *)password);
       xor_operate_8byte((u32*)padding, (u32*)(src+i*8), (u32*)local_iv);
       memcpy(dst+i*8, padding, remainder);
    }
}


void print_array(unsigned char * array, int len)
{
    int i;
    printf("\r\n ====== start of array ===== \r\n");
    for (i = 0; i < len; i++ ) {
        printf ("%02X ", array[i]);
        if ((i + 1)%16 == 0)
            printf("\n");
    }
    if ((i%16) != 0) {
        printf("\n");
    }

    printf(" ====== end of array ===== \r\n");

}

int main()
{
    unsigned char p_text[49] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01
    };
    unsigned char c_text[49] = {};
    unsigned char g_p_text[49] = {};
   // unsigned char c_text[8] = {0};

    //unsigned char get_plain_text[8] = {8};
    print_array(p_text, 49);
    tea_cfb_encrypt(c_text, p_text, 49);

    print_array(c_text, 49);

    tea_cfb_decrypt(g_p_text, c_text, 49);
    print_array(g_p_text, 49);

    
}
