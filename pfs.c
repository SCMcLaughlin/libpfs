
#include "pfs.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>

typedef struct {
    uint32_t    offset;
    uint32_t    signature;
    uint32_t    unknown;
} PfsHeader;

typedef struct {
    uint32_t    deflatedLen;
    uint32_t    inflatedLen;
} PfsBlock;

typedef struct {
    uint32_t    crc;
    uint32_t    offset;
    uint32_t    inflatedLen;
} PfsFileEntry;

typedef struct {
    char*       name;
    uint8_t     nameIsCopy;
    uint8_t     insertedIsCopy;
    uint32_t    crc;
    uint32_t    offset;
    uint32_t    inflatedLen;
    uint32_t    deflatedLen;
    uint8_t*    inserted;
} PfsEntry;

typedef struct {
    uint8_t*    data;
    uint32_t    length;
} PfsBuf;

struct PFS {
    uint32_t    count;
    uint32_t    length;
    PfsEntry*   entries;
    uint32_t*   hashes;
    uint8_t*    data;
    uint8_t*    nameData;
    int         dataIsCopy;
};

static uint32_t pfs_crc_table[] = {
    0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005, 
    0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd, 
    0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9, 0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75, 
    0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd, 
    0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039, 0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5, 
    0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d, 
    0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95, 
    0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1, 0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 
    0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072, 
    0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16, 0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca, 
    0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02, 
    0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba, 
    0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692, 
    0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a, 
    0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2, 
    0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a, 
    0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb, 
    0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f, 0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53, 
    0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b, 
    0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff, 0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623, 
    0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b, 
    0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3, 
    0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7, 0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 
    0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3, 
    0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640, 0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c, 
    0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24, 
    0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec, 
    0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654, 
    0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c, 
    0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4, 
    0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c, 
    0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

#define pfs_is_pow2(n) ((n) && (((n) & ((n) - 1)) == 0))
#define pfs_is_pow2_or_zero(n) ((n == 0) || (((n) & ((n) - 1)) == 0))
#define pfs_free_if_exists(ptr) do { if ((ptr)) free((ptr)); } while(0)

static uint32_t pfs_next_pow2(uint32_t n)
{
    n--;
    
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    
    n++;
    
    return n;
}

static uint32_t pfs_pow2_greater_or_equal(uint32_t n)
{
    return pfs_is_pow2(n) ? (n) : pfs_next_pow2(n);
}

static uint32_t pfs_hash(const char* key, uint32_t len)
{
    uint32_t h = len;
    uint32_t step = (len >> 5) + 1;
    uint32_t i;
    
    for (i = len; i >= step; i -= step)
    {
        h = h ^ ((h << 5) + (h >> 2) + (key[i - 1]));
    }
    
    return h;
}

static uint32_t pfs_crc(const void* data, uint32_t len)
{
    const uint8_t* ptr = (const uint8_t*)data;
    uint32_t val = 0;
    uint32_t idx;
    uint32_t i;
    
    for (i = 0; i < len; i++)
    {
        idx = ((val >> 24) ^ ptr[i]) & 0xff;
        val = (val << 8) ^ pfs_crc_table[idx];
    }
    
    return val;
}

static int pfs_decompress_index(PFS* pfs, uint8_t** outData, uint32_t* outLength, uint32_t index)
{
    PfsEntry* ent;
    uint8_t* src;
    uint8_t* dst;
    uint32_t ilen;
    uint32_t read = 0;
    uint32_t pos = 0;
    
    if (index >= pfs->count)
        return PFS_OUT_OF_BOUNDS;
    
    ent = &pfs->entries[index];
    ilen = ent->inflatedLen;
    src = pfs->data + ent->offset;
    dst = (uint8_t*)malloc(ilen);
    
    if (!dst) return PFS_OUT_OF_MEMORY;
    
    while (read < ilen)
    {
        PfsBlock* block = (PfsBlock*)(src + pos);
        unsigned long len;
        int rc;
        
        pos += sizeof(PfsBlock);
        
        len = ilen - read;
        rc = uncompress(dst + read, &len, src + pos, block->deflatedLen);
        
        if (rc != Z_OK) goto fail;
        
        read += block->inflatedLen;
        pos += block->deflatedLen;
    }
    
    *outData = dst;
    *outLength = ilen;
    return PFS_OK;
    
fail:
    free(dst);
    return PFS_COMPRESSION_ERROR;
}

static int pfs_sort_by_offset(const void* va, const void* vb)
{
    const PfsEntry* a = (const PfsEntry*)va;
    const PfsEntry* b = (const PfsEntry*)vb;
    
    return (a->offset < b->offset) ? -1 : 1;
}

static int pfs_open_impl(PFS** outPfs, const uint8_t* data, uint32_t length, int isCopy)
{
    PFS* pfs;
    uint32_t p, n, i;
    PfsHeader* h;
    uint8_t* nameData = NULL;
    int rc = PFS_CORRUPTED;
    int foundTraceDotDbg = 0;
    
    pfs = (PFS*)malloc(sizeof(PFS));
    
    if (!pfs)
    {
        rc = PFS_OUT_OF_MEMORY;
        goto fail_alloc;
    }
    
    pfs->count = 0;
    pfs->length = length;
    pfs->entries = NULL;
    pfs->hashes = NULL;
    pfs->data = (uint8_t*)data;
    pfs->nameData = NULL;
    pfs->dataIsCopy = isCopy;
    
    p = sizeof(PfsHeader);
    
    if (p > length) goto fail;
    
    h = (PfsHeader*)data;
    
    if (memcmp(&h->signature, "PFS ", sizeof(uint32_t)) != 0)
        goto fail;
    
    p = h->offset;
    i = p + sizeof(uint32_t);
    
    if (i > length) goto fail;
    
    n = *(uint32_t*)(data + p);
    p = i;
    
    /* Must have at least one file + the name data entry to have any real content */
    if (n <= 1) goto done;
    
    i = pfs_pow2_greater_or_equal(n);
    
    pfs->entries = (PfsEntry*)malloc(sizeof(PfsEntry) * i);
    if (!pfs->entries) goto oom;
    
    pfs->hashes = (uint32_t*)malloc(sizeof(uint32_t) * i);
    if (!pfs->hashes)
    {
    oom:
        rc = PFS_OUT_OF_MEMORY;
        goto fail;
    }
    
    for (i = 0; i < n; i++)
    {
        PfsFileEntry* src = (PfsFileEntry*)(data + p);
        PfsEntry ent;
        uint32_t memPos, ilen, totalLen, offset;
        
        memPos = p + sizeof(PfsFileEntry);
        
        if (memPos > length) goto fail;
        
        offset = src->offset;
        
        ent.name = NULL;
        ent.nameIsCopy = 0;
        ent.insertedIsCopy = 0;
        ent.crc = src->crc;
        ent.offset = offset;
        ent.inflatedLen = src->inflatedLen;
        ent.deflatedLen = 0;
        ent.inserted = NULL;
        
        p = offset;
        ilen = 0;
        totalLen = src->inflatedLen;
        
        while (ilen < totalLen)
        {
            PfsBlock* block = (PfsBlock*)(data + p);
            
            p += sizeof(PfsBlock);
            
            if (p > length) goto fail;
            
            p += block->deflatedLen;
            
            if (p > length) goto fail;
            
            ilen += block->inflatedLen;
        }
        
        ent.deflatedLen = p - offset;
        
        p = memPos;
        pfs->entries[i] = ent;
    }
    
    qsort(pfs->entries, n, sizeof(PfsEntry), pfs_sort_by_offset);
    
    /* decompress the name data entry */
    pfs->count = n;
    n--;
    rc = pfs_decompress_index(pfs, &nameData, &length, n);
    if (rc) goto fail;
    
    pfs->count = n;
    pfs->nameData = nameData;
    
    if (length < sizeof(uint32_t)) goto fail;
    
    data = nameData;
    n = *(uint32_t*)data;
    p = sizeof(uint32_t);
    
    if (n > pfs->count)
        n = pfs->count;
    
    /* read the file names from the name data entry */
    i = 0;
    while (i < n)
    {
        PfsEntry* ent;
        uint32_t namelen, k;
        char* name;
        
        k = p + sizeof(uint32_t);
        
        if (k > length) goto fail;
        
        namelen = *(uint32_t*)(data + p);
        p = k;
        
        name = (char*)(data + p);
        p += namelen;
        
        if (p > length) goto fail;
        
        if (!foundTraceDotDbg && strcmp(name, "trace.dbg") == 0)
        {
            n--;
            pfs->count = n;
            foundTraceDotDbg = 1;
            continue;
        }
        
        pfs->hashes[i] = pfs_hash(name, namelen - 1);
        ent = &pfs->entries[i];
        ent->name = name;
        
        i++;
    }
    
    pfs->count = n;
done:
    *outPfs = pfs;
    return PFS_OK;
    
fail:
    pfs_close(pfs);
fail_alloc:
    *outPfs = NULL;
    return rc;
}

int pfs_open(PFS** outPfs, const char* path)
{
    FILE* fp;
    uint8_t* data;
    uint32_t length;
    int rc = PFS_NOT_FOUND;
    
    if (!outPfs || !path)
    {
        rc = PFS_MISUSE;
        goto fail;
    }
    
    fp = fopen(path, "rb");
    if (!fp) goto fail;
    
    fseek(fp, 0, SEEK_END);
    length = (uint32_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (length == 0)
        goto fail_file_open;
    
    data = (uint8_t*)malloc(length);
    
    if (!data)
    {
        rc = PFS_OUT_OF_MEMORY;
        goto fail_file_open;
    }
    
    if (fread(data, sizeof(uint8_t), length, fp) != length)
    {
        free(data);
        rc = PFS_FILE_ERROR;
        goto fail_file_open;
    }
    
    rc = pfs_open_impl(outPfs, data, length, 1);
    
fail_file_open:
    fclose(fp);
fail:
    return rc;
}

int pfs_open_from_memory(PFS** outPfs, const void* data, uint32_t length)
{
    uint8_t* copy;
    int rc;
    
    if (!outPfs || !data || !length)
    {
        rc = PFS_MISUSE;
        goto fail;
    }
    
    copy = (uint8_t*)malloc(length);
    
    if (!copy)
    {
        rc = PFS_OUT_OF_MEMORY;
        goto fail;
    }
    
    memcpy(copy, data, length);
    
    rc = pfs_open_impl(outPfs, copy, length, 1);
    
fail:
    return rc;
}

int pfs_open_from_memory_no_copy(PFS** outPfs, const void* data, uint32_t length)
{
    return pfs_open_impl(outPfs, (const uint8_t*)data, length, 0);
}

int pfs_create_new(PFS** outPfs)
{
    PFS* pfs;
    
    if (!outPfs) return PFS_MISUSE;
    
    pfs = (PFS*)malloc(sizeof(PFS));
    
    if (!pfs) return PFS_OUT_OF_MEMORY;
    
    memset(pfs, 0, sizeof(PFS));
    *outPfs = pfs;
    return PFS_OK;
}

void pfs_close(PFS* pfs)
{
    if (pfs)
    {
        PfsEntry* entries = pfs->entries;
        
        if (entries)
        {
            uint32_t n = pfs->count;
            uint32_t i;
            
            for (i = 0; i < n; i++)
            {
                PfsEntry* ent = &entries[i];
                
                if (ent->inserted && ent->insertedIsCopy)
                {
                    free(ent->inserted);
                }
                ent->inserted = NULL;
                
                if (ent->nameIsCopy && ent->name)
                {
                    free(ent->name);
                }
                ent->name = NULL;
            }
            
            free(entries);
            pfs->entries = NULL;
        }
        
        if (pfs->hashes)
        {
            free(pfs->hashes);
            pfs->hashes = NULL;
        }
        
        if (pfs->dataIsCopy && pfs->data)
            free(pfs->data);
        pfs->data = NULL;
        
        if (pfs->nameData)
        {
            free(pfs->nameData);
            pfs->nameData = NULL;
        }
        
        free(pfs);
    }
}

uint32_t pfs_file_count(PFS* pfs)
{
    return (pfs) ? pfs->count : 0;
}

#define PFS_COMPRESS_INPUT_SIZE 8192
#define PFS_COMPRESS_BUFFER_SIZE (PFS_COMPRESS_INPUT_SIZE + 128) /* Overflow space for things that can't be compressed any further... */

static int pfs_compress(PfsEntry* ent, const void* data, uint32_t length)
{
    const uint8_t* ptr = (const uint8_t*)data;
    uint8_t tmp[PFS_COMPRESS_BUFFER_SIZE];
    uint32_t dlen = 0;
    
    ent->insertedIsCopy = 1;
    ent->inflatedLen = length;
    
    while (length > 0)
    {
        uint32_t r = (length < PFS_COMPRESS_INPUT_SIZE) ? length : PFS_COMPRESS_INPUT_SIZE;
        unsigned long dstlen;
        PfsBlock block;
        uint8_t* inserted;
        uint32_t prevlen;
        int rc;
        
        block.inflatedLen = r;
        dstlen = sizeof(tmp);
        
        rc = compress2(tmp, &dstlen, ptr, r, Z_BEST_COMPRESSION);
        
        if (rc != Z_OK) return PFS_COMPRESSION_ERROR;
        
        block.deflatedLen = dstlen;
        
        prevlen = dlen;
        dlen += dstlen + sizeof(block);
        inserted = (uint8_t*)realloc(ent->inserted, dlen);
        if (!inserted) return PFS_OUT_OF_MEMORY;
        ent->inserted = inserted;
        
        inserted += prevlen;
        memcpy(inserted, &block, sizeof(block));
        memcpy(inserted + sizeof(block), tmp, dstlen);
        
        length -= r;
        ptr += r;
    }
    
    ent->deflatedLen = dlen;
    
    return PFS_OK;
}

static int pfs_buf_append(PfsBuf* buf, const void* data, uint32_t length)
{
    uint32_t cur = buf->length;
    uint32_t len = cur + length;
    uint8_t* array = (uint8_t*)realloc(buf->data, len);
    
    if (!array) return PFS_OUT_OF_MEMORY;
    
    memcpy(array + cur, data, length);
    
    buf->data = array;
    buf->length = len;
    
    return PFS_OK;
}

static int pfs_sort_by_crc(const void* va, const void* vb)
{
    const PfsFileEntry* a = (const PfsFileEntry*)va;
    const PfsFileEntry* b = (const PfsFileEntry*)vb;
    
    return (a->crc < b->crc) ? -1 : 1;
}

int pfs_write_to_disk(PFS* pfs, const char* path)
{
    FILE* fp;
    PfsHeader header;
    PfsFileEntry fent;
    PfsFileEntry* fileEntries;
    PfsBuf dataBuf;
    PfsBuf nameBuf;
    PfsEntry nameBufCompressed;
    uint32_t p, n, i, c;
    uint8_t* pfsData = pfs->data;
    int rc = PFS_OK;
    
    if (!pfs || !path || *path == 0)
        return PFS_MISUSE;
    
    memcpy(&header.signature, "PFS ", sizeof(header.signature));
    header.unknown = 131072; /* Always this */
    
    p = sizeof(PfsHeader);
    c = pfs->count;
    
    fileEntries = (PfsFileEntry*)malloc(sizeof(PfsFileEntry) * (c + 1));
    if (!fileEntries) return PFS_OUT_OF_MEMORY;
    
    dataBuf.data = NULL;
    dataBuf.length = 0;
    nameBuf.data = NULL;
    nameBuf.length = 0;
    nameBufCompressed.inserted = NULL;
    
    rc = pfs_buf_append(&nameBuf, &c, sizeof(c));
    if (rc) goto abort;
    
    for (i = 0; i < c; i++)
    {
        PfsEntry* ent = &pfs->entries[i];
        uint8_t* fileData;
        
        n = strlen(ent->name) + 1;
        
        rc = pfs_buf_append(&nameBuf, &n, sizeof(n));
        if (rc) goto abort;
        
        rc = pfs_buf_append(&nameBuf, ent->name, n);
        if (rc) goto abort;
        
        fent.crc = ent->crc;
        fent.offset = p;
        fent.inflatedLen = ent->inflatedLen;
        
        fileEntries[i] = fent;
        
        fileData = (ent->inserted) ? ent->inserted : (pfsData + ent->offset);
        
        rc = pfs_buf_append(&dataBuf, fileData, ent->deflatedLen);
        if (rc) goto abort;
        
        p += ent->deflatedLen;
    }
    
    /* Names entry */
    fent.crc = 0x61580ac9; /* Always this */
    fent.offset = p;
    fent.inflatedLen = nameBuf.length;
    
    fileEntries[c] = fent;
    qsort(fileEntries, c + 1, sizeof(PfsFileEntry), pfs_sort_by_crc);
    
    rc = pfs_compress(&nameBufCompressed, nameBuf.data, nameBuf.length);
    if (rc) goto abort;
    
    p += nameBufCompressed.deflatedLen;
    
    header.offset = p;
    rc = PFS_FILE_ERROR;
    fp = fopen(path, "wb+");
    if (!fp) goto abort;

    /* Header */
    if (fwrite(&header, sizeof(uint8_t), sizeof(header), fp) != sizeof(header))
        goto close_file;
    
    /* Compressed entries */
    n = dataBuf.length;
    if (fwrite(dataBuf.data, sizeof(uint8_t), n, fp) != n)
        goto close_file;
    
    /* Compressed names entry */
    if (fwrite(nameBufCompressed.inserted, sizeof(uint8_t), nameBufCompressed.deflatedLen, fp) != nameBufCompressed.deflatedLen)
        goto close_file;
    
    /* Offset and CRC list in order of CRC */
    n = c + 1;
    if (fwrite(&n, sizeof(uint8_t), sizeof(n), fp) != sizeof(n))
        goto close_file;
    
    for (i = 0; i < n; i++)
    {
        PfsFileEntry* ent = &fileEntries[i];
        
        if (fwrite(ent, sizeof(uint8_t), sizeof(PfsFileEntry), fp) != sizeof(PfsFileEntry))
            goto close_file;
    }
    
    rc = PFS_OK;
    
close_file:
    fclose(fp);
    
abort:
    pfs_free_if_exists(fileEntries);
    pfs_free_if_exists(dataBuf.data);
    pfs_free_if_exists(nameBuf.data);
    pfs_free_if_exists(nameBufCompressed.inserted);
    
    return rc;
}

static int pfs_file_index_by_name(PFS* pfs, const char* name)
{
    uint32_t* hashes;
    uint32_t hash, n, i;
    
    if (!pfs || !name)
        return PFS_MISUSE;
    
    hash = pfs_hash(name, strlen(name));
    n = pfs->count;
    hashes = pfs->hashes;
    
    for (i = 0; i < n; i++)
    {
        if (hashes[i] == hash)
        {
            PfsEntry* ent = &pfs->entries[i];
            
            if (strcmp(ent->name, name) == 0)
                return (int)i;
        }
    }
    
    return PFS_NOT_FOUND;
}

static PfsEntry* pfs_get_entry(PFS* pfs, const char* name)
{
    int index = pfs_file_index_by_name(pfs, name);
    return (index >= 0) ? &pfs->entries[index] : NULL;
}

static PfsEntry* pfs_get_or_append_entry(PFS* pfs, const char* name)
{
    int index = pfs_file_index_by_name(pfs, name);
    PfsEntry* ent;
    int namelen;
    
    if (index >= 0)
        return &pfs->entries[index];
    
    index = (int)pfs->count;
    
    if (pfs_is_pow2_or_zero(index))
    {
        int cap = (index == 0) ? 1 : index * 2;
        PfsEntry* entries;
        uint32_t* hashes;
        
        entries = (PfsEntry*)realloc(pfs->entries, sizeof(PfsEntry) * cap);
        if (!entries) return NULL;
        pfs->entries = entries;
        
        hashes = (uint32_t*)realloc(pfs->hashes, sizeof(uint32_t) * cap);
        if (!hashes) return NULL;
        pfs->hashes = hashes;
    }
    
    namelen = strlen(name);
    pfs->hashes[index] = pfs_hash(name, (uint32_t)namelen);
    
    ent = &pfs->entries[index];
    ent->name = (char*)malloc(namelen + 1);
    if (!ent->name) return NULL;
    memcpy(ent->name, name, namelen);
    ent->name[namelen] = 0;
    
    ent->nameIsCopy = 1;
    ent->insertedIsCopy = 0;
    ent->crc = pfs_crc(name, namelen + 1); /* CRC includes the null terminator */
    ent->offset = 0;
    ent->inflatedLen = 0;
    ent->deflatedLen = 0;
    ent->inserted = NULL;
    
    pfs->count = index + 1;
    
    return ent;
}

int pfs_insert_file(PFS* pfs, const char* name, const void* data, uint32_t length)
{
    PfsEntry* ent;
    
    if (!pfs || !name || *name == 0 || !data || !length)
        return PFS_MISUSE;
    
    ent = pfs_get_or_append_entry(pfs, name);
    if (!ent) return PFS_OUT_OF_MEMORY;
    
    if (ent->inserted && ent->insertedIsCopy)
    {
        free(ent->inserted);
        ent->inserted = NULL;
    }
    
    return pfs_compress(ent, data, length);
}

static int pfs_dupe_impl(PFS* dst, PFS* src, const char* name, int isCopy)
{
    PfsEntry* ent;
    PfsEntry* srcEnt;
    uint8_t* data;
    
    if (!dst || !src || !name || *name == 0)
        return PFS_MISUSE;
    
    srcEnt = pfs_get_entry(src, name);
    if (!srcEnt) return PFS_NOT_FOUND;
    
    ent = pfs_get_or_append_entry(dst, name);
    if (!ent) return PFS_OUT_OF_MEMORY;
    
    if (ent->inserted && ent->insertedIsCopy)
    {
        free(ent->inserted);
        ent->inserted = NULL;
    }
    
    ent->inflatedLen = srcEnt->inflatedLen;
    ent->deflatedLen = srcEnt->deflatedLen;
    
    data = (srcEnt->inserted) ? srcEnt->inserted : (src->data + srcEnt->offset);
    
    if (isCopy)
    {
        uint8_t* copy = (uint8_t*)malloc(srcEnt->deflatedLen);
        
        if (!copy) return PFS_OUT_OF_MEMORY;
        
        memcpy(copy, data, srcEnt->deflatedLen);
        
        ent->insertedIsCopy = 1;
        ent->inserted = copy;
    }
    else
    {
        ent->insertedIsCopy = 0;
        ent->inserted = data;
    }
    
    return PFS_OK;
}

int pfs_fast_file_duplicate(PFS* dst, PFS* src, const char* name)
{
    return pfs_dupe_impl(dst, src, name, 1);
}

int pfs_fast_file_duplicate_no_copy(PFS* dst, PFS* src, const char* name)
{
    return pfs_dupe_impl(dst, src, name, 0);
}

int pfs_remove_file(PFS* pfs, const char* name)
{
    int index;
    PfsEntry* ent;
    uint32_t n;
    
    if (!pfs || !name)
        return PFS_MISUSE;
    
    index = pfs_file_index_by_name(pfs, name);
    if (index < 0) return index;
    
    ent = &pfs->entries[index];
    
    if (ent->name && ent->nameIsCopy)
    {
        free(ent->name);
        ent->name = NULL;
    }
    
    if (ent->inserted)
    {
        free(ent->inserted);
        ent->inserted = NULL;
    }
    
    /* Swap and pop */
    n = pfs->count - 1;
    pfs->count = n;
    
    pfs->entries[index] = pfs->entries[n];
    pfs->hashes[index] = pfs->hashes[n];
    
    return PFS_OK;
}

const char* pfs_file_name(PFS* pfs, uint32_t index)
{
    const char* name = NULL;
    
    if (pfs && index < pfs->count)
        name = pfs->entries[index].name;
    
    return name;
}

uint32_t pfs_file_size(PFS* pfs, uint32_t index)
{
    uint32_t size = 0;
    
    if (pfs && index < pfs->count)
        size = pfs->entries[index].inflatedLen;
    
    return size;
}

uint32_t pfs_file_size_compressed(PFS* pfs, uint32_t index)
{
    uint32_t size = 0;
    
    if (pfs && index < pfs->count)
        size = pfs->entries[index].deflatedLen;
    
    return size;
}

int pfs_file_data(PFS* pfs, const char* name, uint8_t** data, uint32_t* length)
{
    int index;
    
    if (!pfs || !name || !data || !length)
        return PFS_MISUSE;
    
    index = pfs_file_index_by_name(pfs, name);
    if (index < 0) return index;
    
    return pfs_decompress_index(pfs, data, length, (uint32_t)index);
}
