
#ifndef PFS_H
#define PFS_H

#include <stdint.h>

#define PFS_OK 0
#define PFS_NOT_FOUND -1
#define PFS_OUT_OF_MEMORY -2
#define PFS_COMPRESSION_ERROR -3
#define PFS_FILE_ERROR -4
#define PFS_MISUSE -5
#define PFS_CORRUPTED -6
#define PFS_OUT_OF_BOUNDS -7

#ifdef _WIN32
# ifdef __cplusplus
#  define PFS_API extern "C" __declspec(dllexport)
# else
#  define PFS_API __declspec(dllexport)
# endif
#else
# define PFS_API extern
#endif

typedef struct PFS PFS;

PFS_API int pfs_open(PFS** pfs, const char* path);
PFS_API int pfs_open_from_memory(PFS** pfs, const void* data, uint32_t length);
PFS_API int pfs_open_from_memory_no_copy(PFS** pfs, const void* data, uint32_t length);
PFS_API int pfs_create_new(PFS** pfs);
PFS_API void pfs_close(PFS* pfs);

PFS_API uint32_t pfs_file_count(PFS* pfs);

PFS_API int pfs_write_to_disk(PFS* pfs, const char* path);

PFS_API int pfs_insert_file(PFS* pfs, const char* name, const void* data, uint32_t length);
PFS_API int pfs_fast_file_duplicate(PFS* dst, PFS* src, const char* name);
PFS_API int pfs_fast_file_duplicate_no_copy(PFS* dst, PFS* src, const char* name);

PFS_API int pfs_remove_file(PFS* pfs, const char* name);

PFS_API const char* pfs_file_name(PFS* pfs, uint32_t index);
PFS_API uint32_t pfs_file_size(PFS* pfs, uint32_t index);
PFS_API uint32_t pfs_file_size_compressed(PFS* pfs, uint32_t index);

PFS_API int pfs_file_data(PFS* pfs, const char* name, uint8_t** data, uint32_t* length);

#endif/*PFS_H*/
