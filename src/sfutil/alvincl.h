#ifndef __ALVINCL_H
#define __ALVINCL_H

#ifdef __APPLE__
#include <OpenCL/opcncl.h>
#else
#include <CL/opencl.h>
#endif

typedef struct _acl_device_struct{
    cl_char *name;
    cl_device_id id;
    cl_device_type type;
    cl_command_queue command_queue;
} acl_device_struct;

typedef struct _acl_platform_struct{
    cl_char *name;
    cl_platform_id id;
    cl_uint num_devices;
    acl_device_struct *devices;
    cl_uint num_mems;
    cl_mem *mem_objects;
    cl_context context;
    cl_program program;
    cl_kernel kernel;
    struct _acl_platform_struct *head;
    struct _acl_platform_struct *next;
} acl_platform_struct;

typedef struct _acl_struct{
    acl_platform_struct *platform;
    acl_device_struct *device;
    cl_uint work_dim;
    size_t *global_work_size;
    size_t *local_work_size;
} acl_struct;

cl_ulong aclTimeNanos();
void aclCleanUp(acl_struct *acl_s);
inline void aclCheckResult(acl_struct *acl_s, cl_int ret_num, const char *name);
inline void aclCheckPointer(acl_struct *acl_s, void *ptr, const char *name);
void aclGetPlatforms(acl_struct *acl_s);
void aclGetDevices(acl_struct *acl_s);
void aclSetDevice(acl_struct *acl_s, cl_device_type device_type);
void aclCreateContext(acl_struct *acl_s);
void aclCreateProgram(acl_struct *acl_s, const char *file_name);
void aclCreateKernel(acl_struct *acl_s, const char *kernel_name);
void aclCreateCommandQueue(acl_struct *acl_s, cl_command_queue_properties properties);
void aclInitMemoryObjects(acl_struct *acl_s, cl_uint num_mems);

#endif /* __ALVINCL_H */
