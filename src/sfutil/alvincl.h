#ifdef __APPLE__
#include <OpenCL/opcncl.h>
#else
#include <CL/opencl.h>
#endif

typedef struct _device_struct{
    cl_device_id id;
    cl_device_type type;
    cl_command_queue command_queue;
    cl_char *name;
} device_struct;

typedef struct _platform_struct{
    cl_platform_id id;
    cl_uint num_devices;
    device_struct *devices;
    cl_uint num_mems;
    cl_mem *mem_objects;
    cl_context context;
    cl_program program;
    cl_kernel kernel;
    cl_char *name;
    struct _platform_struct *head;
    struct _platform_struct *next;
} platform_struct;

typedef struct _alvincl_struct{
    cl_uint pdex;
    cl_uint ddex;
    cl_uint num_platforms;
    platform_struct *platforms;
} alvincl_struct;

cl_ulong timeNanos();
void cleanUp(alvincl_struct *acls);
inline void checkResult(alvincl_struct *acls, cl_int ret_num, const char *name);
inline void checkPointer(alvincl_struct *acls, void *ptr, const char *name);
void getPlatforms(alvincl_struct *acls);
void getDevices(alvincl_struct *acls);
void setDevice(alvincl_struct *acls, cl_device_type device_type);
void createContext(alvincl_struct *acls);
void createProgram(alvincl_struct *acls, const char* file_name);
void createCommandQueue(alvincl_struct *acls, cl_command_queue_properties properties);
void initMemoryObjects(alvincl_struct *acls, cl_uint num_mems);
