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

void cleanUp(platform_struct *platforms);
inline void checkResult(platform_struct *platforms, cl_int ret_num, const char *name);
inline void checkPointer(platform_struct *platforms, void *ptr, const char *name);
platform_struct* getPlatforms(cl_uint *num_platforms);
void getDevices(platform_struct *platforms);
cl_uint2 setDevice(platform_struct *platforms, cl_device_type device_type);
void createContext(platform_struct *platforms, cl_uint2 ddex);
void createProgram(platform_struct *platforms, cl_uint2 ddex, const char* file_name);
void createCommandQueue(platform_struct *platforms, cl_uint2 ddex, cl_command_queue_properties properties);
void initMemoryObjects(platform_struct *platforms, cl_uint2 ddex, cl_uint num_mems);
