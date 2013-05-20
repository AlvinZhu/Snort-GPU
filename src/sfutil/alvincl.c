#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "alvincl.h"

static const char* aclErrorString(cl_int ret_num) {
    static const char* errorstring[] = {
        "cl_success",
        "cl_device_not_found",
        "cl_device_not_available",
        "cl_compiler_not_available",
        "cl_mem_object_allocation_failure",
        "cl_out_of_resources",
        "cl_out_of_host_memory",
        "cl_profiling_info_not_available",
        "cl_mem_copy_overlap",
        "cl_image_format_mismatch",
        "cl_image_format_not_supported",
        "cl_build_program_failure",
        "cl_map_failure",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "cl_invalid_value",
        "cl_invalid_device_type",
        "cl_invalid_platform",
        "cl_invalid_device",
        "cl_invalid_context",
        "cl_invalid_queue_properties",
        "cl_invalid_command_queue",
        "cl_invalid_host_ptr",
        "cl_invalid_mem_object",
        "cl_invalid_image_format_descriptor",
        "cl_invalid_image_size",
        "cl_invalid_sampler",
        "cl_invalid_binary",
        "cl_invalid_build_options",
        "cl_invalid_program",
        "cl_invalid_program_executable",
        "cl_invalid_kernel_name",
        "cl_invalid_kernel_definition",
        "cl_invalid_kernel",
        "cl_invalid_arg_index",
        "cl_invalid_arg_value",
        "cl_invalid_arg_size",
        "cl_invalid_kernel_args",
        "cl_invalid_work_dimension",
        "cl_invalid_work_group_size",
        "cl_invalid_work_item_size",
        "cl_invalid_global_offset",
        "cl_invalid_event_wait_list",
        "cl_invalid_event",
        "cl_invalid_operation",
        "cl_invalid_gl_object",
        "cl_invalid_buffer_size",
        "cl_invalid_mip_level",
        "cl_invalid_global_work_size",
    };

    const int errorcount = sizeof(errorstring) / sizeof(errorstring[0]);

    const int index = -ret_num;

    return (index >= 0 && index < errorcount) ? errorstring[index] : "";

}

cl_ulong aclTimeNanos(){
#ifdef linux
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (unsigned long long) tp.tv_sec * (1000ULL * 1000ULL * 1000ULL) + (unsigned long long) tp.tv_nsec;
#else
    LARGE_INTEGER current;
    QueryPerformanceCounter(&current);
    return (unsigned long long)((double)current.QuadPart / m_ticksPerSec * 1e9);
#endif
}

void aclCleanUp(acl_struct *acl_s) {

    acl_platform_struct *platforms = NULL;
    acl_platform_struct *ptr = NULL;

    cl_uint i;

    if(acl_s->platform != NULL){
        platforms = acl_s->platform->head;
        ptr = platforms;
        while(ptr != NULL){
            if (ptr->num_mems != 0){
                for (i = 0; i < ptr->num_mems; i++){
                    if (ptr->mem_objects[i] != 0)
                        clReleaseMemObject(ptr->mem_objects[i]);
                }
                free((void*)ptr->mem_objects);
                //ptr->mem_objects = NULL;
                //ptr->num_mems = 0;
            }

            if (ptr->num_devices != 0){
                for (i = 0; i < ptr->num_devices; i++){
                    if(ptr->devices[i].name != NULL)
                        free((void*)ptr->devices[i].name);
                    if (ptr->devices[i].command_queue != 0)
                        clReleaseCommandQueue(ptr->devices[i].command_queue);
                    //ptr->devices[i].command_queues = NULL;
                }
                free((void*)ptr->devices);
                //ptr->devices = NULL;
                //ptr->num_devices = 0;
            }

            if (ptr->kernel != 0)
                clReleaseKernel(ptr->kernel);

            if (ptr->program != 0)
                clReleaseProgram(ptr->program);

            if (ptr->context != 0)
                clReleaseContext(ptr->context);

            if (ptr->name != NULL)
                free((void*)ptr->name);

            ptr = ptr->next;
        }
        free((void*)platforms);
    }

    acl_s->platform = NULL;
    acl_s->device = NULL;
    acl_s->work_dim = 0;
    if(acl_s->global_work_size != NULL){
        free((void*)acl_s->global_work_size);
        acl_s->global_work_size = NULL;
    }
    if(acl_s->local_work_size != NULL){
        free((void*)acl_s->local_work_size);
        acl_s->local_work_size = NULL;
    }

}

inline void aclCheckResult(acl_struct *acl_s, cl_int ret_num, const char *name) {
    if (ret_num != 0) {
        //fprintf(stderr, "ERROR: %s (%d)\n", name, ret_num);
        fprintf(stderr, "ERROR: %s (%s)\n", name, aclErrorString(ret_num));
        fflush(stderr);
        aclCleanUp(acl_s);
        exit(EXIT_FAILURE);
    }
}

inline void aclCheckPointer(acl_struct *acl_s, void *ptr, const char *name) {
    if (ptr == NULL) {
        fprintf(stderr, "ERROR: %s (NULL)\n", name);
        fflush(stderr);
        aclCleanUp(acl_s);
        exit(EXIT_FAILURE);
    }
}

void aclGetPlatforms(acl_struct *acl_s) {

    acl_platform_struct *platforms = NULL;
    cl_uint num_platforms = 0;
    cl_platform_id *temp_platforms = NULL;
    size_t size_name;
    cl_int ret_num;
    cl_uint i;

    if (acl_s == NULL){
        fprintf(stderr, "ERROR: aclGetPlatforms(NULL!!!)");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }else if(acl_s->platform != NULL){
        return;
    }

    ret_num = clGetPlatformIDs(0, (cl_platform_id *) NULL, &num_platforms);
    aclCheckResult(acl_s, ret_num, "clGetPlatformIDs(num_platforms)");

    if (num_platforms == 0){
        fprintf(stderr, "num_platforms = 0\n");
        fflush(stderr);
        aclCleanUp(acl_s);
        exit(EXIT_FAILURE);
    }

    platforms = (acl_platform_struct *) calloc(num_platforms, sizeof(acl_platform_struct));
    aclCheckPointer(acl_s, platforms, "platforms");

    temp_platforms = (cl_platform_id *) malloc(num_platforms * sizeof(cl_platform_id));
    aclCheckPointer(acl_s, temp_platforms, "temp_platforms");

    ret_num = clGetPlatformIDs(num_platforms, temp_platforms, (cl_uint *) NULL);
    aclCheckResult(acl_s, ret_num, "clGetPlatformIDs(platforms)");

    for (i = 0; i < num_platforms; i++) {
        platforms[i].id = temp_platforms[i];

        ret_num = clGetPlatformInfo(platforms[i].id, CL_PLATFORM_NAME, (size_t) 0, NULL, (size_t *) &size_name);
        aclCheckResult(acl_s, ret_num, "clGetPlatformInfo(size_name)");

        platforms[i].name = (cl_char *) malloc(size_name + 1);
        aclCheckPointer(acl_s, platforms[i].name, "platform.name");

        ret_num = clGetPlatformInfo(platforms[i].id, CL_PLATFORM_NAME, size_name, platforms[i].name, (size_t *) NULL);
        aclCheckResult(acl_s, ret_num, "clGetPlatformInfo(platform.name)");

        platforms[i].name[size_name] = '\0';

        platforms[i].head = platforms;
        if (i != num_platforms -1 ){
            platforms[i].next = &platforms[i+1];
        }
        else{
            platforms[i].next = NULL;
        }
    }
    free(temp_platforms);
    acl_s->platform = platforms;
}

void aclGetDevices(acl_struct *acl_s) {

    acl_platform_struct *platforms = NULL;
    cl_device_id *tmp_devices = NULL;
    size_t size_name;
    cl_int ret_num;
    cl_uint i;

    if (acl_s == NULL){
        fprintf(stderr, "ERROR: aclGetDevices(NULL!!!)");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }else if(acl_s->platform == NULL){
        fprintf(stderr, "ERROR: aclGetDevices() platform == NULL");
        fflush(stderr);
        aclCleanUp(acl_s);
        exit(EXIT_FAILURE);
    }else if(acl_s->device != NULL){
        return;
    }

    platforms = acl_s->platform->head;

    while(platforms != NULL){
        ret_num = clGetDeviceIDs(platforms->id, CL_DEVICE_TYPE_ALL, 0, NULL, (cl_uint *) &(platforms->num_devices));
        aclCheckResult(acl_s, ret_num, "clGetDeviceIDs(num_devices)");

        platforms->devices = (acl_device_struct *) calloc(platforms->num_devices, sizeof(acl_device_struct));
        aclCheckPointer(acl_s, platforms->devices, "platform.devices");

        tmp_devices = (cl_device_id *) malloc(platforms->num_devices * sizeof(cl_device_id));
        aclCheckPointer(acl_s, tmp_devices, "tmp_devices");

        ret_num = clGetDeviceIDs(platforms->id, CL_DEVICE_TYPE_ALL, platforms->num_devices, tmp_devices, NULL);
        aclCheckResult(acl_s, ret_num, "clGetDeviceIDs(platform.devices)");

        for (i = 0; i < platforms->num_devices; i++) {
            platforms->devices[i].id = tmp_devices[i];
            ret_num = clGetDeviceInfo(platforms->devices[i].id, CL_DEVICE_TYPE, sizeof(cl_device_type), &platforms->devices[i].type, NULL);
            aclCheckResult(acl_s, ret_num, "clGetDeviceInfo(platform.device.type)");

            ret_num = clGetDeviceInfo(platforms->devices[i].id, CL_DEVICE_NAME, (size_t) 0, NULL, (size_t *) &size_name);
            aclCheckResult(acl_s, ret_num, "clGetDeviceInfo(size_name)");

            platforms->devices[i].name = (cl_char *) malloc(size_name + 1);
            aclCheckPointer(acl_s, platforms->devices[i].name, "platform.device.name");

            ret_num = clGetDeviceInfo(platforms->devices[i].id, CL_DEVICE_NAME, size_name, platforms->devices[i].name, (size_t *) NULL);
            aclCheckResult(acl_s, ret_num, "clGetDeviceInfo(platform.device.name)");

            platforms->devices[i].name[size_name] = '\0';	 
        }
        free(tmp_devices);

        platforms = platforms->next;
    }

    acl_s->device = acl_s->platform->devices;
}

void aclSetDevice(acl_struct *acl_s, cl_device_type device_type) {

    acl_platform_struct *platforms = NULL;
    acl_platform_struct *ptr = NULL;
    int device_found;
    cl_uint i;

    if (acl_s == NULL){
        fprintf(stderr, "ERROR: aclSetDevices(NULL!!!)");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }else if(acl_s->platform == NULL || acl_s->device == NULL){
        fprintf(stderr, "ERROR: aclSetDevices() platform or device == NULL");
        fflush(stderr);
        aclCleanUp(acl_s);
        exit(EXIT_FAILURE);
    }

    ptr = platforms;
    platforms = acl_s->platform->head;
    device_found = 0;

    if (device_type == CL_DEVICE_TYPE_DEFAULT) {
        ptr = platforms;
        while(ptr != NULL){
            for (i = 0; i < ptr->num_devices; i++) {
                if (ptr->devices[i].type == CL_DEVICE_TYPE_ACCELERATOR) {
                    device_found = 1;
                    acl_s->platform = ptr;
                    acl_s->device = &(ptr->devices[i]);
                    break;
                }
            }
            if(device_found == 1)
                break;
            ptr = ptr->next;
        }
        if (device_found == 0) {
            ptr = platforms;
            while(ptr != NULL){
                for (i = 0; i < ptr->num_devices; i++) {
                    if (ptr->devices[i].type == CL_DEVICE_TYPE_GPU) {
                        device_found = 1;
                        acl_s->platform = ptr;
                        acl_s->device = &(ptr->devices[i]);
                        break;
                    }
                }
                if(device_found == 1)
                    break;
                ptr = ptr->next;
            }
            if (device_found == 0) {
                ptr = platforms;
                while(ptr != NULL){
                    for (i = 0; i < ptr->num_devices; i++) {
                        if (ptr->devices[i].type == CL_DEVICE_TYPE_CPU) {
                            device_found = 1;
                            acl_s->platform = ptr;
                            acl_s->device = &(ptr->devices[i]);
                            break;
                        }
                    }
                    if(device_found == 1)
                        break;
                    ptr = ptr->next;
                }
            }
        }
    }
    else {
        ptr = platforms;
        while(ptr != NULL){
            for (i = 0; i < ptr->num_devices; i++) {
                if (ptr->devices[i].type == device_type) {
                    device_found = 1;
                    acl_s->platform = ptr;
                    acl_s->device = &(ptr->devices[i]);
                    break;
                }
            }
            if(device_found == 1)
                break;
            ptr = ptr->next;
        }
    }
    if (device_found == 0) {
        fprintf(stderr, "ERROR: No device of the requested type were found.  Leaving...\n"); 
        fflush(stderr);
        aclCleanUp(acl_s);
        exit(EXIT_FAILURE);
    }

}

void aclCreateContext(acl_struct *acl_s) {

    cl_context_properties properties[3];
    cl_int ret_num;

    if (acl_s == NULL){
        fprintf(stderr, "ERROR: aclCreateContext(NULL!!!)");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }else if(acl_s->platform == NULL || acl_s->device == NULL){
        fprintf(stderr, "ERROR: aclCreateContext() platform or device == NULL");
        fflush(stderr);
        aclCleanUp(acl_s);
        exit(EXIT_FAILURE);
    }


    properties[0] = CL_CONTEXT_PLATFORM;
    properties[1] = (const cl_context_properties) acl_s->platform->id;
    properties[2] = 0;
    acl_s->platform->context = clCreateContext((const cl_context_properties *) properties, 1, &(acl_s->device->id), NULL, NULL, &ret_num);
    aclCheckResult(acl_s, ret_num, "clCreateContext");
}

void aclCreateProgram(acl_struct *acl_s, const char* file_name) {

    cl_int ret_num;
    char* source = NULL;

    struct stat statbuf;

    FILE *fh = fopen(file_name, "r");
    if (fh == 0) {
        fprintf(stderr, "ERROR: Couldn't open %s\n", file_name);
        fflush(stderr);
        aclCleanUp(acl_s);
        exit(EXIT_FAILURE);
    }

    stat(file_name, &statbuf);
    source = (char *) malloc(statbuf.st_size + 1);
    aclCheckPointer(acl_s, source, "source");

    ret_num = fread(source, statbuf.st_size, 1, fh);
    if (ret_num != 1){
        fprintf(stderr, "ERROR: fread (%d)\n", ret_num);
        fflush(stderr);
        aclCleanUp(acl_s);
        exit(EXIT_FAILURE);
    }

    source[statbuf.st_size] = '\0';

    acl_s->platform->program = clCreateProgramWithSource(acl_s->platform->context, 1, (const char **) &source, NULL, &ret_num);
    aclCheckResult(acl_s, ret_num, "clCreateProgramWithSource");

    ret_num = clBuildProgram(acl_s->platform->program, 1, &(acl_s->device->id), "", NULL, NULL);
    if (ret_num != CL_SUCCESS)
    {
        // Determine the reason for the error
        char buildLog[16384];
        clGetProgramBuildInfo(acl_s->platform->program, acl_s->device->id, CL_PROGRAM_BUILD_LOG, sizeof(buildLog), buildLog, NULL);

        fprintf(stderr, "Error in kernel:\n");
        fprintf(stderr, "%s\n", buildLog);
    }
    aclCheckResult(acl_s, ret_num, "clBuildProgram");

    free(source);
}

void aclCreateKernel(acl_struct *acl_s, const char *kernel_name){
    cl_int ret_num;

    acl_s->platform->kernel = clCreateKernel(acl_s->platform->program, kernel_name, &ret_num);
    aclCheckResult(acl_s, ret_num, "clCreateKernel");
}

void aclCreateCommandQueue(acl_struct *acl_s, cl_command_queue_properties properties) {

    cl_int ret_num;

    acl_s->device->command_queue = clCreateCommandQueue(acl_s->platform->context, acl_s->device->id, properties, &ret_num);
    aclCheckResult(acl_s, ret_num, "clCreateCommandQueue");

}

void aclInitMemoryObjects(acl_struct *acl_s, cl_uint num_mems) {

    acl_s->platform->mem_objects = (cl_mem *) calloc(num_mems, sizeof(cl_mem));
    aclCheckPointer(acl_s, acl_s->platform->mem_objects, "platform.mem_objects");
    acl_s->platform->num_mems = num_mems;
}

#ifdef ALVINCL_MAIN

int main(int argc, char *argv[]) {

    acl_struct *acl_s;

    aclGetPlatforms(acl_s);
    aclGetDevices(acl_s);
    aclSetDevice(acl_s);
    aclCreateContext(acl_s);
    aclCreateProgram(acl_s, "kernel.cl");
    aclCreateKernel(cl_s, "kernel_1");
    aclCreateCommandQueue(acl_s, CL_QUEUE_PROFILING_ENABLE);
    aclInitMemoryObjects(cl_s, 3);


    return 0;
}

#endif //ALVINCL_MAIN


