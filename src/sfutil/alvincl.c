#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alvincl.h"

void cleanUp(platform_struct *platforms) {
	cl_uint i;
	platform_struct *ptr = NULL;
		
	platforms = platforms->head;
	
	ptr = platforms;
	while(ptr != NULL){
		if (ptr->num_mems != 0){
			for (i = 0; i < ptr->num_mems; i++){
				if (ptr->mem_objects[i] != 0){
					clReleaseMemObject(ptr->mem_objects[i]);
				}
			}
			free((void*)ptr->mem_objects);
		}
		if (ptr->num_devices != 0){
			for (i = 0; i < ptr->num_devices; i++){
				if (ptr->devices[i].command_queue != 0){
					clReleaseCommandQueue(ptr->devices[i].command_queue);

				}
				free((void*)ptr->devices[i].name);
			}
			free((void*)ptr->devices);
		}		
		if (ptr->kernel != 0){
			clReleaseKernel(ptr->kernel);
		}
		if (ptr->program != 0){
			clReleaseProgram(ptr->program);
		}
		if (ptr->context != 0){
			clReleaseContext(ptr->context);
		}
		free((void*)ptr->name);
		ptr = ptr->next;
	}
	if (platforms != NULL) {
		free((void*)platforms);	
	}	
}

const char* oclErrorString(cl_int error) {
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
    
    const int index = -error;
    
    return (index >= 0 && index < errorcount) ? errorstring[index] : "";
     
}

inline void checkResult(platform_struct *platforms, cl_int ret_num, const char *name) {
	if (ret_num != 0) {
		fprintf(stderr, "ERROR: %s (%d)\n", name, ret_num);
		//fprintf(stderr, "ERROR: %s (%s)\n", name, oclErrorString(ciErrNum));
		cleanUp(platforms);
		fflush(stderr);
		exit(EXIT_FAILURE);
	}
}

inline void checkPointer(platform_struct *platforms, void *ptr, const char *name) {
	if (ptr == NULL) {
		fprintf(stderr, "ERROR: %s (NULL)\n", name);
		cleanUp(platforms);
		fflush(stderr);
		exit(EXIT_FAILURE);
	}
}

platform_struct* getPlatforms(cl_uint* num_platforms) {
	platform_struct *platforms = NULL;

	cl_platform_id *temp_platforms = NULL;
	size_t size_name;
	cl_int ret_num;
	cl_uint i;
		
	ret_num = clGetPlatformIDs(0, (cl_platform_id *) NULL, num_platforms);
	checkResult(platforms, ret_num, "clGetPlatformIDs(num_platforms)");
	
	if (*num_platforms == 0){
		fprintf(stderr, "num_platforms = 0\n");
		fflush(stderr);
		exit(EXIT_FAILURE);
	}
	
	platforms = (platform_struct *) calloc(*num_platforms, sizeof(platform_struct));
	checkPointer(platforms, platforms, "platforms");
	
	temp_platforms = (cl_platform_id *) malloc(*num_platforms * sizeof(cl_platform_id));
	checkPointer(platforms, temp_platforms, "temp_platforms");
	
	ret_num = clGetPlatformIDs(*num_platforms, temp_platforms, (cl_uint *) NULL);
	checkResult(platforms, ret_num, "clGetPlatformIDs(platforms)");
	
	for (i = 0; i < *num_platforms; i++) {
		platforms[i].id = temp_platforms[i];
		
		ret_num = clGetPlatformInfo(platforms[i].id, CL_PLATFORM_NAME, (size_t) 0, NULL, (size_t *) &size_name);
		checkResult(platforms, ret_num, "clGetPlatformInfo(size_name)");
		
		platforms[i].name = (cl_char *) malloc(size_name + 1);
		checkPointer(platforms, platforms[i].name, "platform.name");
		
		ret_num = clGetPlatformInfo(platforms[i].id, CL_PLATFORM_NAME, size_name, platforms[i].name, (size_t *) NULL);
		checkResult(platforms, ret_num, "clGetPlatformInfo(platform.name)");
		
		platforms[i].name[size_name] = '\0';
		
		platforms[i].head = platforms;
		if (i != *num_platforms -1 ){
			platforms[i].next = &platforms[i+1];
		}
		else{
			platforms[i].next = NULL;
		}
	}
	free(temp_platforms);
	return platforms;
}

void getDevices(platform_struct *platforms) {
	cl_device_id *tmp_devices = NULL;
	size_t size_name;
	cl_int ret_num;
	cl_uint i;

	while(platforms != NULL){
		ret_num = clGetDeviceIDs(platforms->id, CL_DEVICE_TYPE_ALL, 0, NULL, (cl_uint *) &(platforms->num_devices));
		checkResult(platforms, ret_num, "clGetDeviceIDs(num_devices)");
		
		platforms->devices = (device_struct *) calloc(platforms->num_devices, sizeof(device_struct));
		checkPointer(platforms, platforms->devices, "platform.devices");

		tmp_devices = (cl_device_id *) malloc(platforms->num_devices * sizeof(cl_device_id));
		checkPointer(platforms, tmp_devices, "tmp_devices");

		ret_num = clGetDeviceIDs(platforms->id, CL_DEVICE_TYPE_ALL, platforms->num_devices, tmp_devices, NULL);
		checkResult(platforms, ret_num, "clGetDeviceIDs(platform.devices)");

		for (i = 0; i < platforms->num_devices; i++) {
			platforms->devices[i].id = tmp_devices[i];
			ret_num = clGetDeviceInfo(platforms->devices[i].id, CL_DEVICE_TYPE, sizeof(cl_device_type), &platforms->devices[i].type, NULL);
			checkResult(platforms, ret_num, "clGetDeviceInfo(platform.device.type)");

			ret_num = clGetDeviceInfo(platforms->devices[i].id, CL_DEVICE_NAME, (size_t) 0, NULL, (size_t *) &size_name);
			checkResult(platforms, ret_num, "clGetDeviceInfo(size_name)");
			
			platforms->devices[i].name = (cl_char *) malloc(size_name + 1);
			checkPointer(platforms, platforms->devices[i].name, "platform.device.name");
			
			ret_num = clGetDeviceInfo(platforms->devices[i].id, CL_DEVICE_NAME, size_name, platforms->devices[i].name, (size_t *) NULL);
			checkResult(platforms, ret_num, "clGetDeviceInfo(platform.device.name)");
			
			platforms->devices[i].name[size_name] = '\0';	 
		}
		free(tmp_devices);
	
		platforms = platforms->next;
	}
}

cl_uint2 setDevice(platform_struct *platforms, cl_device_type device_type) {
	int accel_found = 0;
	int gpu_found = 0; 
	int cpu_found = 0; 
	cl_uint2 ddex;
	cl_uint i, p;
	platform_struct *ptr = platforms;
	
	
	if (device_type == CL_DEVICE_TYPE_DEFAULT) {
		ptr = platforms;
		p = 0;
		while(ptr != NULL){
			for (i = 0; i < ptr->num_devices; i++) {
				if (ptr->devices[i].type == CL_DEVICE_TYPE_ACCELERATOR) {
					accel_found = 1;
					ddex.x = p;
					ddex.y = i;
				}
			}
			ptr = ptr->next;
			p++;
			
		}
		if (!accel_found) {
			ptr = platforms;
			p = 0;
			while(ptr != NULL){
				for (i = 0; i < ptr->num_devices; i++) {
					if (ptr->devices[i].type == CL_DEVICE_TYPE_GPU) {
						gpu_found = 1;
						ddex.x = p;
						ddex.y = i;
					}
				}
				ptr = ptr->next;
				p++;
			}
			if (!gpu_found) {
				ptr = platforms;
				p = 0;
				while(ptr != NULL){
					for (i = 0; i < ptr->num_devices; i++) {
						if (ptr->devices[i].type == CL_DEVICE_TYPE_CPU) {
							cpu_found = 1;
							ddex.x = p;
							ddex.y = i;
						}
					}
					ptr = ptr->next;
					p++;
				}
				if (!cpu_found) {
					fprintf(stderr, "no devices of any kind were found on this system.  Leaving...\n"); 
					cleanUp(platforms);
					fflush(stderr);
					exit(EXIT_FAILURE);
				}
			}
		}
	}
	else {
		int device_found = 0;
		ptr = platforms;
		p = 0;
		while(ptr != NULL){
			for (i = 0; i < ptr->num_devices; i++) {
				if (ptr->devices[i].type == device_type) {
					device_found = 1;
					ddex.x = p;
					ddex.y = i;
				}
			}
			ptr = ptr->next;
			p++;
		}
		if (device_found == 0) {
			fprintf(stderr, "no devices of the requested type were found on this system.  Leaving...\n"); 
			cleanUp(platforms);
			fflush(stderr);
			exit(EXIT_FAILURE);
		}
	}
	
	return ddex;
}

void createContext(platform_struct *platforms, cl_uint2 ddex) {
	cl_int ret_num;
	
	cl_context_properties properties[3];
	properties[0] = CL_CONTEXT_PLATFORM;
	properties[1] = (const cl_context_properties) platforms[ddex.x].id;
	properties[2] = 0;
	platforms[ddex.x].context = clCreateContext((const cl_context_properties *) properties, 1, &(platforms[ddex.x].devices[ddex.y].id), NULL, NULL, &ret_num);
	checkResult(platforms, ret_num, "clCreateContext");
}

void createProgram(platform_struct *platforms, cl_uint2 ddex, const char* file_name) {
    cl_int ret_num;
	char* source = NULL;
		
	struct stat statbuf;

	FILE *fh = fopen(file_name, "r");
	if (fh == 0) {
		fprintf(stderr, "Couldn't open %s\n", file_name);
		cleanUp(platforms);
		fflush(stderr);
		exit(EXIT_FAILURE);
	}

	stat(file_name, &statbuf);
	source = (char *) malloc(statbuf.st_size + 1);
	checkPointer(platforms, source, "source");
	
	ret_num = fread(source, statbuf.st_size, 1, fh);
	if (ret_num != 1){
		fprintf(stderr, "ERROR: fread (%d)\n", ret_num);
		cleanUp(platforms);
		fflush(stderr);
		exit(EXIT_FAILURE);
	}
		
	source[statbuf.st_size] = '\0';

	platforms[ddex.x].program = clCreateProgramWithSource(platforms[ddex.x].context, 1, (const char **) &source, NULL, &ret_num);
	checkResult(platforms, ret_num, "clCreateProgramWithSource");

	ret_num = clBuildProgram(platforms[ddex.x].program, 1, &(platforms[ddex.x].devices[ddex.y].id), "", NULL, NULL);
	if (ret_num != CL_SUCCESS)
    {
        // Determine the reason for the error
        char buildLog[16384];
        clGetProgramBuildInfo(platforms[ddex.x].program, platforms[ddex.x].devices[ddex.y].id, CL_PROGRAM_BUILD_LOG,
                              sizeof(buildLog), buildLog, NULL);

        fprintf(stderr, "Error in kernel:\n");
		fprintf(stderr, "%s\n", buildLog);
    }
    checkResult(platforms, ret_num, "clBuildProgram");
    
    free(source);
}

void createCommandQueue(platform_struct *platforms, cl_uint2 ddex, cl_command_queue_properties properties) {
	cl_int ret_num;
	
	platforms[ddex.x].devices[ddex.y].command_queue = clCreateCommandQueue(platforms[ddex.x].context, platforms[ddex.x].devices[ddex.y].id, properties, &ret_num);
	checkResult(platforms, ret_num, "clCreateCommandQueue");
	
}

void initMemoryObjects(platform_struct *platforms, cl_uint2 ddex, cl_uint num_mems) {
	platforms[ddex.x].num_mems = num_mems;
	platforms[ddex.x].mem_objects = (cl_mem *) calloc(platforms[ddex.x].num_mems, sizeof(cl_mem));
	checkPointer(platforms, platforms[ddex.x].mem_objects, "platform.mem_objects");
}


//~ void setKernel(cl_uint2 ddex, cl_uint kernel_type ){
	//~ if (kernel_type == KERNEL_DEFAULT) {
      //~ kernel_type = (platforms[ddex.x].device[ddex.y].type == CL_DEVICE_TYPE_ACCELERATOR) ? KERNEL_AWGC : KERNEL_LS;
   //~ }
//~ }

//~ int main(int argc, char *argv[]) {
	//~ cl_uint num_platforms;
	//~ platform_struct *platforms = NULL;
	//~ cl_uint2 ddex;
	//~ 
	//~ platforms = getPlatforms(&num_platforms);
	//~ getDevices(platforms);
	//~ 
	//~ ddex = setDevice(platforms, CL_DEVICE_TYPE_DEFAULT);
	//~ 
	//~ createContext(platforms, ddex);
	//~ 
	//~ createProgram(platforms, ddex, "kernel.cl");
	//~ 
	//~ return 0;
//~ }

