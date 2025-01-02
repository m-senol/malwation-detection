#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <getopt.h>

#include <libvmi/libvmi.h>
#include <yara.h>

int init(vmi_instance_t* vmi, char** yara_rule_file, int argc, char* argv[], vmi_init_data_t **init_data, unsigned long* tasks_offset, unsigned long* pid_offset, unsigned long* name_offset, int* verbose)
{
    uint64_t domid = 0;
    uint8_t init = VMI_INIT_DOMAINNAME, config_type = VMI_CONFIG_GLOBAL_FILE_ENTRY;
    void *input = NULL, *config = NULL;
    int all_set = 0;

    if ( argc == 2 )
        input = argv[1];

    if ( argc > 2 )
    {
        const struct option long_opts[] = {
            {"name", required_argument, NULL, 'n'},
            {"domid", required_argument, NULL, 'd'},
            {"json", required_argument, NULL, 'j'},
            {"socket", optional_argument, NULL, 's'},
            {"yara", required_argument, NULL, 'y'},
            {"verbose", no_argument, NULL, 'v'},
            {NULL, 0, NULL, 0}
        };
        const char* opts = "n:d:j:s:y:v";
        int c;
        int long_index = 0;

        while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
        {
            switch (c)
            {
                case 'n':
                    all_set = 1;
                    input = optarg;
                    break;
                case 'd':
                    all_set = 1;
                    init = VMI_INIT_DOMAINID;
                    domid = strtoull(optarg, NULL, 0);
                    input = (void*)&domid;
                    break;
                case 'j':
                    all_set = 1;
                    config_type = VMI_CONFIG_JSON_PATH;
                    config = (void*)optarg;
                    break;
                case 's':
                    all_set = 1;
                    // in case we have multiple '-s' argument, avoid memory leak
                    if (*init_data)
                    {
                        free((*init_data)->entry[0].data);
                    }
                    else
                    {
                        *init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
                    }
                    (*init_data)->count = 1;
                    (*init_data)->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
                    (*init_data)->entry[0].data = strdup(optarg);
                    break;
                case 'y':
                    *yara_rule_file = (char*)malloc(strlen(optarg) + 1);
                    if (*yara_rule_file == NULL)
                    {
                        fprintf(stderr, "Memory allocation failed while copying yara rule file\n");
                        return 1;
                    }
                    strncpy(*yara_rule_file, optarg, strlen(optarg) + 1);
                    break;
                case 'v':
                    *verbose = 1;
                    break;

                default:
                    fprintf(stderr, "Unknown option\n");
                    return 1;
            }
        }
    }
    if (*yara_rule_file == NULL)
    {
        fprintf(stderr, "-y/--yara is a mandatory argument\n");
        return 1;
    }
    if (all_set == 0)
    {
        fprintf(stderr, "No init info given for vmi\n");
        return 1;
    }

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init_complete(vmi, input, init, *init_data, config_type, config, NULL)) {
        fprintf(stderr, "Failed to init LibVMI library.\n");
        return 1;
    }
    /* init the offset values */
    if (VMI_OS_LINUX == vmi_get_ostype(*vmi)) {
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "linux_tasks", tasks_offset) )
            return 1;
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "linux_name", name_offset) )
            return 1;
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "linux_pid", pid_offset) )
            return 1;
    } else if (VMI_OS_WINDOWS == vmi_get_ostype(*vmi)) {
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "win_tasks", tasks_offset) )
            return 1;
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "win_pname", name_offset) )
            return 1;
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "win_pid", pid_offset) )
            return 1;
    } else if (VMI_OS_FREEBSD == vmi_get_ostype(*vmi)) {
        tasks_offset = 0;
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "freebsd_name", name_offset) )
            return 1;
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "freebsd_pid", pid_offset) )
            return 1;
    } else if (VMI_OS_OSX == vmi_get_ostype(*vmi)) {
        tasks_offset = 0;
        if (VMI_FAILURE == vmi_get_offset(*vmi, "osx_name", name_offset))
            return 1;
        if (VMI_FAILURE == vmi_get_offset(*vmi, "osx_pid", pid_offset))
            return 1;
    }

    return 0;
}

void clean_up(vmi_instance_t vmi, vmi_init_data_t *init_data, char* yara_rule_file)
{
    vmi_resume_vm(vmi);
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    free(yara_rule_file);
}

int get_list_head(vmi_instance_t vmi, unsigned long tasks_offset, os_t os, addr_t* list_head, addr_t* cur_list_entry, addr_t* next_list_entry)
{
    if (VMI_OS_LINUX == os) {
        /* Begin at PID 0, the 'swapper' task. It's not typically shown by OS
         *  utilities, but it is indeed part of the task list and useful to
         *  display as such.
         */
        if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, "init_task", list_head) )
            return 1;

        *list_head += tasks_offset;
    } else if (VMI_OS_WINDOWS == os) {

        // find PEPROCESS PsInitialSystemProcess
        if (VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", list_head)) {
            printf("Failed to find PsActiveProcessHead\n");
            return 1;
        }
    } else if (VMI_OS_FREEBSD == os || VMI_OS_OSX == os) {
        // find initproc
        if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, "allproc", list_head) )
            return 1;
    }

    *cur_list_entry = *list_head;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, *cur_list_entry, 0, next_list_entry)) {
        printf("Failed to read next pointer at %"PRIx64"\n", *cur_list_entry);
        return 1;
    }

    if (VMI_OS_FREEBSD == os || VMI_OS_OSX == os) {
        // FreeBSD's p_list is not circularly linked
        *list_head = 0;
        // Advance the pointer once
        ;
        if (VMI_FAILURE == vmi_read_addr_va(vmi, *cur_list_entry, 0, cur_list_entry)) {
            printf("Failed to read next pointer at %"PRIx64"\n", *cur_list_entry);
            return 1;
        }
    }
    return 0;
}

int scan(char* filename, uint8_t* data_to_scan, size_t size)
{
    int result = 0;
    yr_initialize();

    FILE* rule_file = fopen(filename, "r");
    if (rule_file == NULL) {
        fprintf(stderr, "Failed to open YARA rule file: test.yar\n");
        yr_finalize();
        return result;
    }

    YR_COMPILER* compiler = NULL;
    YR_RULES* rules = NULL;

    yr_compiler_create(&compiler);

    yr_compiler_add_file(compiler, rule_file, NULL, NULL);
    
    fclose(rule_file);

    yr_compiler_get_rules(compiler, &rules);

    if (yr_rules_scan_mem(rules, data_to_scan, size, 0, NULL, NULL, 0) == ERROR_SUCCESS) {
        result = 1;
    } else {
        result = 0;
    }

    yr_compiler_destroy(compiler);
    yr_rules_destroy(rules);
    yr_finalize();
    return result;
}

void traverse_vad_tree(vmi_instance_t vmi, addr_t node, unsigned long left_offset, unsigned long right_offset, unsigned long start_offset, unsigned long end_offset, char* process_name, char* filename)
{
    if (node == 0)
    {
        return;
    }

    const uint64_t page_size = 4096; // not sure

    uint64_t starting_vpn = 0, ending_vpn = 0;
    vmi_read_64_va(vmi, node + start_offset, 0, &starting_vpn);
    vmi_read_64_va(vmi, node + end_offset, 0, &ending_vpn);

    uint64_t start_adress = starting_vpn * page_size;
    uint64_t end_adress = ((ending_vpn + 1) * page_size ) - 1;

    for (uint64_t addr = start_adress; addr <= end_adress; addr+=page_size)
    {
        uint8_t buffer[page_size];
        if (VMI_SUCCESS == vmi_read_pa(vmi, addr, page_size, buffer, NULL))
        {
            if (scan(filename, buffer, page_size) == 1)
            {
                printf("Found in task %s\n", process_name);
            }
            
        }
    }

    addr_t left_child = 0, right_child = 0;
    vmi_read_addr_va(vmi, node + left_offset, 0, &left_child);
    vmi_read_addr_va(vmi, node + right_offset, 0, &right_child);


    traverse_vad_tree(vmi, left_child, left_offset, right_offset, start_offset, end_offset, process_name, filename);
    traverse_vad_tree(vmi, right_child, left_offset, right_offset, start_offset, end_offset, process_name, filename);
}

int loop(vmi_instance_t vmi, os_t os, addr_t list_head, addr_t* cur_list_entry, addr_t* next_list_entry, unsigned long tasks_offset, unsigned long pid_offset, unsigned long name_offset, unsigned long vadroot_offset, unsigned long avltreeleftchild_offset, unsigned long avltreerightchild_offset, unsigned long avltreestartingvpn_offset, unsigned long avltreeendingvpn_offset, char* filename, int verbose)
{
    addr_t current_process = 0, vad_root = 0, vad_root_pointer = 0;
    vmi_pid_t pid = 0;
    char* procname = NULL;
    while (1)
    {
        current_process = *cur_list_entry - tasks_offset;
        
        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

        procname = vmi_read_str_va(vmi, current_process + name_offset, 0);
        if (!procname)
        {
            printf("Failed to find procname\n");
            return 1;
        }
        
        vmi_read_addr_va(vmi, current_process + vadroot_offset, 0, &vad_root_pointer);
        vmi_read_addr_va(vmi, vad_root_pointer, 0, &vad_root);
        
        if (verbose)
        {
            printf("[%5d] %s (struct addr:%"PRIx64")\n", pid, procname, current_process);
        }
        

        traverse_vad_tree(vmi, vad_root, avltreeleftchild_offset, avltreerightchild_offset, avltreestartingvpn_offset, avltreeendingvpn_offset, procname, filename);

        if (procname)
        {
            free(procname);
            procname = NULL;
        }

        if ((VMI_OS_FREEBSD == os || VMI_OS_OSX == os) && *next_list_entry == list_head)
        {
            break;
        }

        /* follow the next pointer */
        *cur_list_entry = *next_list_entry;
        if (vmi_read_addr_va(vmi, *cur_list_entry, 0, next_list_entry) == VMI_FAILURE) {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", *cur_list_entry);
            return 1;
        }
        /* In Windows, the next pointer points to the head of list, this pointer is actually the
         * address of PsActiveProcessHead symbol, not the address of an ActiveProcessLink in
         * EPROCESS struct.
         * It means in Windows, we should stop the loop at the last element in the list, while
         * in Linux, we should stop the loop when coming back to the first element of the loop
         */
        if (VMI_OS_WINDOWS == os && *next_list_entry == list_head) {
            break;
        } else if (VMI_OS_LINUX == os && *cur_list_entry == list_head) {
            break;
        }
    }
    return 0;
}

int main(int argc, char* argv[])
{
    if ( argc < 2 )
    {
        printf("Usage: %s\n", argv[0]);
        printf("\t -n/--name <domain name>\n");
        printf("\t -d/--domid <domain id>\n");
        printf("\t -j/--json <path to kernel's json profile>\n");
        printf("\t -s/--socket <path to KVMI socket>\n");
        printf("\t -y/--yara <yara rule file>\n");
        printf("\t -v/--verbose");
        return 1;
    }
    
    int verbose = 0;
    vmi_instance_t vmi = {0};
    addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
    unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;
    unsigned long vadroot_offset = 0x448, avltreeleftchild_offset = 0x8, avltreerightchild_offset = 0x10, avltreestartingvpn_offset = 0x18, avltreeendingvpn_offset = 0x20; // temporaryly here
    vmi_init_data_t *init_data = NULL;
    char* yara_rule_file = NULL;
    if (init(&vmi, &yara_rule_file, argc, argv, &init_data, &tasks_offset, &pid_offset, &name_offset, &verbose) == 1)
    {
        fprintf(stderr, "Error initiliasing the program\n");
        clean_up(vmi, init_data, yara_rule_file);
        return 1;
    }

    if (vmi_pause_vm(vmi) != VMI_SUCCESS)
    {
        printf("Failed to pause VM\n");
        clean_up(vmi, init_data, yara_rule_file);
        return 1;
    }

    os_t os = vmi_get_ostype(vmi);
    if (get_list_head(vmi, tasks_offset, os, &list_head, &cur_list_entry, &next_list_entry) == 1)
    {
        clean_up(vmi, init_data, yara_rule_file);
        return 1;
    }

    if (loop(vmi, os, list_head, &cur_list_entry, &next_list_entry, tasks_offset, pid_offset, name_offset, vadroot_offset, avltreeleftchild_offset, avltreerightchild_offset, avltreestartingvpn_offset, avltreeendingvpn_offset, yara_rule_file, verbose) == 1)
    {
        clean_up(vmi, init_data, yara_rule_file);
        return 1;
    }
    
    clean_up(vmi, init_data, yara_rule_file);
    return 0;
}
