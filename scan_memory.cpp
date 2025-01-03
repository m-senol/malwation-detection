#include "scan_memory.hpp"

ScanMemory::ScanMemory():
vmi(0), rules(NULL), list_head(0), cur_list_entry(0), next_list_entry(0),
tasks_offset(0), pid_offset(0), name_offset(0), vadroot_offset(0x448),
avltreeleftchild_offset(0x8), avltreerightchild_offset(0x10),
avltreestartingvpn_offset(0x18), avltreeendingvpn_offset(0x20), verbose(0),
init_data(NULL), page_size(4096)
{
}

ScanMemory::~ScanMemory()
{
    vmi_resume_vm(vmi);
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    yr_rules_destroy(rules);
    yr_finalize();
}

int ScanMemory::init_list_head()
{
    if (VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &list_head))
    {
        printf("Failed to find PsActiveProcessHead\n");
        return 1;
    }

    cur_list_entry = list_head;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry))
    {
        printf("Failed to read next pointer at %" PRIx64 "\n", cur_list_entry);
        return 1;
    }

    return 0;
}

int ScanMemory::init(int argc, char* argv[])
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

    uint64_t domid = 0;
    uint8_t init = VMI_INIT_DOMAINNAME;
    vmi_config_t config_type = VMI_CONFIG_GLOBAL_FILE_ENTRY;
    void *input = NULL, *config = NULL;
    int all_set = 0;

    if ( argc == 2 )
    {
        input = argv[1];
    }

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
                    if (init_data)
                    {
                        free((init_data)->entry[0].data);
                    }
                    else
                    {
                        init_data = (vmi_init_data_t*)malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
                    }
                    (init_data)->count = 1;
                    (init_data)->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
                    (init_data)->entry[0].data = strdup(optarg);
                    break;
                case 'y':
                {

                    yr_initialize();

                    FILE* rule_file = fopen(optarg, "r");
                    if (rule_file == NULL)
                    {
                        fprintf(stderr, "Failed to open YARA rule file: test.yar\n");
                        yr_finalize();
                        return 1;
                    }
                    YR_COMPILER* compiler = NULL;
                    yr_compiler_create(&compiler);
                    yr_compiler_add_file(compiler, rule_file, NULL, NULL);
                    fclose(rule_file);
                    yr_compiler_get_rules(compiler, &rules);
                    yr_compiler_destroy(compiler);
                    break;
                }
                case 'v':
                    verbose = 1;
                    break;

                default:
                    fprintf(stderr, "Unknown option\n");
                    return 1;
            }
        }
        if (all_set == 0)
        {
            fprintf(stderr, "No init info given for vmi\n");
            return 1;
        }
    }

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init_complete(&vmi, input, init, init_data, config_type, config, NULL))
    {
        fprintf(stderr, "Failed to init LibVMI library.\n");
        return 1;
    }
    /* init the offset values */
    if (VMI_OS_WINDOWS == vmi_get_ostype(vmi))
    {
        if ( VMI_FAILURE == vmi_get_offset(vmi, "win_tasks", &tasks_offset) )
            return 1;
        if ( VMI_FAILURE == vmi_get_offset(vmi, "win_pname", &name_offset) )
            return 1;
        if ( VMI_FAILURE == vmi_get_offset(vmi, "win_pid", &pid_offset) )
            return 1;
    }
    else
    {
        fprintf(stderr, "Only Windows is supported\n");
        return 1;
    }

    if (init_list_head() != 0)
    {
        return 1;
    }

    if (vmi_pause_vm(vmi) != VMI_SUCCESS)
    {
        printf("Failed to pause VM\n");
        return 1;
    }
    
    return 0;
}

int ScanMemory::scan(uint8_t* data_to_scan, size_t size)
{
    int result = 0;
    if (yr_rules_scan_mem(rules, data_to_scan, size, 0, NULL, NULL, 0) == ERROR_SUCCESS) {
        result = 1;
    }
    return result;
}

void ScanMemory::traverse_vad_tree(addr_t node, char* process_name)
{
    if (node == 0)
    {
        return;
    }

    uint64_t starting_vpn = 0, ending_vpn = 0;
    vmi_read_64_va(vmi, node + avltreestartingvpn_offset, 0, &starting_vpn);
    vmi_read_64_va(vmi, node + avltreeendingvpn_offset, 0, &ending_vpn);

    uint64_t start_adress = starting_vpn * page_size;
    uint64_t end_adress = ((ending_vpn + 1) * page_size ) - 1;

    for (uint64_t addr = start_adress; addr <= end_adress; addr+=page_size)
    {
        uint8_t buffer[page_size];
        if (VMI_SUCCESS == vmi_read_pa(vmi, addr, page_size, buffer, NULL))
        {
            if (scan(buffer, page_size) == 1)
            {
                printf("Found in task %s\n", process_name);
            }
            
        }
    }

    addr_t left_child = 0, right_child = 0;
    vmi_read_addr_va(vmi, node + avltreeleftchild_offset, 0, &left_child);
    vmi_read_addr_va(vmi, node + avltreerightchild_offset, 0, &right_child);


    traverse_vad_tree(left_child, process_name);
    traverse_vad_tree(right_child, process_name);
}

int ScanMemory::run()
{
    addr_t current_process = 0, vad_root = 0, vad_root_pointer = 0;
    vmi_pid_t pid = 0;
    char* process_name = NULL;

    while(1)
    {
        current_process = cur_list_entry - tasks_offset;

        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

        vmi_read_addr_va(vmi, current_process + vadroot_offset, 0, &vad_root_pointer);
        vmi_read_addr_va(vmi, vad_root_pointer, 0, &vad_root);

        process_name = vmi_read_str_va(vmi, current_process + name_offset, 0);
        if (!process_name)
        {
            printf("Failed to find procname\n");
            return 1;
        }
        if (verbose)
        {
            printf("[%5d] %s (struct addr:%" PRIx64 ")\n", pid, process_name, current_process);
        }
        traverse_vad_tree(vad_root, process_name);

        cur_list_entry = next_list_entry;

        if (vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry) == VMI_FAILURE)
        {
            printf("Failed to read next pointer in loop at %" PRIx64 "\n", cur_list_entry);
            return 1;
        }

        if (next_list_entry == list_head)
        {
            break;
        }
    }
    return 0;
}