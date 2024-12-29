#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>

#include <libvmi/libvmi.h>

int init(vmi_instance_t* vmi, char** yara_rule_file, int argc, char* argv[], vmi_init_data_t **init_data)
{
    unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;
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
            {NULL, 0, NULL, 0}
        };
        const char* opts = "n:d:j:s:y:";
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
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "linux_tasks", &tasks_offset) )
            return 1;
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "linux_name", &name_offset) )
            return 1;
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "linux_pid", &pid_offset) )
            return 1;
    } else if (VMI_OS_WINDOWS == vmi_get_ostype(*vmi)) {
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "win_tasks", &tasks_offset) )
            return 1;
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "win_pname", &name_offset) )
            return 1;
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "win_pid", &pid_offset) )
            return 1;
    } else if (VMI_OS_FREEBSD == vmi_get_ostype(*vmi)) {
        tasks_offset = 0;
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "freebsd_name", &name_offset) )
            return 1;
        if ( VMI_FAILURE == vmi_get_offset(*vmi, "freebsd_pid", &pid_offset) )
            return 1;
    } else if (VMI_OS_OSX == vmi_get_ostype(*vmi)) {
        tasks_offset = 0;
        if (VMI_FAILURE == vmi_get_offset(*vmi, "osx_name", &name_offset))
            return 1;
        if (VMI_FAILURE == vmi_get_offset(*vmi, "osx_pid", &pid_offset))
            return 1;
    }

    return 0;
}

void before_exit(vmi_instance_t vmi, vmi_init_data_t *init_data, char* yara_rule_file)
{
    vmi_resume_vm(vmi);
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    free(yara_rule_file);
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
        return 1;
    }
    
    vmi_instance_t vmi = {0};
    vmi_init_data_t *init_data = NULL;
    char* yara_rule_file = NULL;
    if (init(&vmi, &yara_rule_file, argc, argv, &init_data) == 1)
    {
        fprintf(stderr, "Error initiliasing the program\n");
        before_exit(vmi, init_data, yara_rule_file);
        return 1;

    }
    printf("Yara rule file: %s\n", yara_rule_file);
    before_exit(vmi, init_data, yara_rule_file);
    return 0;
}
