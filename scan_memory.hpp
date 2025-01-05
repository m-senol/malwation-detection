#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <getopt.h>

#include <libvmi/libvmi.h>
#include <yara.h>

class ScanMemory
{
private:
    vmi_instance_t vmi;
    YR_RULES* rules;
    addr_t list_head, cur_list_entry, next_list_entry;
    unsigned long tasks_offset, pid_offset, name_offset;
    const unsigned long vadroot_offset, avltreeleftchild_offset, avltreerightchild_offset, avltreestartingvpn_offset, avltreeendingvpn_offset, depth_offset;
    bool verbose;
    vmi_init_data_t* init_data;
    const uint64_t page_size;

    
    int init_list_head();
    void traverse_vad_tree(addr_t node, char* process_name, vmi_pid_t pid, uint64_t depth);
    static int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);
    int scan(uint8_t* data_to_scan, size_t size, char* process_name);

public:
    ScanMemory();
    ~ScanMemory();

    int init(int argc, char* argv[]);
    int run();
};
