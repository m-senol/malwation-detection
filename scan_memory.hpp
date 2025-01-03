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
    unsigned long vadroot_offset, avltreeleftchild_offset, avltreerightchild_offset, avltreestartingvpn_offset, avltreeendingvpn_offset;
    bool verbose;
    vmi_init_data_t* init_data;
    const uint64_t page_size;

    
    int init_list_head();
    void traverse_vad_tree(addr_t node, char* process_name);
    int scan(uint8_t* data_to_scan, size_t size);

public:
    ScanMemory();
    ~ScanMemory();

    int init(int argc, char* argv[]);
    int run();
};
