#ifndef RPL_STATS_H
#define RPL_STATS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*---------------------------------------------------------------------------*/

/* Define an entry in the stats table */
#include "uip.h"
struct rpl_stats_entry
{
    uip_ipaddr_t addr;
    uint32_t dio_count;
    uint32_t dao_count;
    uint32_t dis_count;
    bool dio_attacker;
    bool dis_attacker;
};
typedef struct rpl_stats_entry rpl_stats_entry_t;

/* RPL message types enum */
enum rpl_messages {
    DIO,
    DAO,
    DIS
};
typedef enum rpl_messages rpl_messages_e ;

/*---------------------------------------------------------------------------*/

void rpl_init_stats_collection();

uint32_t rpl_read_stat_count_ip(uip_ipaddr_t* neighbor, rpl_messages_e type);
uint32_t rpl_read_stat_count_index(size_t neighbor_idx, rpl_messages_e type);

uint32_t rpl_read_neighbor_num();

void rpl_reset_stats();

void rpl_check_dio_attackers();
void rpl_check_dis_attackers();

size_t rpl_stats_snprint(char *buf, size_t len);

/*---------------------------------------------------------------------------*/
#endif // RPL_STATS_H
