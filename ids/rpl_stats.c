#include "rpl_stats.h"

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "mutex.h"
#include "rpl-icmp6.h"
#include "uiplib.h"

#define LOG_MODULE "RPL Stats"
#define LOG_LEVEL LOG_LEVEL_INFO

#define TABLE_ENTRIES 64
#define DIS_THRESHOLD 3

/*---------------------------------------------------------------------------*/

static rpl_stats_entry_t rpl_stats[TABLE_ENTRIES] = {};
static mutex_t stats_lock;
static long last_entry = 0;

/*---------------------------------------------------------------------------*/

static long search_ip(uip_ipaddr_t *ip) {
    for (int i = 0; i < last_entry; i++) {
        if (uip_ipaddr_cmp(&(rpl_stats[i].addr), ip)) {
            return i;
        }
    }
    return -1;
}

static void rpl_increment_stat_count(uip_ipaddr_t *neighbor,
                                     rpl_messages_e type) {
    while (!mutex_try_lock(&stats_lock));
    long pos = search_ip(neighbor);

    if (pos < 0) {
        if (last_entry >= TABLE_ENTRIES) {
            goto cleanup;
        }
        uip_ipaddr_copy(&(rpl_stats[last_entry].addr), neighbor);
        switch (type) {
            case DIO:
                rpl_stats[last_entry++].dio_count++;
                break;
            case DAO:
                rpl_stats[last_entry++].dao_count++;
                break;
            case DIS:
                rpl_stats[last_entry++].dis_count++;
                break;
        }
    } else {
        switch (type) {
            case DIO:
                rpl_stats[pos].dio_count++;
                break;
            case DAO:
                rpl_stats[pos].dao_count++;
                break;
            case DIS:
                rpl_stats[pos].dis_count++;
                break;
        }
    }

cleanup:
    mutex_unlock(&stats_lock);
}

static void dio_callback(rpl_dio_t *dio, uip_ipaddr_t *from) {
    char buf[46];
    uiplib_ipaddr_snprint(buf, sizeof(buf), from);
    LOG_DBG("Received DIO message from: %s", buf);
    rpl_increment_stat_count(from, DIO);
}

static void dao_callback(rpl_dao_t *dao, uip_ipaddr_t *from) {
    char buf[46];
    uiplib_ipaddr_snprint(buf, sizeof(buf), from);
    LOG_DBG("Received DAO message from: %s", buf);
    rpl_increment_stat_count(from, DAO);
}

static void dis_callback(uip_ipaddr_t *from) {
    char buf[46];
    uiplib_ipaddr_snprint(buf, sizeof(buf), from);
    LOG_DBG("Received DIS message from: %s", buf);
    rpl_increment_stat_count(from, DIS);
}

/*---------------------------------------------------------------------------*/

void rpl_init_stats_collection() {
    rpl_install_dio_callback(&dio_callback);
    rpl_install_dao_callback(&dao_callback);
    rpl_install_dis_callback(&dis_callback);
}

uint32_t rpl_read_stat_count_ip(uip_ipaddr_t *neighbor, rpl_messages_e type) {
    while (!mutex_try_lock(&stats_lock));

    int ret = 0;
    int pos = search_ip(neighbor);

    if (pos < 0) {
        goto cleanup;
    } else {
        switch (type) {
            case DIO:
                ret = rpl_stats[pos].dio_count;
                break;
            case DAO:
                ret = rpl_stats[pos].dao_count;
                break;
            case DIS:
                ret = rpl_stats[pos].dis_count;
                break;
        }
    }
cleanup:
    mutex_unlock(&stats_lock);
    return ret;
}

uint32_t rpl_read_stat_count_index(size_t neighbor_idx, rpl_messages_e type) {
    while (!mutex_try_lock(&stats_lock));

    int ret = 0;

    if (neighbor_idx < 0 || neighbor_idx >= last_entry) {
        goto cleanup;
    } else {
        switch (type) {
            case DIO:
                ret = rpl_stats[neighbor_idx].dio_count;
                break;
            case DAO:
                ret = rpl_stats[neighbor_idx].dao_count;
                break;
            case DIS:
                ret = rpl_stats[neighbor_idx].dis_count;
                break;
        }
    }
cleanup:
    mutex_unlock(&stats_lock);
    return ret;
}

uint32_t rpl_read_neighbor_num() {
    uint32_t ret = 0;
    while (!mutex_try_lock(&stats_lock));
    ret = last_entry;
    mutex_unlock(&stats_lock);
    return ret;
}

void rpl_reset_stats() {
    while (!mutex_try_lock(&stats_lock));
    memset(rpl_stats, 0, sizeof(rpl_stats));
    last_entry = 0;
    mutex_unlock(&stats_lock);
}

void rpl_check_dio_attackers() {
    // Compute average
    float avg = 0.0f;
    int neighbors = rpl_read_neighbor_num();
    for (int i = 0; i < neighbors; i++) {
        avg += (float)rpl_read_stat_count_index(i, DIO);
    }
    avg = avg / (float)neighbors;

    // Compute stddev
    float temp = 0.0f;
    for (int i = 0; i < neighbors; i++) {
        temp += powf(2, avg - (float)rpl_read_stat_count_index(i, DIO));
    }
    float stddev = sqrtf(temp / (float)neighbors);

    // Compute k based on neigbors number
    float k = -5e-05 * powf(neighbors, 4) + 0.0037 * powf(neighbors, 3) -
              0.0899 * powf(neighbors, 2) + 0.9281 * neighbors - 0.7903;

    // Compare count with computed distribution
    for (int i = 0; i < neighbors; i++) {
        if ((float)rpl_read_stat_count_index(i, DIO) > avg + (k * stddev)) {
            rpl_stats[i].dio_attacker = true;
        }
    }
}

void rpl_check_dis_attackers() {
    int neighbors = rpl_read_neighbor_num();
    // Compare count with threshold
    for (int i = 0; i < neighbors; i++) {
        if ((float)rpl_read_stat_count_index(i, DIS) > DIS_THRESHOLD) {
            rpl_stats[i].dis_attacker = true;
        }
    }
}

size_t rpl_stats_snprint(char *buf, size_t len) {
    size_t written = 0;

    // Print header
    written += snprintf(buf, len, "\n%-30s%5s%5s%5s%5s%5s\n", "Neigbor", "DIO",
                        "DAO", "DIS", "DIOA", "DISA");

    while (!mutex_try_lock(&stats_lock));
    static char ipbuf[46];
    for (int i = 0; i < last_entry; i++) {
        // IP addr to string
        uiplib_ipaddr_snprint(ipbuf, sizeof(ipbuf), &(rpl_stats[i].addr));
        written +=
            snprintf(buf + written, len - written, "%-30s%5d%5d%5d%5d%5d\n",
                     ipbuf, rpl_stats[i].dio_count, rpl_stats[i].dao_count,
                     rpl_stats[i].dis_count, rpl_stats[i].dio_attacker,
                     rpl_stats[i].dis_attacker);
    }

    mutex_unlock(&stats_lock);
    return written;
}
