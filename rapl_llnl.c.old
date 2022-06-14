#define _GNU_SOURCE
#include <inttypes.h>
#include <unistd.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <string.h>

#include "ldms.h"
#include "ldmsd.h"
#include "sampler_base.h"
#include "msr_core.h"
#include "msr_rapl.h"
#include "msr_thermal.h"
#include "msr_counters.h"

/*Patki: April 25, 2016.
 *Ported by Jessica Hannebert: June 8, 2022.
Ideally, the following should be read from a config file such as the whitelist
that defines which MSRs to sample.
But as a first cut for Intel, we are hardcoding the requested MSRs and CSRs
*/

#define SAMP "rapl_llnl"

#define PKG_MSR_COUNT_RO 9
#define CORE_MSR_COUNT_RO 2
#define THR_MSR_COUNT_RO 5

#define C2_PKG 0x60D
#define C3_PKG 0x3F8
#define C6_PKG 0x3F9
#define IA32_PKG_THERM 0x19D
#define MSR_PKG_ENERGY_STATUS 0x611
#define MSR_PKG_POWER_LIMIT 0x610
#define MSR_DRAM_POWER_LIMIT 0x618
#define MSR_MPERF_PKG 0xE7
#define MSR_APERF_PKG 0xE8

#define C3_CORE 0x3FC
#define C6_CORE 0x3FD

#define MCNT_THR 0x30A
#define ACNT_THR 0x30B
#define TSC_THR 0x10
#define IA32_THERM_STATUS_THR 0x19C
#define IA32_PERF_STATUS_THR 0x198

//Specific to comus: 2 sockets, 36 total cores, 72 threads with hyperthreading enabled
#define NUM_U64_VALS ((PKG_MSR_COUNT_RO * 2) + (CORE_MSR_COUNT_RO * 36) + (THR_MSR_COUNT_RO * 72))
#define MSR_STR_LEN 80
//10 Read-only PKG MSRs
uint64_t **v_pkg_ro[PKG_MSR_COUNT_RO];
//3 Read-only CORE MSRs
uint64_t **v_core_ro[CORE_MSR_COUNT_RO];
//3 Read-only THR MSRs
uint64_t **v_thr_ro[THR_MSR_COUNT_RO];

FILE *logfile;

static ldms_set_t set = NULL;
//static ldms_metric_t *metric_table;
static ldmsd_msg_log_f msglog;
//uint64_t comp_id;
char msr_name[NUM_U64_VALS][MSR_STR_LEN];
char tempStr[MSR_STR_LEN];
static base_data_t base;
static int metric_offset;

/******************/
/*Non-LDMS Functions*/
/******************/
void load_and_allocate_batches()
{
  int i;
  /*All package-scope MSRs RO*/
  for (i=0;i<PKG_MSR_COUNT_RO;i++){
    v_pkg_ro[i] = (uint64_t**) malloc(num_sockets() * sizeof(uint64_t *));
  }

  /*All core-scope MSRs RO*/
  for (i=0;i<CORE_MSR_COUNT_RO;i++){
    v_core_ro[i] = (uint64_t**) malloc(num_cores() * sizeof(uint64_t *));
  }


  /*All thread-scope MSRs RO*/
  for (i=0;i<THR_MSR_COUNT_RO;i++){
    v_thr_ro[i] = (uint64_t**) malloc(num_devs() * sizeof(uint64_t *));
  }

  fprintf(stderr, "HANNEBERT DEBUG: done with malloc for MSRs\n");

  /*Allocate read-only and write-read-write batches*/
  int rd_batch_size = PKG_MSR_COUNT_RO * num_sockets() + CORE_MSR_COUNT_RO * num_cores() + THR_MSR_COUNT_RO * num_devs();

  allocate_batch(USR_BATCH1, rd_batch_size);

  /*Load in batches: USR_BATCH1 for READ */

  fprintf(stderr, "HANNEBERT DEBUG: done with allocate_batch\n");

  load_socket_batch(C2_PKG,v_pkg_ro[0],USR_BATCH1);
  load_socket_batch(C3_PKG,v_pkg_ro[1],USR_BATCH1);
  load_socket_batch(C6_PKG,v_pkg_ro[2],USR_BATCH1);
  load_socket_batch(IA32_PKG_THERM,v_pkg_ro[3],USR_BATCH1);
  load_socket_batch(MSR_PKG_ENERGY_STATUS,v_pkg_ro[4],USR_BATCH1);
  load_socket_batch(MSR_PKG_POWER_LIMIT,v_pkg_ro[5],USR_BATCH1);
  load_socket_batch(MSR_DRAM_POWER_LIMIT,v_pkg_ro[6],USR_BATCH1);
  load_socket_batch(MSR_MPERF_PKG,v_pkg_ro[7],USR_BATCH1);
  load_socket_batch(MSR_APERF_PKG,v_pkg_ro[8],USR_BATCH1);

  load_core_batch(C3_CORE, v_core_ro[0], USR_BATCH1);
  load_core_batch(C6_CORE, v_core_ro[1], USR_BATCH1);

  load_thread_batch(MCNT_THR, v_thr_ro[0], USR_BATCH1);
  load_thread_batch(ACNT_THR, v_thr_ro[1], USR_BATCH1);
  load_thread_batch(TSC_THR, v_thr_ro[2], USR_BATCH1);
  load_thread_batch(IA32_THERM_STATUS_THR, v_thr_ro[3], USR_BATCH1);
  load_thread_batch(IA32_PERF_STATUS_THR, v_thr_ro[4], USR_BATCH1);

  fprintf(stderr, "HANNEBERT DEBUG: done loading batches\n");

}

//Read from MSRs and put the MSR values into ldms data structures
void read_and_assign()
{
  int i,j;
  int metric_no=metric_offset;
  union ldms_value v;

 read_batch(USR_BATCH1);

  for(i=0;i<PKG_MSR_COUNT_RO;i++){
    for(j=0;j<num_sockets();j++){
      v.v_u64 = *v_pkg_ro[i][j];

      //ldms_set_metric(metric_table[metric_no], &v);
      ldms_metric_set(set, metric_no, &v);
      metric_no++;
    }
  }


  for(i=0;i<CORE_MSR_COUNT_RO;i++){
    for(j=0;j<num_cores();j++){
      v.v_u64 = *v_core_ro[i][j];

      //ldms_set_metric(metric_table[metric_no], &v);
      ldms_metric_set(set, metric_no, &v);
      metric_no++;
    }
  }

    for(i=0;i<THR_MSR_COUNT_RO;i++){
    for(j=0;j<num_devs();j++){
      v.v_u64 = *v_thr_ro[i][j];

      //ldms_set_metric(metric_table[metric_no], &v);
      ldms_metric_set(set, metric_no, &v);
      metric_no++;
    }
  }

}

static void create_name_list()
{

  fprintf(stderr, "PATKI DEBUG: In CREATE NAME LIST\n");
  fprintf(stderr, "PATKI DEBUG: MSR_NAME SIZE %d, %d \n",NUM_U64_VALS, MSR_STR_LEN);
  fprintf(stderr, "PATKI DEBUG: Sockets, Cores, Threads: %ld, %ld %ld\n", num_sockets(), num_cores(), num_devs());
  int i;
  int j=0;

 /*Unfortunately the following can't be a double loop because of the static constant strings associated and the order in which MSRs are read*/
  /*Copied and repeated PKG/CORE/THR_MSR_COUNT_RO times. */

	/*PKG MSRS*/
  for (i=0; i<num_sockets(); i++){
    sprintf(msr_name[j], "C2_PKG_%d", i);
    j++;
  }

  for (i=0; i<num_sockets(); i++){
    sprintf(msr_name[j], "C3_PKG_%d", i);
    j++;
  }

  for (i=0; i<num_sockets(); i++){
    sprintf(msr_name[j], "C6_PKG_%d", i);
    j++;
  }

  for (i=0; i<num_sockets(); i++){
    sprintf(msr_name[j], "IA32_PKG_THERM_%d", i);
    j++;
  }

  for (i=0; i<num_sockets(); i++){
    sprintf(msr_name[j], "MSR_PKG_ENERGY_STATUS_%d", i);
    j++;
  }

  for (i=0; i<num_sockets(); i++){
    sprintf(msr_name[j], "MSR_PKG_POWER_LIMIT_%d", i);
    j++;
  }

  for (i=0; i<num_sockets(); i++){
    sprintf(msr_name[j], "MSR_DRAM_POWER_LIMIT_%d", i);
    j++;
  }

  for (i=0; i<num_sockets(); i++){
    sprintf(msr_name[j], "MSR_MPERF_PKG_%d", i);
    j++;
  }

  for (i=0; i<num_sockets(); i++){
    sprintf(msr_name[j], "MSR_APERF_PKG_%d", i);
    j++;
  }

/*CORE MSRS*/
  for (i=0; i<num_cores(); i++){
    sprintf(msr_name[j], "C3_CORE_%d", i);
    j++;
  }

  for (i=0; i<num_cores(); i++){
    sprintf(msr_name[j], "C6_CORE_%d", i);
    j++;
  }

  for (i=0; i<num_devs(); i++){
    sprintf(msr_name[j], "MCNT_THR_%d", i);
    j++;
  }

    for (i=0; i<num_devs(); i++){
    sprintf(msr_name[j], "ACNT_THR_%d", i);
    j++;
  }

    for (i=0; i<num_devs(); i++){
    sprintf(msr_name[j], "TSC_THR_%d", i);
    j++;
  }

    for (i=0; i<num_devs(); i++){
    sprintf(msr_name[j], "IA32_THERM_STATUS_THR_%d", i);
    j++;
  }

    for (i=0; i<num_devs(); i++){
    sprintf(msr_name[j], "IA32_PERF_STATUS_THR_%d", i);
    j++;
  }
}

void free_batches()
{

  int i = 0;

  /*All package-scope MSRs RO*/
  for (i=0;i<PKG_MSR_COUNT_RO;i++){
	free(v_pkg_ro[i]);
  }

  /*All core-scope MSRs RO*/
  for (i=0;i<CORE_MSR_COUNT_RO;i++){
	free(v_core_ro[i]);
  }

  /*All thread-scope MSRs RO*/
  for (i=0;i<THR_MSR_COUNT_RO;i++){
	free(v_thr_ro[i]);
  }
}

/******************/
/*LDMS Functions */
/******************/

static int create_metric_set(base_data_t base)
{
    fprintf(stderr, "PATKI: ENTERED CREATE METRIC SET\n");
//    size_t meta_sz, tot_meta_sz;
//    size_t data_sz, tot_data_sz;
    int rc, metric_count;
    int metric_no;
//    int i=0;
    struct rapl_data *rd = NULL;
    uint64_t *rapl_flags = NULL;

    metric_count = 0;
    metric_no  = 0;

    ldms_schema_t schema;
/*    tot_meta_sz = 0;
    tot_data_sz = 0;

  //Set size calculation
  for (i=0; i < NUM_U64_VALS; i++)
    {
      rc = ldms_get_metric_size(msr_name[i], LDMS_V_U64,
                          &meta_sz, &data_sz);
      if (rc)
        return rc;

      tot_meta_sz += meta_sz;
      tot_data_sz += data_sz;
      metric_count++;
    }

    rc = ldms_create_set(path, tot_meta_sz, tot_data_sz, &set);

    if(rc)
        return rc;

    metric_table = calloc(metric_count, sizeof(ldms_metric_t));
    if(!metric_table)
        goto err;*/

//create a schema
    schema = base_schema_new(base);
    metric_offset = ldms_schema_metric_count_get(schema);

//Initialize libmsr
  if (init_msr()) {
    fprintf(stderr, "ERROR: Could not initialize libmsr\n");
    return -1;
 }
  //Initialize rapl
    if (rapl_init(&rd, &rapl_flags) < 0) {
     fprintf(stderr, "ERROR: Could not initialize rapl\n");
     return -1;
   }

    fprintf(stderr, "PATKI DEBUG: Before create_name_list\n");

	create_name_list();

    fprintf(stderr, "\nPATKI DEBUG: Here after create_name_list");

    for (int i=0; i < NUM_U64_VALS; i++) {
       //metric_table[metric_no] = ldms_add_metric(set, msr_name[i], LDMS_V_U64);
       rc = ldms_schema_metric_add(schema, msr_name[i], LDMS_V_U64);
       if (rc < 0) {
           rc = ENOMEM;
           goto err;
       }
       /*if(!metric_table[metric_no]) {
          rc = ENOMEM;
          goto err;
       }*/

      //ldms_set_user_data(metric_table[metric_no], comp_id);
      //metric_no++;
   }

    fprintf(stderr, "\nPATKI DEBUG: Here after schema metric addition");

  //Allocate and load batch
   load_and_allocate_batches();

   fprintf(stderr, "\nHANNEBERT DEBUG: Here after load_and_allocate_batches\n");

   set = base_set_new(base);
   if (!set) {
       rc = errno;
       goto err;
   }
   // return 0;
   return rc; //PATKI FEB 7
    err:
      free_batches();
      ldms_set_delete(set);
      return rc;

}

/*
 \brief Configuration
//note from Jessica: this might to change and most likely just becomes the default configuration text
 config name=patki component_id=<comp_id> set=<setname>
  comp_id     The component id value.
  setname     The set name.
 */
static int config(struct ldmsd_plugin *self, struct attr_value_list *kwl, struct attr_value_list *avl)
{
    fprintf(stderr, "\nPATKI DEBUG: IN CONFIG\n");
        /*char *value;
    	int rc;
        value = av_value(avl, "component_id");
        if (value)
                comp_id = strtoull(value, NULL, 0);

       value = av_value(avl, "set");
       if (value)
               rc = create_metric_set(value);
       //return 0;

       if (rc == 0)
		fprintf(stderr, "PATKI: rc was 0, all well\n");
       else
		fprintf(stderr, "PATKI: rc was 1, ERROR.\n");
      return rc;*/

	int rc;

	if (set) {
		msglog(LDMSD_LERROR, SAMP ": Set already created.\n");
		return EINVAL;
	}

	base = base_config(avl, SAMP, SAMP, msglog);
	if (!base) {
		rc = errno;
		goto err;
	}

	rc = create_metric_set(base);
	if (rc) {
		msglog(LDMSD_LERROR, SAMP ": failed to create a metric set.\n");
		goto err;
	}
	return 0;
err:
	base_del(base);
	return rc;
}

static int sample(struct ldmsd_sampler *self)
{
  int rc;

  rc=0;

  if (!set) {
      msglog(LDMSD_LERROR, "libmsr: plugin not initialized\n");
      return EINVAL;
  }

  base_sample_begin(base);
  read_and_assign();
  base_sample_end(base);

  //Seems a little silly
  return rc;

}

static ldms_set_t get_set(struct ldmsd_sampler *self)
{
        return set;
}

static void term(struct ldmsd_plugin *self)
{
        if (base)
            base_del(base);
        if (set)
            ldms_set_delete(set);
        set = NULL;
        free_batches();
}

static const char *usage(struct ldmsd_plugin *self)
{
        /*return  "config name=rapl_llnl component_id=<comp_id> set=<setname>\n";
                        "    comp_id     The component id value.\n";
                        "    setname     The set name.\n";*/
    return  "config name=" SAMP " " BASE_CONFIG_USAGE;
}

static struct ldmsd_sampler rapl_llnl_plugin = {
        .base = {
                .name = SAMP,
                .type = LDMSD_PLUGIN_SAMPLER,
                .term = term,
                .config = config,
                .usage= usage,
        },
        .get_set = get_set,
        .sample = sample,
};

struct ldmsd_plugin *get_plugin(ldmsd_msg_log_f pf)
{
        msglog = pf;
        return &rapl_llnl_plugin.base;
}

