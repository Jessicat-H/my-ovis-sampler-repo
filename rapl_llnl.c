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

static ldms_set_t set = NULL;
//static ldms_metric_t *metric_table;
static ldmsd_msg_log_f msglog;
//uint64_t comp_id;
static base_data_t base;
static int metric_offset;

/******************/
/*LDMS Functions */
/******************/

static int create_metric_set(base_data_t base)
{
    fprintf(stderr, "HANNEBERT DEBUG: in create_metric_set\n");
    ldms_schema_t schema;
	int rc, i;

	schema = base_schema_new(base);
	if (!schema) {
        fprintf(stderr, "HANNEBERT DEBUG: schema creation failed\n");
        msglog(LDMSD_LERROR,
		       "%s: The schema '%s' could not be created, errno=%d.\n",
		       __FILE__, base->schema_name, errno);
		rc = errno;
		goto err;
	}

	metric_offset = ldms_schema_metric_count_get(schema);

    //dummy metric
    rc = ldms_schema_metric_add(schema, "foo", LDMS_V_U64);
    if (rc < 0) {
        fprintf(stderr, "HANNEBERT DEBUG: adding metric failed\n");
        rc = ENOMEM;
        goto err;
    }

	set = base_set_new(base);
	if (!set) {
		rc = errno;
		goto err;
	}

	return 0;

 err:
	return rc;

}

/*
 \brief Configuration
 */
static int config(struct ldmsd_plugin *self, struct attr_value_list *kwl, struct attr_value_list *avl)
{

    fprintf(stderr, "HANNEBERT DEBUG: in config\n");
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
  fprintf(stderr, "HANNEBERT DEBUG: in sample\n");
  int rc;
  int metric_no;
  union ldms_value v;

  metric_no = metric_offset;
  rc=0;

  if (!set) {
      msglog(LDMSD_LERROR, "libmsr: plugin not initialized\n");
      return EINVAL;
  }

  base_sample_begin(base);
  //set the dummy value
  v.v_u64 = 5;
  ldms_metric_set(set, metric_no, &v);
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
}

static const char *usage(struct ldmsd_plugin *self)
{
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

