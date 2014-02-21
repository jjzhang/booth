/* -------------------------------------------------------------------------
 * booth_resource_monitord --- The monitoring of the resources which depended on the ticket.
 *   This program watches the resource that depended on the ticket.
 *   When abnormality occurs in a resource, move a ticket to other sites using booth.
 *
 * Copyright (c) 2012 NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * -------------------------------------------------------------------------
 */

#include "b_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <glib.h>
#include <sysexits.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

/* booth find myself */
#include <net/if.h>
#include <asm/types.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libxml/tree.h>

#include <crm_config.h>
#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/cib/compatibility.h>
#include <crm/error.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/mainloop.h>
#include <crm/pengine/status.h>

#include "booth_resource_monitord.h"

GMainLoop *mainloop;
char *booth_config_file;
char *pid_file;
int max_failures = 30;

GHashTable *booth_tickets;
GHashTable *tickets;
GHashTable *tmp_tickets;
GList *sites;
GList *exclude_tickets;

cib_t *cib;

crm_ipc_t *crmd_channel;
char *booth_resource_monitord_uuid;
int crmd_message_timer_id = -1;
int revoke_check_timeout = 5;
gboolean do_crmd_query = FALSE;
gboolean need_shutdown = FALSE;

void clean_up(int rc)
{
	crm_debug("Clean up to %s.", crm_system_name);

	if (cib != NULL) {
		crm_info("Clean up to CIB session.");
		cib->cmds->signoff(cib);
		cib_delete(cib);
		cib = NULL;
	}

	if (booth_config_file != NULL) {
		crm_trace("free() booth_config_file.");
		free(booth_config_file);
		booth_config_file = NULL;
	}

	if (pid_file != NULL) {
		crm_trace("free() pid_file.");
		free(pid_file);
		pid_file = NULL;
	}

	if (rc > 0) {
		crm_exit(rc);
	}
}

void free_ticket(gpointer data)
{
	GListPtr gIter = NULL;
	ticket_info_t *ticket = (ticket_info_t *) data;

	crm_debug("Free ticket name[%s]", ticket->name);

	free(ticket->name);

	for (gIter = ticket->resources; gIter != NULL; gIter = gIter->next) {
		resource_info_t *resource = (resource_info_t *) gIter->data;

		if (resource->id != NULL) {
			free(resource->id);
		}

		free(resource);
	}

	g_list_free(ticket->resources);

	free(ticket);

	return;
}

void shutdown_called(int nsig)
{
	need_shutdown = TRUE;

	crm_info("Shutdown was called. signal[%d]", nsig);

	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_main_quit(mainloop);
	} else {
		clean_up(EX_OK);
		crm_exit(0);
	}

	return;
}

void print_ticket_summary(gpointer key, gpointer value, gpointer user_data)
{
	GListPtr gIter = NULL;
	ticket_info_t *ticket = (ticket_info_t *) value;

	crm_debug
	    ("Ticket name[%s] monitored[%s] grant[%s] standby[%s] expected[%d].",
	     ticket->name, ticket->monitored ? "TRUE" : "FALSE",
	     ticket->granted ? "granted" : "revoked",
	     ticket->standby ? "TRUE" : "FALSE", ticket->expected_count);

	for (gIter = ticket->resources; gIter != NULL; gIter = gIter->next) {
		resource_info_t *rsc = (resource_info_t *) gIter->data;
		crm_debug("resource[%s] target-role[%s]",
			  rsc->id, role2text(rsc->target_role));
	}

	return;
}

void unpack_cluster_status(pe_working_set_t *data_set)
{
	xmlNode *current_cib = NULL;

	crm_trace("Unpack cluster status.");
	qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_ENABLED, QB_FALSE);

	set_working_set_defaults(data_set);
	current_cib = get_cib_copy(cib);
	data_set->input = copy_xml(current_cib);
	cluster_status(data_set);
	free_xml(current_cib);

	qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_ENABLED, QB_TRUE);

	return;
}

resource_t *find_resource_from_list(const char *search_rsc_id, GListPtr list)
{
	GListPtr gIter = NULL;
	resource_t *faund_rsc = NULL;

	crm_trace("Find rsc[%s]", search_rsc_id);
	for (gIter = list; gIter != NULL; gIter = gIter->next) {
		resource_t *rsc = (resource_t *) gIter->data;

		crm_trace("Resource id[%s].", rsc->id);

		if (g_list_length(rsc->children) > 0) {
			crm_trace("Resource id[%s] have a children.", rsc->id);
			faund_rsc =
			    find_resource_from_list(search_rsc_id,
						    rsc->children);
		}

		if (safe_str_eq(search_rsc_id, rsc->id)) {
			faund_rsc = rsc;
		}

		if (faund_rsc != NULL) {
			crm_trace("Faund resource id[%s].", faund_rsc->id);
			break;
		}
	}

	return faund_rsc;
}

void print_info_summary(int nsig)
{
	GListPtr gIter = NULL;

	for (gIter = sites; gIter != NULL; gIter = gIter->next) {
		site_info_t *site = (site_info_t *) gIter->data;
		crm_debug("Site address[%s] local[%s].",
			  site->addr, site->local ? "TRUE" : "FALSE");
	}

	g_hash_table_foreach(tickets, print_ticket_summary, NULL);

	return;
}

int grant_ticket(ticket_info_t *ticket)
{
	FILE *p;
	int rc;
	char cmd[COMMAND_MAX];
	char new_owner_ip[IPADDR_LEN];
	site_info_t *site = NULL;
	exclude_ticket_info_t *exclude_ticket = NULL;
	GListPtr gIter = NULL;
	GListPtr gIter2 = NULL;

	memset(new_owner_ip, 0, IPADDR_LEN);

	/* Set the IP of the failover destination */
	for (gIter = sites; gIter != NULL; gIter = gIter->next) {
		gboolean exclude_flag = FALSE;
		site = (site_info_t *) gIter->data;

		if (site->local)
			continue;

		for (gIter2 = exclude_tickets; gIter2 != NULL;
		     gIter2 = gIter2->next) {
			exclude_ticket = (exclude_ticket_info_t *) gIter2->data;

			if (safe_str_eq(ticket->name, exclude_ticket->ticket) &&
			    safe_str_eq(site->addr, exclude_ticket->site))
				exclude_flag = TRUE;
		}

		if (exclude_flag) {
			crm_debug("Site address[%s] is exclude site",
				  site->addr);
			continue;
		}

		crm_debug
		    ("The site[%s] was chosen as the movement place of a ticket.",
		     site->addr);
		strcpy(new_owner_ip, site->addr);

		break;
	}

	if (strlen(new_owner_ip) == 0) {
		crm_err("Failed to select the destination of the ticket.");
		return -1;
	}

	/* used site is turned back */
	sites = g_list_remove(sites, site);
	sites = g_list_append(sites, site);

	snprintf(cmd, COMMAND_MAX, "booth client grant -t %s -s %s",
		 ticket->name, new_owner_ip);

	crm_info("Command: '%s' was executed", cmd);
	p = popen(cmd, "r");

	if (p == NULL) {
		crm_perror(LOG_ERR, "popen() call failed");
		return -1;
	}

	rc = pclose(p);

	if (rc == -1) {
		crm_perror(LOG_ERR, "pclose() call failed");
		return -1;
	} else if (rc > 0) {
		crm_err("Failed to execute booth command. exit code %d",
			WEXITSTATUS(rc));
		return -1;
	}

	crm_info("Ticket[%s] was granted to %s.", ticket->name, new_owner_ip);

	return 0;
}

int revoke_ticket(ticket_info_t *ticket)
{
	FILE *p;
	int rc;
	char cmd[COMMAND_MAX];
	char owner_ip[IPADDR_LEN];
	GListPtr gIter = NULL;

	memset(owner_ip, 0, IPADDR_LEN);

	/* use own site ip */
	for (gIter = sites; gIter != NULL; gIter = gIter->next) {
		site_info_t *site = (site_info_t *) gIter->data;

		crm_trace("site address[%s].", site->addr);

		if (site->local) {
			crm_info("%s is own site address.", site->addr);
			strcpy(owner_ip, site->addr);

			break;
		}
	}

	if (strlen(owner_ip) == 0) {
		crm_err("Failed to pick the holder of the ticket.");
		return -1;
	}

	snprintf(cmd, COMMAND_MAX, "booth client revoke -t %s -s %s",
		 ticket->name, owner_ip);

	crm_info("Command: '%s' was executed", cmd);
	p = popen(cmd, "r");

	if (p == NULL) {
		crm_perror(LOG_ERR, "popen() call failed");
		return -1;
	}

	rc = pclose(p);

	if (rc == -1) {
		crm_perror(LOG_ERR, "pclose() call failed");
		return -1;
	} else if (rc > 0) {
		crm_err("Failed to execute booth command. exit code %d",
			WEXITSTATUS(rc));
		return -1;
	}

	crm_info("Ticket[%s] was revoked by %s.", ticket->name, owner_ip);

	return 0;
}

void update_tickets_info(gpointer key, gpointer value, gpointer user_data)
{
	ticket_info_t *manage_ticket = (ticket_info_t *) value;
	ticket_t *cluster_ticket = NULL;
	pe_working_set_t *data_set = NULL;

	if (user_data == NULL) {
		crm_err("Failed to unpack cluster status.");
		return;
	}

	data_set = (pe_working_set_t *) user_data;

	cluster_ticket =
	    g_hash_table_lookup(data_set->tickets, manage_ticket->name);

	if (cluster_ticket == NULL) {
		crm_info("State of the ticket[%s] is not yet in the cluster.",
			 manage_ticket->name);
		return;
	}

	manage_ticket->granted = cluster_ticket->granted;
	manage_ticket->standby = cluster_ticket->standby;

	crm_trace
	    ("Ticket name[%s] monitored[%s] grant[%s] standby[%s] expected[%d].",
	     manage_ticket->name, manage_ticket->monitored ? "TRUE" : "FALSE",
	     manage_ticket->granted ? "granted" : "revoked",
	     manage_ticket->standby ? "TRUE" : "FALSE",
	     manage_ticket->expected_count);

	return;
}

void failover_ticket(gpointer key, gpointer value, gpointer user_data)
{
	int rc, i;
	gboolean revoke_succeed = FALSE;
	pe_working_set_t data_set;
	ticket_info_t *manage_ticket = (ticket_info_t *) value;
	ticket_t *cluster_ticket = NULL;

	if (manage_ticket->failover != TRUE) {
		crm_trace("Ticket[%s] does not have to failover it.",
			  manage_ticket->name);
		return;
	}

	crm_info("Failover ticket[%s].", manage_ticket->name);

	rc = revoke_ticket(manage_ticket);

	if (rc != 0) {
		crm_err("Failed in revoke of ticket[%s].", manage_ticket->name);
		manage_ticket->failover = FALSE;
		return;
	}

	/* check the completion of the revoke */
	for (i = 0; i <= revoke_check_timeout; i++) {
		const char *owner = NULL;
		const char *expires = NULL;

		unpack_cluster_status(&data_set);

		cluster_ticket =
		    g_hash_table_lookup(data_set.tickets, manage_ticket->name);

		if (cluster_ticket == NULL) {
			crm_err("Failed to get information for the ticket[%s], "
				"can not confirm the success of the revoke.",
				manage_ticket->name);
			cleanup_calculations(&data_set);
			manage_ticket->failover = FALSE;
			return;
		}

		owner = g_hash_table_lookup(cluster_ticket->state, "owner");
		expires = g_hash_table_lookup(cluster_ticket->state, "expires");

		crm_debug("ticket[%s] granted=%s owner=%s expires=%s",
			  cluster_ticket->id,
			  cluster_ticket->granted ? "true" : "false", owner,
			  expires);

		if (cluster_ticket->granted == FALSE &&
		    safe_str_eq(owner, "NO_OWNER") && safe_str_eq(expires, "0")) {
			revoke_succeed = TRUE;
			cleanup_calculations(&data_set);

			break;
		}

		cleanup_calculations(&data_set);
		sleep(1);
	}

	if (revoke_succeed == FALSE) {
		crm_err("Failed in revoke of ticket[%s]. Reason: Timeout.",
			manage_ticket->name);
		manage_ticket->failover = FALSE;
		return;
	}

	rc = grant_ticket(manage_ticket);

	if (rc != 0) {
		crm_err("Failed in grant of ticket[%s].", manage_ticket->name);
		manage_ticket->failover = FALSE;
		return;
	}

	crm_info("Ticket[%s] failover succeeded.", manage_ticket->name);
	manage_ticket->failover = FALSE;

	return;
}

int check_ticket_condition(ticket_info_t *manage_ticket)
{
	crm_trace
	    ("Ticket name[%s] monitored[%s] grant[%s] standby[%s] expected[%d].",
	     manage_ticket->name, manage_ticket->monitored ? "TRUE" : "FALSE",
	     manage_ticket->granted ? "granted" : "revoked",
	     manage_ticket->standby ? "TRUE" : "FALSE",
	     manage_ticket->expected_count);

	/* The state of a ticket checks in "revoke" or "standby" */
	if (manage_ticket->granted == FALSE || manage_ticket->standby == TRUE) {
		crm_debug("Ticket[%s] is revoked or standby.",
			  manage_ticket->name);
		return 1;
	}

	return 0;
}

int
check_resource_role(resource_t *cluster_resource,
		    resource_info_t *manage_resource)
{
	gboolean flag;
	enum rsc_role_e rsc_target_role;

	crm_trace("Cluster resource id[%s] is role[%s].",
		  cluster_resource->id, role2text(cluster_resource->role));

	/* If the role of the resource is specified by the user */
	flag = get_target_role(cluster_resource, &rsc_target_role);

	if (flag && manage_resource->target_role != rsc_target_role) {
		crm_trace("Cluster resource id[%s] target-role[%s].",
			  cluster_resource->id, role2text(rsc_target_role));
		return -1;
	}

	/* When role of the resource becomes prospective role */
	if (cluster_resource->role == manage_resource->target_role) {
		crm_trace("Role[%s] of the resource[%s] is expected role.",
			  role2text(cluster_resource->role),
			  cluster_resource->id);
		return 1;
	}

	crm_trace("Role[%s] of the resource[%s] is not expected role[%s].",
		  role2text(cluster_resource->role),
		  cluster_resource->id,
		  role2text(manage_resource->target_role));

	/* When role of the resource does not become prospective role */
	return 0;
}

void
check_ticket_failover_need(gpointer key, gpointer value, gpointer user_data)
{
	int rc;
	int count = 0;
	GListPtr gIter = NULL;
	ticket_info_t *manage_ticket = (ticket_info_t *) value;
	GListPtr cluster_resource_list = (GListPtr) user_data;

	/* Determine whether there is a need for failover */
	rc = check_ticket_condition(manage_ticket);

	if (rc != 0) {
		crm_info("Ticket name[%s] is not a condition to be monitored.",
			 manage_ticket->name);
		manage_ticket->monitored = FALSE;
		manage_ticket->failover = FALSE;
		return;
	}

	for (gIter = manage_ticket->resources; gIter != NULL;
	     gIter = gIter->next) {
		resource_info_t *manage_resource =
		    (resource_info_t *) gIter->data;
		resource_t *cluster_resource = NULL;

		crm_trace("Ticket[%s] find resource[%s].",
			  manage_ticket->name, manage_resource->id);

		cluster_resource = find_resource_from_list(manage_resource->id,
							   cluster_resource_list);

		if (cluster_resource == NULL) {
			crm_err("Resource[%s] is not found in the cluster."
				" This resource is ignored.",
				manage_resource->id);

			continue;
		}

		/* check role of the resource */
		rc = check_resource_role(cluster_resource, manage_resource);

		if (rc == 1) {
			crm_debug("Role of resources[%s] is expected role.",
				  cluster_resource->id);
			count = count + 1;
		} else if (rc == -1) {
			crm_warn("Role of resources[%s] was changed explicitly."
				 " Stop the monitoring of the ticket[%s].",
				 cluster_resource->id, manage_ticket->name);
			manage_ticket->monitored = FALSE;
			return;
		} else {
			crm_warn("Role of resources[%s] is not expected role.",
				 cluster_resource->id);
		}
	}

	crm_trace("expected count[%d] vs real count[%d].",
		  manage_ticket->expected_count, count);

	if (manage_ticket->expected_count == count) {
		crm_info
		    ("All the resources depending on ticket name[%s] started or promoted.",
		     manage_ticket->name);
		manage_ticket->monitored = TRUE;

	} else if (manage_ticket->monitored
		   && manage_ticket->expected_count != count) {
		crm_info("Ticket name[%s] is required for failover.",
			 manage_ticket->name);
		manage_ticket->monitored = FALSE;
		manage_ticket->failover = TRUE;
	}

	return;
}

void start_resource_monitor(void)
{
	pe_working_set_t data_set;

	crm_trace("Start resource monitor.");
	unpack_cluster_status(&data_set);

	/* update a ticket in the latest CIB information */
	g_hash_table_foreach(tickets, update_tickets_info, &data_set);

	/* determine whether failover of the ticket is necessary */
	g_hash_table_foreach(tickets, check_ticket_failover_need,
			     data_set.resources);

	/* failover of a ticket is performed */
	g_hash_table_foreach(tickets, failover_ticket, NULL);

	print_info_summary(0);

	cleanup_calculations(&data_set);
	crm_trace("End resource monitor.");

	return;
}

gboolean docHasTag(xmlNode *root, const char *tag)
{
	xmlNode *child = NULL;

	crm_trace("Find tag[%s]", tag);

	for (child = __xml_first_child(root); child != NULL;
	     child = __xml_next(child)) {

		if (safe_str_eq((const char *)child->name, tag)) {
			crm_trace("Faund tag[%s]", (const char *)child->name);
			return TRUE;
		}

		if (child->children) {
			crm_trace("xmlNode[%s] has children",
				  (const char *)child->name);

			if (docHasTag(child, tag)) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

int
search_xml_children(GListPtr *children, xmlNode *root, const char *tag,
		    const char *field, const char *value,
		    gboolean search_matches)
{
	int match_found = 0;

	CRM_CHECK(root != NULL, return FALSE);
	CRM_CHECK(children != NULL, return FALSE);

	if (tag != NULL && safe_str_neq(tag, crm_element_name(root))) {

	} else if (value != NULL
		   && safe_str_neq(value, crm_element_value(root, field))) {

	} else {
		*children = g_list_append(*children, root);
		match_found = 1;
	}

	if (search_matches || match_found == 0) {
		xmlNode *child = NULL;

		for (child = __xml_first_child(root); child;
		     child = __xml_next(child)) {
			match_found +=
			    search_xml_children(children, child, tag, field,
						value, search_matches);
		}
	}

	return match_found;
}

void
register_monitor_resource(ticket_info_t *ticket, resource_t *resource,
			  enum rsc_role_e target_role)
{
	resource_info_t *manage_resource = NULL;

	if (resource->variant != pe_native) {
		crm_debug
		    ("Resource id[%s] type is not primitive, does not register.",
		     resource->id);
		return;
	}

	if (is_set(resource->flags, pe_rsc_orphan)) {
		crm_notice("Resource id[%s] is ORPHAN, does not register.",
			   resource->id);
		return;
	}

	manage_resource = calloc(1, sizeof(resource_info_t));
	memset(manage_resource, 0, sizeof(resource_info_t));

	manage_resource->id = strdup(resource->id);
	manage_resource->target_role = target_role;
	manage_resource->variant = resource->variant;

	crm_info
	    ("Registered ticket[%s] monitor resource[%s] set target role [%s].",
	     ticket->name, manage_resource->id, role2text(target_role));

	ticket->resources = g_list_append(ticket->resources, manage_resource);

	return;
}

void
register_monitor_resource_children(ticket_info_t *ticket, GListPtr list,
				   enum rsc_role_e target_role)
{
	GListPtr gIter = NULL;

	for (gIter = list; gIter != NULL; gIter = gIter->next) {
		resource_t *rsc = (resource_t *) gIter->data;

		if (g_list_length(rsc->children) > 0) {
			crm_trace("Resource id[%s] have a children.", rsc->id);
			register_monitor_resource_children(ticket,
							   rsc->children,
							   target_role);
		}

		register_monitor_resource(ticket, rsc, target_role);
	}

	return;
}

void
create_ticket_info(xmlNode *rsc_ticket, gboolean update,
		   pe_working_set_t *data_set)
{
	ticket_info_t *ticket = NULL;
	const char *id = NULL;
	const char *ticket_name = NULL;
	const char *ticket_target_role = NULL;
	enum rsc_role_e target_role;
	int child_count = 1;
	resource_t *child = NULL;

	id = crm_element_value(rsc_ticket, XML_ATTR_ID);
	ticket_name = crm_element_value(rsc_ticket, XML_TICKET_ATTR_TICKET);
	crm_debug("rsc_ticket id[%s] name[%s]", id, ticket_name);

	/* check whether it is a ticket managed in booth */
	if (g_hash_table_lookup(booth_tickets, ticket_name) == NULL) {
		crm_info("Ticket name[%s] is not managed in booth.",
			 ticket_name);
		return;
	}

	crm_trace("Ticket name[%s] is managed in booth.", ticket_name);

	ticket = g_hash_table_lookup(tmp_tickets, ticket_name);

	if (ticket == NULL) {
		ticket = calloc(1, sizeof(ticket_info_t));
		memset(ticket, 0, sizeof(ticket_info_t));
		ticket->name = strdup(ticket_name);
		ticket->need_delete = FALSE;
		g_hash_table_insert(tmp_tickets, ticket->name, ticket);
	}

	/* acquire the value of the rsc-role attribute of rsc_ticket */
	ticket_target_role =
	    crm_element_value(rsc_ticket, XML_COLOC_ATTR_SOURCE_ROLE);

	if (ticket_target_role == NULL) {
		target_role = RSC_ROLE_STARTED;
	} else {
		target_role = text2role(ticket_target_role);
	}

	/* When rsc_ticket has rsc attribute */
	if (xmlHasProp(rsc_ticket, (const xmlChar*)"rsc")) {
		resource_t *cluster_resource = NULL;
		const char *rsc_id = NULL;
		const char *clone_max = NULL;
		const char *master_max = NULL;

		rsc_id = crm_element_value(rsc_ticket, "rsc");
		cluster_resource =
		    find_resource_from_list(rsc_id, data_set->resources);

		if (cluster_resource == NULL) {
			crm_err
			    ("Resource id[%s] to depend on the ticket was not found.",
			     rsc_id);
			return;
		}

		/* The number of resources is registered into management information */
		switch (cluster_resource->variant) {

		case pe_native:
			crm_trace("Resource[%s] is native.",
				  cluster_resource->id);

			register_monitor_resource(ticket, cluster_resource,
						  target_role);

			ticket->expected_count = ticket->expected_count + 1;

			break;
		case pe_group:
			crm_trace("Resource[%s] is group.",
				  cluster_resource->id);

			register_monitor_resource_children(ticket,
							   cluster_resource->children,
							   target_role);

			ticket->expected_count = ticket->expected_count +
			    g_list_length(cluster_resource->children);

			break;
		case pe_clone:
			crm_trace("Resource[%s] is clone.",
				  cluster_resource->id);

			register_monitor_resource_children(ticket,
							   cluster_resource->children,
							   target_role);

			clone_max = g_hash_table_lookup(cluster_resource->meta,
							XML_RSC_ATTR_INCARNATION_MAX);

			child =
			    (resource_t *)
			    g_list_nth_data(cluster_resource->children, 0);

			if (child != NULL && child->variant == pe_group) {
				child_count = g_list_length(child->children);
			}

			if (clone_max != NULL) {
				crm_trace("Clone resource[%s] clone_max[%s].",
					  cluster_resource->id, clone_max);
				ticket->expected_count =
				    ticket->expected_count +
				    crm_parse_int(clone_max,
						  NULL) * child_count;
			} else {
				/* When there is no setup of clone_max, the number of nodes is set up */
				crm_trace("Clone resource[%s] node num[%d].",
					  cluster_resource->id,
					  g_list_length(data_set->nodes));
				ticket->expected_count =
				    ticket->expected_count +
				    g_list_length(data_set->nodes) *
				    child_count;
			}

			break;
		case pe_master:
			crm_trace("Resource[%s] is master.",
				  cluster_resource->id);

			register_monitor_resource_children(ticket,
							   cluster_resource->children,
							   target_role);

			child =
			    (resource_t *)
			    g_list_nth_data(cluster_resource->children, 0);

			if (child != NULL && child->variant == pe_group) {
				child_count = g_list_length(child->children);
			}

			if (target_role == RSC_ROLE_STARTED) {
				clone_max =
				    g_hash_table_lookup(cluster_resource->meta,
							XML_RSC_ATTR_INCARNATION_MAX);

				if (clone_max != NULL) {
					crm_trace
					    ("Clone resource[%s] clone_max[%s].",
					     cluster_resource->id, clone_max);
					ticket->expected_count =
					    ticket->expected_count +
					    crm_parse_int(clone_max,
							  NULL) * child_count;
				} else {
					/* When there is no setup of clone_max, the number of nodes is set up */
					crm_trace
					    ("Clone resource[%s] node num[%d].",
					     cluster_resource->id,
					     g_list_length(data_set->nodes));
					ticket->expected_count =
					    ticket->expected_count +
					    g_list_length(data_set->nodes) *
					    child_count;
				}
			} else {
				master_max =
				    g_hash_table_lookup(cluster_resource->meta,
							XML_RSC_ATTR_MASTER_MAX);

				if (master_max != NULL) {
					crm_trace
					    ("Master resource[%s] master_max[%s].",
					     cluster_resource->id, master_max);
					ticket->expected_count =
					    ticket->expected_count +
					    crm_parse_int(master_max,
							  NULL) * child_count;
				} else {
					/* When there is no setup of master_max, 1 is set up as a default value */
					crm_trace
					    ("Master resource[%s] master_max is 1.",
					     cluster_resource->id);
					ticket->expected_count =
					    ticket->expected_count +
					    1 * child_count;
				}
			}

			break;
		default:
			crm_warn("Unknown type resource[%s].",
				 cluster_resource->id);
			break;
		}

	} else {
		/* TODO: At a present stage, it does not correspond to the notation of resource_set */
		crm_warn("rsc_ticket(id=%s) is notation which does not support."
			 " Ignore this rsc_ticket constraint.", id);
		return;
	}

	crm_debug("Ticket name[%s] expected count[%d].",
		  ticket->name, ticket->expected_count);

	return;
}

ticket_info_t *copy_ticket_info(ticket_info_t *copy_ticket)
{
	GListPtr gIter = NULL;
	ticket_info_t *ticket = NULL;

	ticket = calloc(1, sizeof(ticket_info_t));
	ticket = memcpy(ticket, copy_ticket, sizeof(ticket_info_t));
	ticket->name = strdup(copy_ticket->name);
	ticket->resources = NULL;

	for (gIter = copy_ticket->resources; gIter != NULL; gIter = gIter->next) {
		resource_info_t *copy_resource =
		    (resource_info_t *) gIter->data;
		resource_info_t *resource = NULL;

		resource = calloc(1, sizeof(resource_info_t));
		resource =
		    memcpy(resource, copy_resource, sizeof(resource_info_t));
		resource->id = strdup(copy_resource->id);

		crm_debug("Copy resource [%s]", resource->id);
		ticket->resources = g_list_append(ticket->resources, resource);
	}

	return ticket;
}

int compare_resource(GListPtr rsc_list, resource_info_t *rsc)
{
	GListPtr gIter = NULL;

	crm_trace("Compare resource id[%s]", rsc->id);

	for (gIter = rsc_list; gIter != NULL; gIter = gIter->next) {
		resource_info_t *register_rsc = (resource_info_t *) gIter->data;
		crm_trace("Compare resource id[%s]", register_rsc->id);

		if (safe_str_eq(rsc->id, register_rsc->id)) {
			crm_debug("Match resource id[%s]", register_rsc->id);

			if (rsc->target_role == register_rsc->target_role) {
				crm_debug
				    ("Role of resource id[%s] not changed.",
				     rsc->id);
				return 0;
			}
		}

	}

	return 1;
}

int
compare_ticket_info(ticket_info_t *tmp_ticket, ticket_info_t *register_ticket)
{
	int rc;
	GListPtr gIter = NULL;

	crm_trace("Compare ticket name[%s]", tmp_ticket->name);

	if (g_list_length(tmp_ticket->resources) !=
	    g_list_length(register_ticket->resources)) {
		crm_debug
		    ("The number of the resources to watch of ticket name[%s] changed.",
		     tmp_ticket->name);
		return 1;
	}

	for (gIter = tmp_ticket->resources; gIter != NULL; gIter = gIter->next) {
		resource_info_t *rsc = (resource_info_t *) gIter->data;

		rc = compare_resource(register_ticket->resources, rsc);

		if (rc != 0) {
			crm_debug("Resource of ticket name[%s] changed.",
				  tmp_ticket->name);
			return 1;
		}
	}

	return 0;
}

void register_tickets(gpointer key, gpointer value, gpointer user_data)
{
	int rc;
	gboolean complete;
	ticket_info_t *tmp_ticket = (ticket_info_t *) value;
	ticket_info_t *register_ticket = NULL;

	crm_debug("Register ticket name[%s]", tmp_ticket->name);

	register_ticket = g_hash_table_lookup(tickets, tmp_ticket->name);

	if (register_ticket == NULL) {
		register_ticket = copy_ticket_info(tmp_ticket);
		crm_info("Register new information ticket name[%s].",
			 register_ticket->name);
		g_hash_table_insert(tickets, register_ticket->name,
				    register_ticket);
		return;
	}

	rc = compare_ticket_info(tmp_ticket, register_ticket);

	if (rc != 0) {
		crm_info("Ticket name[%s] was changed.", register_ticket->name);
		tmp_ticket->monitored = register_ticket->monitored;
		complete = g_hash_table_remove(tickets, register_ticket->name);

		if (complete != TRUE) {
			crm_err("Failed to delete registered ticket");
			return;
		}

		register_ticket = copy_ticket_info(tmp_ticket);
		g_hash_table_insert(tickets, register_ticket->name,
				    register_ticket);
	} else {
		crm_info("Ticket name[%s] was no changed.",
			 register_ticket->name);
		register_ticket->need_delete = FALSE;
	}

	return;
}

void delete_unnecessary_ticket(gpointer key, gpointer value, gpointer user_data)
{
	gboolean complete;
	ticket_info_t *ticket = (ticket_info_t *) value;

	if (ticket->need_delete == FALSE) {
		ticket->need_delete = TRUE;
		return;
	}

	/* The information on the ticket deleted from cib
	 * information is deleted from management information
	 */
	crm_info("Delete unnecessary ticket name[%s].", ticket->name);
	complete = g_hash_table_remove(tickets, ticket->name);

	if (complete != TRUE) {
		crm_err("Failed to delete registered ticket");
	}

	return;
}

void create_information(void)
{
	int match_num;
	GListPtr match_list = NULL;
	GListPtr gIter = NULL;
	pe_working_set_t data_set;
	xmlNode *current_cib = NULL;

	tmp_tickets =
	    g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, free_ticket);

	if (tickets == NULL) {
		tickets =
		    g_hash_table_new_full(crm_str_hash, g_str_equal, NULL,
					  free_ticket);
	}

	current_cib = get_cib_copy(cib);
	/* find rsc_ticket from CIB information */
	match_num = search_xml_children(&match_list, current_cib,
					XML_CONS_TAG_RSC_TICKET, NULL, NULL,
					TRUE);

	if (match_num == 0) {
		crm_warn("CIB does not have information of <%s>.",
			 XML_CONS_TAG_RSC_TICKET);
		goto out;
	}

	unpack_cluster_status(&data_set);

	for (gIter = match_list; gIter != NULL; gIter = gIter->next) {
		xmlNode *match = NULL;

		match = (xmlNode *) gIter->data;
		create_ticket_info(match, FALSE, &data_set);
	}

	free_xml(current_cib);
	cleanup_calculations(&data_set);

out:
	g_hash_table_foreach(tmp_tickets, register_tickets, NULL);
	g_hash_table_destroy(tmp_tickets);
	g_hash_table_foreach(tickets, delete_unnecessary_ticket, NULL);

	return;
}

int do_dc_health(void)
{
	gboolean rc;
	const char *sys_to = NULL;
	const char *crmd_operation = NULL;
	xmlNode *msg_data = NULL;
	xmlNode *cmd = NULL;

	sys_to = CRM_SYSTEM_DC;
	crmd_operation = CRM_OP_PING;

	crm_trace("Do dc health.");

	if (crmd_channel == NULL) {
		crm_err
		    ("The IPC connection is not valid, cannot send anything");
		return 1;
	}

	cmd = create_request(crmd_operation, msg_data, NULL, sys_to,
			     crm_system_name, booth_resource_monitord_uuid);

	/* send it */
	crm_trace("Send health check message.");
	rc = crm_ipc_send(crmd_channel, cmd, 0, 0, NULL);

	if (rc == FALSE) {
		crm_err("Failed to send ipc messege to CRMd.");
		return 1;
	}

	free_xml(cmd);

	return 0;
}

gboolean do_dc_health_start(gpointer data)
{
	int rc = 0;

	rc = do_dc_health();

	if (rc != 0) {
		crm_err("Failed in a state inquiry of DC.");
		clean_up(1);
	}

	return FALSE;
}

void cib_diff_notify(const char *event, xmlNode *msg)
{
	int rc = -1;
	const char *op = NULL;
	const char *value = NULL;
	unsigned int log_level = LOG_INFO;
	int crmd_transition_delay = 0;
	pe_working_set_t data_set;

	xmlNode *diff = NULL;
	xmlNode *update = get_message_xml(msg, F_CIB_UPDATE);

	if (msg == NULL) {
		crm_err("NULL update");
		return;
	}

	crm_element_value_int(msg, F_CIB_RC, &rc);
	op = crm_element_value(msg, F_CIB_OPERATION);
	diff = get_message_xml(msg, F_CIB_UPDATE_RESULT);

	if (rc < pcmk_ok) {
		log_level = LOG_WARNING;
		do_crm_log(log_level, "[%s] %s ABORTED: %s",
			   event, op, pcmk_strerror(rc));
		return;
	}

	if (diff) {
		crm_log_xml_trace(diff, "cib_diff");

		/* It is checked whether change has been in configuration */
		if (docHasTag(diff, XML_CIB_TAG_CONFIGURATION)) {
			crm_trace("Change configuration.");
			create_information();
		} else {
			crm_trace("Not change configuration.");
		}

		log_cib_diff(LOG_TRACE, diff, op);
	}

	if (update != NULL) {
		crm_log_xml_trace(update, "raw_update");
	}

	unpack_cluster_status(&data_set);

	value =
	    g_hash_table_lookup(data_set.config_hash, "crmd-transition-delay");
	crmd_transition_delay = crm_get_msec(value);

	if (crmd_transition_delay < 0) {
		crmd_transition_delay = 0;
	}

	cleanup_calculations(&data_set);
	crm_trace("Set crmd-transition-delay is %d msec",
		  crmd_transition_delay);

	/* Nothing will be done if it has asked DC */
	if (do_crmd_query) {
		crm_trace("Already queried crmd.");
		goto out;
	}

	/* The state of DC is checked */
	crm_trace("Query for dc health.");
	do_crmd_query = TRUE;
	g_timeout_add(crmd_transition_delay + 1000, do_dc_health_start, NULL);

out:
	return;
}

void usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s [-%s]\n", cmd, OPTARGS);
	fprintf(stream, "	Basic options\n");
	fprintf(stream,
		"\t--%s (-%c) <filename>\t\tFile in which to store the process' PID\n"
		"\t\t\t\t\t\t* Default=%s\n", "pid-file", 'p', PID_FILE);
	fprintf(stream,
		"\t--%s (-%c) <filename>\t\tAppoint a place with booth.conf.\n"
		"\t\t\t\t\t\t* Default=%s\n", "booth-config", 'b',
		BOOTH_CONFIG_FILE);
	fprintf(stream, "\t--%s (-%c) \t\t\tRun in daemon mode\n", "daemonize",
		'D');
	fprintf(stream, "\t--%s (-%c) \t\t\t\tRun in verbose mode\n", "verbose",
		'V');
	fprintf(stream, "\t--%s (-%c) \t\t\t\tThis text\n", "help", 'h');

	fflush(stream);

	clean_up(exit_status);
}

void cib_connection_destroy(gpointer user_data)
{
	cib_t *conn = user_data;

	/* Ensure IPC is cleaned up */
	conn->cmds->signoff(conn);

	if (need_shutdown) {
		crm_info("Connection to the CIB terminated.");
	} else {
		crm_err("Connection to the CIB terminated.");
		clean_up(1);
	}

	return;
}

int cib_connect(void)
{
	int rc = -ENOTCONN;
	int attempts = 0;

	cib = cib_new();

	while (rc != pcmk_ok && attempts++ < max_failures) {
		crm_trace("Connecting to CIB. attempt %d", attempts);
		rc = cib->cmds->signon(cib, crm_system_name, cib_query);

		if (rc != pcmk_ok) {
			crm_trace("Waiting signing on to the CIB service\n");
			sleep(1);
		}
	}

	if (rc != pcmk_ok) {
		crm_err("Signon to CIB failed: %s", pcmk_strerror(rc));
		return rc;
	}

	if (rc == pcmk_ok) {
		/* set a function called at the time of CIB cutting */
		crm_trace("Setting dnotify.");
		rc = cib->cmds->set_connection_dnotify(cib,
						       cib_connection_destroy);

		if (rc != pcmk_ok) {
			crm_err("Failed to setting dnotify: %s",
				pcmk_strerror(rc));
			return rc;
		}

		/* set a function called at the time of CIB change */
		crm_trace("Setting notify callback.");
		rc = cib->cmds->add_notify_callback(cib, T_CIB_DIFF_NOTIFY,
						    cib_diff_notify);

		if (rc != pcmk_ok) {
			crm_err("Failed to setting notify callback: %s",
				pcmk_strerror(rc));
			return rc;
		}
	}

	return rc;
}

void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	while (RTA_OK(rta, len)) {

		if (rta->rta_type <= max) {
			tb[rta->rta_type] = rta;
		}

		rta = RTA_NEXT(rta, len);
	}
}

int search_self_node_ip(site_info_t *site)
{
	int fd, addrlen, found = 0;
	struct sockaddr_nl nladdr;
	unsigned char ndaddr[IPADDR_LEN];
	unsigned char ipaddr[IPADDR_LEN];
	static char rcvbuf[NETLINK_BUFSIZE];
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

	memset(ipaddr, 0, IPADDR_LEN);
	memset(ndaddr, 0, IPADDR_LEN);

	if (site->family == AF_INET) {
		inet_pton(AF_INET, site->addr, ndaddr);
		addrlen = sizeof(struct in_addr);
	} else if (site->family == AF_INET6) {
		inet_pton(AF_INET6, site->addr, ndaddr);
		addrlen = sizeof(struct in6_addr);
	} else {
		crm_err("Invalid INET family");
		return 0;
	}

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if (fd < 0) {
		crm_err("Failed to create netlink socket");
		return 0;
	}

	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETADDR;
	req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = 1;
	req.g.rtgen_family = AF_INET;

	if (sendto(fd, (void *)&req, sizeof(req), 0,
		   (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
		close(fd);
		crm_err("Failed to send data to netlink socket");
		return 0;
	}

	while (1) {
		int status;
		struct nlmsghdr *h;
		struct iovec iov = { rcvbuf, sizeof(rcvbuf) };
		struct msghdr msg = {
			(void *)&nladdr, sizeof(nladdr),
			&iov, 1,
			NULL, 0,
			0
		};

		status = recvmsg(fd, &msg, 0);

		if (status <= 0) {
			close(fd);
			crm_err("Failed to recvmsg from netlink socket");
			return 0;
		}

		h = (struct nlmsghdr *)rcvbuf;

		if (h->nlmsg_type == NLMSG_DONE)
			break;

		if (h->nlmsg_type == NLMSG_ERROR) {
			close(fd);
			crm_err("Netlink socket recvmsg error");
			return 0;
		}

		while (NLMSG_OK(h, status)) {

			if (h->nlmsg_type == RTM_NEWADDR) {
				struct ifaddrmsg *ifa = NLMSG_DATA(h);
				struct rtattr *tb[IFA_MAX + 1];
				int len = h->nlmsg_len
				    - NLMSG_LENGTH(sizeof(*ifa));

				memset(tb, 0, sizeof(tb));
				parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), len);
				memcpy(ipaddr, RTA_DATA(tb[IFA_ADDRESS]),
				       IPADDR_LEN);

				if (!memcmp(ipaddr, ndaddr, addrlen)) {
					found = 1;
					goto out;
				}

			}

			h = NLMSG_NEXT(h, status);
		}
	}

out:
	close(fd);
	return found;
}

int read_booth_config(void)
{
	char line[1024];
	FILE *fp;
	char *s, *key, *val, *expiry, *weight;
	int in_quotes, got_equals, got_quotes;
	int lineno = 0;
	int rc = 0;
	int fclose_rc;

	booth_tickets = g_hash_table_new(crm_str_hash, g_str_equal);

	fp = fopen(booth_config_file, "r");

	if (!fp) {
		crm_err("Failed to open %s: %s", booth_config_file,
			strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		lineno++;
		s = line;

		while (*s == ' ')
			s++;

		if (*s == '#' || *s == '\n')
			continue;

		if (*s == '-' || *s == '.' || *s == '/'
		    || *s == '+' || *s == '(' || *s == ')'
		    || *s == ':' || *s == ',' || *s == '@'
		    || *s == '=' || *s == '"') {
			crm_err("Invalid key name in config file "
				"('%c', line %d char %ld)", *s, lineno,
				(long)(s - line));
			rc = -1;
			goto out;
		}

		key = s;	/* will point to the key on the left hand side  */
		val = NULL;	/* will point to the value on the right hand side */
		in_quotes = 0;	/* true iff we're inside a double-quoted string   */
		got_equals = 0;	/* true iff we're on the RHS of the = assignment  */
		got_quotes = 0;	/* true iff the RHS is quoted                    */

		while (*s != '\n' && *s != '\0') {
			if (!(*s >= 'a' && *s <= 'z')
			    && !(*s >= 'A' && *s <= 'Z')
			    && !(*s >= '0' && *s <= '9')
			    && !(*s == '_')
			    && !(*s == '-')
			    && !(*s == '.')
			    && !(*s == '/')
			    && !(*s == ' ')
			    && !(*s == '+')
			    && !(*s == '(')
			    && !(*s == ')')
			    && !(*s == ':')
			    && !(*s == ';')
			    && !(*s == ',')
			    && !(*s == '@')
			    && !(*s == '=')
			    && !(*s == '"')) {
				crm_err
				    ("Invalid character ('%c', line %d char %ld)"
				     " in config file", *s, lineno,
				     (long)(s - line));
				rc = -1;
				goto out;
			}

			if (*s == '=' && !got_equals) {
				got_equals = 1;
				*s = '\0';
				val = s + 1;
			} else
			    if ((*s == '=' || *s == '_' || *s == '-'
				 || *s == '.')
				&& got_equals && !in_quotes) {
				crm_err
				    ("Invalid config file format: unquoted '%c' "
				     "(line %d char %ld)", *s, lineno,
				     (long)(s - line));
				rc = -1;
				goto out;
			} else if ((*s == '/' || *s == '+'
				    || *s == '(' || *s == ')' || *s == ':'
				    || *s == ',' || *s == '@') && !in_quotes) {
				crm_err
				    ("Invalid config file format: unquoted '%c' "
				     "(line %d char %ld)", *s, lineno,
				     (long)(s - line));
				rc = -1;
				goto out;
			} else if ((*s == ' ')
				   && !in_quotes && !got_quotes) {
				crm_err
				    ("Invalid config file format: unquoted whitespace "
				     "(line %d char %ld)", lineno,
				     (long)(s - line));
				rc = -1;
				goto out;
			} else if (*s == '"' && !got_equals) {
				crm_err
				    ("Invalid config file format: unexpected quotes "
				     "(line %d char %ld)", lineno,
				     (long)(s - line));
				rc = -1;
				goto out;
			} else if (*s == '"' && !in_quotes) {
				in_quotes = 1;
				if (val) {
					val++;
					got_quotes = 1;
				}
			} else if (*s == '"' && in_quotes) {
				in_quotes = 0;
				*s = '\0';
			}

			s++;
		}

		if (!got_equals) {
			crm_err
			    ("Invalid config file format: missing '=' (lineno %d)",
			     lineno);
			rc = -1;
			goto out;
		}

		if (in_quotes) {
			crm_err
			    ("Invalid config file format: unterminated quotes (lineno %d)",
			     lineno);
			rc = -1;
			goto out;
		}

		if (!got_quotes)
			*s = '\0';

		if (strlen(key) > BOOTH_NAME_LEN
		    || strlen(val) > BOOTH_NAME_LEN) {
			crm_err("key/value too long");
			rc = -1;
			goto out;
		}

		if (!strcmp(key, "site")) {
			site_info_t *site = calloc(1, sizeof(site_info_t));
			memset(site, 0, sizeof(site_info_t));

			strcpy(site->addr, val);
			site->family = AF_INET;
			crm_trace("Site address[%s].", site->addr);
			if (search_self_node_ip(site) == 1) {
				crm_trace("Site[%s] is local site.",
					  site->addr);
				site->local = TRUE;
			}

			sites = g_list_append(sites, site);
		}

		if (!strcmp(key, "ticket")) {
			char *ticket_name = calloc(1, BOOTH_NAME_LEN);
			memset(ticket_name, 0, BOOTH_NAME_LEN);
			expiry = index(val, ';');
			weight = rindex(val, ';');

			if (!expiry) {
				crm_trace("Not expire");
				strcpy(ticket_name, val);
			} else if (expiry && expiry == weight) {
				crm_trace("Expire only");
				*expiry++ = '\0';

				while (*expiry == ' ')
					expiry++;

				strcpy(ticket_name, val);
			} else {
				crm_trace("Expire and weight");
				*expiry++ = '\0';
				*weight++ = '\0';

				while (*expiry == ' ')
					expiry++;

				while (*weight == ' ')
					weight++;

				strcpy(ticket_name, val);
			}

			crm_info("Registered booth managed ticket[%s].",
				 ticket_name);
			g_hash_table_insert(booth_tickets, ticket_name,
					    ticket_name);
		}

		if (!strcmp(key, "exclude_ticket")) {
			exclude_ticket_info_t *exclude_ticket = calloc(1,
								       sizeof
								       (exclude_ticket_info_t));
			char *ticket_name = NULL;

			ticket_name = index(val, ';');

			if (ticket_name == NULL) {
				crm_err("exclude ticket format error. "
					"there is no ';'");
				rc = -1;
				goto out;
			}

			*ticket_name++ = '\0';

			exclude_ticket->site = strdup(val);
			exclude_ticket->ticket = strdup(ticket_name);

			exclude_tickets =
			    g_list_append(exclude_tickets, exclude_ticket);
		}
	}

out:
	fclose_rc = fclose(fp);

	if (fclose_rc != 0) {
		crm_perror(LOG_ERR, "fclose() call failed");
		rc = -1;
	}

	return rc;
}

gboolean
validate_crm_message(xmlNode *msg, const char *sys, const char *uuid,
		     const char *msg_type)
{
	const char *type = NULL;
	const char *crm_msg_reference = NULL;

	if (msg == NULL) {
		return FALSE;
	}

	type = crm_element_value(msg, F_CRM_MSG_TYPE);
	crm_msg_reference = crm_element_value(msg, XML_ATTR_REFERENCE);

	if (type == NULL) {
		crm_info("No message type defined.");
		return FALSE;

	} else if (msg_type != NULL && strcasecmp(msg_type, type) != 0) {
		crm_info("Expecting a (%s) message but received a (%s).",
			 msg_type, type);
		return FALSE;
	}

	if (crm_msg_reference == NULL) {
		crm_info("No message crm_msg_reference defined.");
		return FALSE;
	}

	return TRUE;
}

int
crmd_ipc_msg_callback(const char *buffer, ssize_t length, gpointer user_data)
{
	xmlNode *msg = string2xml(buffer);
	xmlNode *data = NULL;
	const char *dc = NULL;
	const char *state = NULL;
	const char *result = NULL;

	g_source_remove(crmd_message_timer_id);
	crmd_message_timer_id = -1;

	if (msg == NULL) {
		crm_info("XML in IPC message was not valid... " "discarding.");
	} else
	    if (validate_crm_message
		(msg, crm_system_name, booth_resource_monitord_uuid,
		 XML_ATTR_RESPONSE) == FALSE) {
		crm_trace("Message was not a CRM response. Discarding.");

	} else {
		result = crm_element_value(msg, XML_ATTR_RESULT);

		if (result == NULL || strcasecmp(result, "ok") == 0) {
			result = "pass";

		} else {
			result = "fail";
		}

		dc = crm_element_value(msg, F_CRM_HOST_FROM);
		data = get_message_xml(msg, F_CRM_DATA);
		state = crm_element_value(data, "crmd_state");

		crm_trace("Cluster status of %s@%s: %s (%s).",
			  crm_element_value(data, XML_PING_ATTR_SYSFROM), dc,
			  state, crm_element_value(data, XML_PING_ATTR_STATUS));

		if (safe_str_eq(state, "S_IDLE")) {
			/* Since the state is S_IDLE, the resource for surveillance is checked */
			crm_info
			    ("Cluster status is %s: resource monitoring start.",
			     state);
			start_resource_monitor();
			do_crmd_query = FALSE;
		} else {
			/* When a state is except S_IDLE, a state is checked again */
			crm_trace("State of the DC is not S_IDLE.");
			crmd_message_timer_id = g_timeout_add(1 * 1000,
							      do_dc_health_start,
							      NULL);
		}
	}

	free_xml(msg);
	msg = NULL;

	return 0;
}

void crmd_ipc_connection_destroy(gpointer user_data)
{
	crm_err("Connection to CRMd was terminated");

	if (mainloop) {
		g_main_quit(mainloop);
	} else {
		crm_exit(1);
	}
}

struct ipc_client_callbacks crm_callbacks = {
	.dispatch = crmd_ipc_msg_callback,
	.destroy = crmd_ipc_connection_destroy
};

int crmd_connect(void)
{
	xmlNode *xml = NULL;
	mainloop_io_t *src = NULL;
	int attempts = 0;

	booth_resource_monitord_uuid = calloc(1, 11);

	if (booth_resource_monitord_uuid == NULL) {
		crm_err("Failed to allocate memory.");
		return -1;
	}

	snprintf(booth_resource_monitord_uuid, 10, "%d", getpid());
	booth_resource_monitord_uuid[10] = '\0';
	crm_trace("uuid[%s]", booth_resource_monitord_uuid);

	while (src == NULL && attempts++ < max_failures) {
		crm_trace("Connecting to CRMd. attempt %d", attempts);
		src = mainloop_add_ipc_client(CRM_SYSTEM_CRMD,
					      G_PRIORITY_DEFAULT, 0, NULL,
					      &crm_callbacks);

		if (src == NULL) {
			crm_trace("Waiting signing on to the CRMd service.");
			sleep(1);
		}
	}

	crmd_channel = mainloop_get_ipc_client(src);

	if (crmd_channel == NULL) {
		crm_err("Failed in a connection trial with CRMd.");
		return -1;
	}

	xml =
	    create_hello_message(booth_resource_monitord_uuid, crm_system_name,
				 "0", "1");
	crm_ipc_send(crmd_channel, xml, 0, 0, NULL);
	free_xml(xml);

	crm_debug("Signing on to the CRMd service.");

	return 0;
}

int main(int argc, char **argv)
{
	int rc;
	int argerr = 0;
	int flag;
	gboolean daemonize = FALSE;

#ifdef HAVE_GETOPT_H
	int option_index = 0;
	static struct option long_options[] = {
		/* Top-level Options */
		{"verbose", 0, 0, 'V'},
		{"help", 0, 0, 'h'},
		{"pid-file", 1, 0, 'p'},
		{"booth-config", 1, 0, 'b'},
		{"daemonize", 0, 0, 'D'},
		{0, 0, 0, 0}
	};
#endif
	signal(SIGTERM, shutdown_called);
	signal(SIGINT, shutdown_called);
	signal(SIGPIPE, SIG_IGN);

	booth_config_file = strdup(BOOTH_CONFIG_FILE);
	pid_file = strdup(PID_FILE);

	crm_log_init(basename(argv[0]), LOG_INFO, TRUE, FALSE, argc, argv, FALSE);

	while (1) {
#ifdef HAVE_GETOPT_H
		flag = getopt_long(argc, argv, OPTARGS,
				   long_options, &option_index);
#else
		flag = getopt(argc, argv, OPTARGS);
#endif
		if (flag == -1)
			break;

		switch (flag) {
		case 'V':
			crm_bump_log_level(argc, argv);
			break;
		case 'p':
			free(pid_file);
			pid_file = strdup(optarg);
			break;
		case 'b':
			free(booth_config_file);
			booth_config_file = strdup(optarg);
			break;
		case 'D':
			daemonize = TRUE;
			break;
		case 'h':
			usage(crm_system_name, EX_USAGE);
			break;
		default:
			++argerr;
			break;
		}
	}

	if (optind < argc) {
		printf("non-option ARGV-elements: ");

		while (optind < argc) {
			crm_err("%s ", argv[optind]);
			printf("%s ", argv[optind]);
			optind++;
		}

		printf("\n");
		argerr++;
	}

	if (argerr > 0) {
		printf("Options exist that can not be processed.\n");
		usage(crm_system_name, EX_USAGE);
	}

	crm_make_daemon(crm_system_name, daemonize, pid_file);

	crm_info("Initializing %s.", crm_system_name);

	crm_trace("connect to CRMd.");
	rc = crmd_connect();

	if (rc == 0) {
		crm_info("Succeeded to connect CRMd.");
	} else {
		crm_err("Failed to connect CRMd.");
		clean_up(1);
	}

	crm_trace("connect to CIB.");
	rc = cib_connect();

	if (rc == pcmk_ok) {
		crm_info("Succeeded to connect CIB.");
	} else {
		crm_err("Failed to connect CIB.");
		clean_up(1);
	}

	rc = read_booth_config();

	if (rc != 0) {
		crm_err("Failed to reading of %s.", booth_config_file);
		clean_up(1);
	}

	create_information();
	start_resource_monitor();

	crm_info("Starting %s.", crm_system_name);

	mainloop = g_main_new(FALSE);
	mainloop_add_signal(SIGTERM, shutdown_called);
	mainloop_add_signal(SIGINT, shutdown_called);
	mainloop_add_signal(SIGHUP, print_info_summary);
	g_main_run(mainloop);

	crm_info("Exiting %s.", crm_system_name);

	clean_up(EX_OK);

	return 0;
}
