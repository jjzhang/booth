/* -------------------------------------------------------------------------
 * booth_resource_monitord --- The monitoring of the resources which depended on the ticket.
 *   This program watches the resource that depended on the ticket.
 *   When abnormality occurs in a resource, move a ticket to other sites using booth.
 *
 * Copyright (c) 2012 NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 * Copyright (c) 2014 Philipp Marek <philipp.marek@linbit.com>
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

#define IPADDR_LEN		(sizeof(struct in6_addr))
#define NETLINK_BUFSIZE		16384

#define BOOTH_NAME_LEN		63
#define COMMAND_MAX		256

#define OPTARGS			"p:b:DVh"
#define PID_FILE		"/tmp/booth_resource_monitord.pid"
#define BOOTH_CONFIG_FILE	"/etc/booth/booth.conf"

#define F_CIB_UPDATE		"cib_update"
#define F_CIB_RC		"cib_rc"
#define F_CIB_OPERATION		"cib_op"
#define F_CIB_UPDATE_RESULT	"cib_update_result"

typedef struct site_info_s {
	gboolean local;
	unsigned short family;
	char addr[IPADDR_LEN];
	int weight;
} site_info_t;

typedef struct ticket_info_s {
	char *name;
	gboolean granted;
	gboolean standby;
	gboolean monitored;
	gboolean failover;
	gboolean need_delete;
	int expected_count;
	GList *resources;
} ticket_info_t;

typedef struct exclude_ticket_info_s {
	char *site;
	char *ticket;
} exclude_ticket_info_t;

typedef struct resource_info_s {
	char *id;
	enum rsc_role_e target_role;
	enum pe_obj_types variant;
	int clone_max;
	int clone_node_max;
	int master_max;
	int master_node_max;
} resource_info_t;

gboolean get_target_role(resource_t * rsc, enum rsc_role_e *role);
void crm_make_daemon(const char *name, gboolean daemonize, const char *pidfile);
void clean_up(int rc);
void free_ticket(gpointer data);
void shutdown_called(int nsig);
void print_ticket_summary(gpointer key, gpointer value, gpointer user_data);
void unpack_cluster_status(pe_working_set_t * data_set);
resource_t *find_resource_from_list(const char *search_rsc_id, GListPtr list);
void print_info_summary(int nsig);
int grant_ticket(ticket_info_t * ticket);
int revoke_ticket(ticket_info_t * ticket);
void update_tickets_info(gpointer key, gpointer value, gpointer user_data);
void failover_ticket(gpointer key, gpointer value, gpointer user_data);
int check_ticket_condition(ticket_info_t * manage_ticket);
int check_resource_role(resource_t * cluster_resource,
			resource_info_t * manage_resource);
void check_ticket_failover_need(gpointer key, gpointer value,
				gpointer user_data);
void start_resource_monitor(void);
gboolean docHasTag(xmlNode * root, const char *tag);
int search_xml_children(GListPtr * children, xmlNode * root, const char *tag,
			const char *field, const char *value,
			gboolean search_matches);
void register_monitor_resource(ticket_info_t * ticket, resource_t * resource,
			       enum rsc_role_e target_role);
void register_monitor_resource_children(ticket_info_t * ticket, GListPtr list,
					enum rsc_role_e target_role);
void create_ticket_info(xmlNode * rsc_ticket, gboolean update,
			pe_working_set_t * data_set);
ticket_info_t *copy_ticket_info(ticket_info_t * copy_ticket);
int compare_resource(GListPtr rsc_list, resource_info_t * rsc);
int compare_ticket_info(ticket_info_t * tmp_ticket,
			ticket_info_t * register_ticket);
void register_tickets(gpointer key, gpointer value, gpointer user_data);
void delete_unnecessary_ticket(gpointer key, gpointer value,
			       gpointer user_data);
void create_information(void);
int do_dc_health(void);
gboolean do_dc_health_start(gpointer data);
void cib_diff_notify(const char *event, xmlNode * msg);
void usage(const char *cmd, int exit_status);
void cib_connection_destroy(gpointer user_data);
int cib_connect(void);
void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);
int search_self_node_ip(site_info_t * site);
int read_booth_config(void);
gboolean validate_crm_message(xmlNode * msg, const char *sys, const char *uuid,
			      const char *msg_type);
int crmd_ipc_msg_callback(const char *buffer, ssize_t length,
			  gpointer user_data);
void crmd_ipc_connection_destroy(gpointer user_data);
int crmd_connect(void);


#ifdef HAVE_LOG_CIB_DIFF
/* OK */
#else
#ifdef HAVE_XML_LOG_PATCHSET
/* See https://github.com/ClusterLabs/pacemaker, commit
 * 6953aa52e00c4ddf481254a828f6d7c7826a23b9 */
	static inline void
log_cib_diff(int log_level, xmlNode * diff, const char *function)
{
	xml_log_patchset(log_level, function, diff);
}
#else
#error "Neither log_cib_diff() nor xml_log_patchset() available."
#endif
#endif
