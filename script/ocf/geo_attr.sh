#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it would be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# Further, this software is distributed without any warranty that it is
# free of the rightful claim of any third person regarding infringement
# or the like.  Any license provided herein, whether implied or
# otherwise, applies only to this software file.  Patent licenses, if
# any, provided herein do not apply to combinations of this program with
# other software, or any other product whatsoever.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write the Free Software Foundation,
# Inc., 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
#

# This file is part of the booth project and contains /bin/sh
# code to support GEO attributes

# USAGE
#
# To use this for updating GEO attributes just follow the
# instructions below.

# Source this file in your OCF RA script:
#
##	. ${OCF_ROOT}/lib/booth/geo_attr.sh

# 1) meta-data
#
# geo_attr_meta_data prints descriptions of three parameters.
# Best to invoke it just before printing "</parameters>". For
# instance:
#
##	    cat <<EOF
##	<?xml version="1.0"?>
##	...
##	<parameters>
##	...
##	`geo_attr_meta_data`
##	</parameters>
##	...
##	EOF

# 2) validation (validate-all)
#
# Invoke geo_attr_validate_all to test the environment:
#
##	 if ! geo_attr_validate_all; then
##	 	return $OCF_ERR_INSTALL
##	 fi

# 3) Attribute updating
#
# Put something like the following code after the RA updated the
# remote site state (e.g. data replication):
#
##	 if [ -n "$OCF_RESKEY_booth_ticket" ]; then
##	 	if geo_attr_geo_attr $outcome; then
##	 		# success!
##	 	else
##	 		# failed to set the attribute
##	 		# appropriate error was already logged
##	 		# normally, more cannot be done at this point
##	 		# because updating GEO attributes is
##	 		# essentially a best effort operation
##	 	fi
##	 fi
#
# The outcome variable is a boolean.
# It should reflect the outcome of the operation to update
# data at the site (set to "0" for failure, anything else for
# success).

# 4) Site name (optional)
#
# We use the special value 'other' to specify the site where the
# attribute is to be updated. That should cover the majority of
# GEO clusters. In case your setup has more than two sites, then
# provide a function named get_site_name which should print the
# appropriate site name (as specified in booth.conf too) to
# stdout.
#

DEFAULT_BOOTH_CONF="/etc/booth/booth.conf"
: ${OCF_RESKEY_booth_config:=$DEFAULT_BOOTH_CONF}

geo_attr_meta_data() {
	cat <<END

<parameter name="booth_ticket">
<longdesc lang="en">
Booth ticket. Need to define this to activate GEO attribute
updating. See also the booth_config and geo_attribute parameters.
</longdesc>
<shortdesc lang="en">Booth ticket</shortdesc>
<content type="string" default="" />
</parameter>

<parameter name="booth_config">
<longdesc lang="en">
Booth configuration name (or configuration filename) to use.
</longdesc>
<shortdesc lang="en">BOOTH configuration file</shortdesc>
<content type="string" default="$DEFAULT_BOOTH_CONF" />
</parameter>

<parameter name="geo_attribute">
<longdesc lang="en">
Attribute name. If not specified, we'll get the name from the
first "attr-prereq" definition for the given ticket. This
normally needs to be used only in case there are multiple
"attr-prereq" directives for the ticket.
</longdesc>
<shortdesc lang="en">GEO attribute</shortdesc>
<content type="string" default="" />
</parameter>

END
}

geo_attr_get_attr() {
	local tkt cnf attr
	tkt=$OCF_RESKEY_booth_ticket
	cnf=$OCF_RESKEY_booth_config
	attr=$OCF_RESKEY_geo_attribute

	awk -v attr="$attr" '
n && /^[[:space:]]*attr-prereq = auto .* eq / {
	if (attr == "" || attr == $4) {
		print $4,$6; exit
	}
}
n && (/^$/ || /^ticket.*/) {exit}
/^ticket.*'$tkt'/ {n=1}
' $cnf
}

# arguments:
# $1: 0 reset the attribute
#     != 0 set the attribute
#
geo_attr_geo_attr() {
	local val site

	val=$1
	set -- `geo_attr_get_attr`
	if test z"`command -v get_site_name`" = z"get_site_name"; then
		site=`get_site_name`
	else
		site="other"
	fi

	if [ "$val" = "0" ]; then
		geostore delete -s $site $1 >/dev/null 2>&1
	else
		geostore set -s $site $1 $2
	fi
}

geo_attr_read_attr() {
	local site

	set -- `geo_attr_get_attr`
	if test z"`command -v get_site_name`" = z"get_site_name"; then
		site=`get_site_name`
	else
		site="other"
	fi

	geostore get -s $site $1
}

# test the environment for geo_attr
#
geo_attr_validate_all() {
	if [ -z "$OCF_RESKEY_booth_ticket" ]; then
		return 0
	fi

	if ! test -f "$OCF_RESKEY_booth_config"; then
		ocf_log err "booth configuration $OCF_RESKEY_booth_config doesn't exist"
		return 1
	fi

	if ! grep -qs "^ticket[[:space:]]*=[[:space:]]*\"$OCF_RESKEY_booth_ticket\"" $OCF_RESKEY_booth_config; then
		ocf_log err "ticket $OCF_RESKEY_booth_ticket not found in $OCF_RESKEY_booth_config"
		return 1
	fi

	set -- `geo_attr_get_attr`
	if [ $# -eq 0 ]; then
		ocf_log err "no attr-prereq defined in $OCF_RESKEY_booth_ticket"
		return 1
	fi

	return 0
}
