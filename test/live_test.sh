#!/bin/sh
#
# see README-testing for more information
# do some basic booth operation tests for the given config
#

usage() {
	echo "$0: {booth.conf}"
	exit
}

[ $# -eq 0 ] && usage

tkt=ticket-A
cnf=$1
shift 1
logf=test_booth.log
iprules=/usr/share/booth/tests/test/booth_path

is_function() {
    test z"`command -v $1`" = z"$1"
}
manage_site() {
	ssh $1 crm resource $2 booth
}
manage_arbitrator() {
	ssh $1 systemctl $2 booth@booth.service
}
start_site() {
	manage_site $1 start
}
start_arbitrator() {
	manage_arbitrator $1 start
}
stop_site_clean() {
	manage_site $1 stop &&
	sleep 1 &&
	ssh $1 crm --force site ticket revoke $tkt
}
stop_site() {
	manage_site $1 stop
}
stop_arbitrator() {
	manage_arbitrator $1 stop
}
restart_site() {
	manage_site $1 restart
}
restart_arbitrator() {
	manage_arbitrator $1 restart
}
get_stat_fld() {
	local h=$1 fld=$2
	ssh $h booth status | sed "s/.* $fld=//;s/ .*//;s/'//g"
}
booth_status() {
	test "`get_stat_fld $1 booth_state`" = "started"
}
start_booth() {
	local h
	for h in $sites; do
		start_site $h
	done >/dev/null 2>&1
	for h in $arbitrators; do
		start_arbitrator $h
	done >/dev/null 2>&1
	wait_timeout
}
restart_booth() {
	local h procs
	for h in $sites; do
		restart_site $h & procs="$! $procs"
	done >/dev/null 2>&1
	for h in $arbitrators; do
		restart_arbitrator $h
	done >/dev/null 2>&1
	wait $procs
	wait_timeout
}
sync_conf() {
	local h rc=0
	for h in $sites $arbitrators; do
		rsync -q $cnf $h:/etc/booth/booth.conf
		rc=$((rc|$?))
	done
	return $rc
}
forall() {
	local h rc=0
	for h in $sites $arbitrators; do
		ssh $h $@
		rc=$((rc|$?))
	done
	return $rc
}
forall_fun() {
	local h rc=0 f=$1
	for h in $sites $arbitrators; do
		$f $h
		rc=$((rc|$?))
		[ $rc -ne 0 ] && break
	done
	return $rc
}
run_site() {
	local n=$1 h
	shift 1
	h=`echo $sites | awk '{print $'$n'}'`
	ssh $h $@ || {
		echo "$h: '$@' failed (exit code $?)" >&2
	}
}
run_arbitrator() {
	local n=$1 h
	shift 1
	h=`echo $arbitrators | awk '{print $'$n'}'`
	ssh $h $@
}
get_site() {
	local n=$1 h
	shift 1
	echo $sites | awk '{print $'$n'}'
}

get_servers() {
	grep "^$1" | 
		sed -n 's/.*="//;s/"//p'
}

get_tkt_settings() {
awk '
n && /^	/ && /expire|timeout/ {
	sub(" = ", "=", $0);
	sub("^	", "T_", $0);
	print
	next
}
n && /^$/ {exit}
/^ticket.*'$tkt'/ {n=1}
' $cnf
}
wait_exp() {
	sleep $T_expire
}
wait_half_exp() {
	sleep $((T_expire/2))
}
wait_timeout() {
	sleep $T_timeout
}

cib_status() {
	local h=$1 stat
	stat=`ssh $h crm_ticket -L |
		grep "^$tkt" | awk '{print $2}'`
	test "$stat" != "-1"
}
is_cib_granted() {
	local stat h=$1
	stat=`ssh $h crm_ticket -L |
		grep "^$tkt" | awk '{print $2}'`
	[ "$stat" = "granted" ]
}
check_cib_consistency() {
	local h gh="" rc=0
	for h in $sites; do
		if is_cib_granted $h; then
			[ -n "$gh" ] && rc=1 # granted twice
			gh="$gh $h"
		fi
	done
	[ -z "$gh" ] && gh="none"
	if [ $rc -eq 0 ]; then
		echo $gh
		return $rc
	fi
	cat<<EOF >&2
CIB consistency test failed
ticket granted to $gh
EOF
	return $rc
}
check_cib() {
	local exp_grantee=$1 cib_grantee booth_grantee
	local rc=0 pending
	cib_grantee=`check_cib_consistency`
	booth_grantee=`booth_where_granted`
	pending=$?
	if [ $pending -eq 0 ]; then
		[ "$cib_grantee" = "$booth_grantee" ]
		rc=$?
	else
		# ticket is not committed to cib yet
		[ "$exp_grantee" = "$booth_grantee" ]
		rc=$?
		exp_grantee="" # cheat a bit
	fi
	case "$exp_grantee" in
	"any") [ "$cib_grantee" != "none" ] ;;
	"") [ "$cib_grantee" = "none" ] ;;
	*) [ "$cib_grantee" = "$exp_grantee" ] ;;
	esac
	rc=$((rc|$?))
	if [ $rc -ne 0 ]; then
		cat<<EOF >&2
CIB check failed
CIB grantee: $cib_grantee
booth grantee: $booth_grantee
expected grantee: $booth_grantee
EOF
	fi
	return $rc
}

booth_where_granted() {
	local grantee ticket_line
	ticket_line=`run_arbitrator 1 booth list | grep $tkt`
	grantee=`echo "$ticket_line" | sed 's/.*leader: //;s/,.*//'`
	echo $grantee
	[ "$grantee" = "none" ] && return
	! ssh $grantee booth list | grep -q "$tkt.*pending"
}
check_booth_consistency() {
	local cnt tlist
	tlist=`forall booth list 2>/dev/null | grep $tkt |
		sed 's/commit:.*//;s/NONE/none/'`
	cnt=`echo "$tlist" | sort -u | wc -l`
	test $cnt -eq 1 && return
	cat<<EOF >&2
booth list consistency test failed:
===========
"$tlist"
===========
EOF
	return 1
}

check_consistency() {
	local exp_grantee=$1
	check_booth_consistency &&
	check_cib $exp_grantee
}

reset_booth() {
	start_booth
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
}
test_booth_status() {
	forall_fun booth_status
}

runtest() {
	local start_ts end_ts rc booth_status
	local start_time end_time
	start_time=`date`
	start_ts=`date +%s`
	echo -n "Testing: $1... "
	test_$1 && check_$1
	rc=$?
	end_time=`date`
	end_ts=`date +%s`
	is_function recover_$1 && recover_$1
	test_booth_status
	booth_status=$?
	if [ $rc -eq 0 -a $booth_status -eq 0 ]; then
		echo OK
	else
		echo "FAIL (running hb_report ... $1.tar.bz2; see also $logf)"
		[ $booth_status -ne 0 ] &&
			echo "unexpected: some booth daemons not running"
		echo "running hb_report" >&2
		hb_report -f "`date -d @$((start_ts-5))`" \
			-t "`date -d @$((end_ts+60))`" \
			-n "$sites $arbitrators" $1 >&2
	fi
}

[ -f "$cnf" ] || {
	ls $cnf
	usage
}

sites=`get_servers site < $cnf`
arbitrators=`get_servers arbitrator < $cnf`
eval `get_tkt_settings`

[ -z "$sites" ] && {
	echo no sites in $cnf
	usage
}

[ -z "$T_expire" ] && {
	echo set $tkt expire time in $cnf
	usage
}

exec 2>$logf
BASH_XTRACEFD=2
PS4='+ `date +"%T"`: '
set -x

#
# the tests
#

# just a grant
test_grant() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
}
check_grant() {
	check_consistency `get_site 1`
}

# just a revoke
test_revoke() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
}
check_revoke() {
	check_consistency
}

# just a grant to another site
test_grant_elsewhere() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant -s `get_site 2` $tkt >/dev/null
	wait_timeout
}
check_grant_elsewhere() {
	check_consistency `get_site 2`
}

# grant with one site lost
test_grant_site_lost() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	stop_site `get_site 2`
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	check_cib `get_site 1` || return 1
	wait_exp
}
check_grant_site_lost() {
	check_consistency `get_site 1`
}
recover_grant_site_lost() {
	start_site `get_site 2`
}

# restart with ticket granted
test_restart_granted() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	restart_site `get_site 1`
	wait_timeout
}
check_restart_granted() {
	check_consistency `get_site 1`
}

# restart with ticket granted (but cib empty)
test_restart_granted_nocib() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	stop_site_clean `get_site 1` || return 1
	wait_timeout
	start_site `get_site 1`
	wait_timeout
}
check_restart_granted_nocib() {
	check_consistency `get_site 1`
}

# restart with ticket not granted
test_restart_notgranted() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	stop_site `get_site 2`
	sleep 1
	start_site `get_site 2`
	wait_timeout
}
check_restart_notgranted() {
	check_consistency `get_site 1`
}

# ticket failover
test_failover() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	stop_site_clean `get_site 1` || return 1
	booth_status `get_site 1` && return 1
	wait_exp
	wait_timeout
}
check_failover() {
	check_consistency any
}
recover_failover() {
	start_site `get_site 1`
}

# split brain (leader alone)
test_split_leader() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	run_site 1 $iprules stop  >/dev/null
	wait_exp
	wait_timeout
	check_cib any || return 1
	run_site 1 $iprules start  >/dev/null
	wait_timeout
}
check_split_leader() {
	check_consistency any
}
recover_split_leader() {
	run_site 1 $iprules start  >/dev/null
}

# split brain (follower alone)
test_split_follower() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	run_site 2 $iprules stop  >/dev/null
	wait_exp
	wait_timeout
	run_site 2 $iprules start  >/dev/null
	wait_timeout
}
check_split_follower() {
	check_consistency `get_site 1`
}

# split brain (leader alone)
test_split_edge() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	run_site 1 $iprules stop  >/dev/null
	wait_exp
	run_site 1 $iprules start  >/dev/null
	wait_timeout
}
check_split_edge() {
	check_consistency any
}

sync_conf || exit
restart_booth
test_booth_status || {
	reset_booth
	test_booth_status || exit
}

TESTS="$@"

: ${TESTS:="grant grant_elsewhere grant_site_lost revoke
restart_granted restart_granted_nocib restart_notgranted
failover split_leader split_follower split_edge"}

for t in $TESTS; do
	runtest $t
done
