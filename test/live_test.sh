#!/bin/sh
#
# see README-testing for more information
# do some basic booth operation tests for the given config
#

PROG=`basename $0`
usage() {
	cat<<EOF
usage:

	[NETEM_ENV=<envfun>[:<val>]] $PROG <booth.conf> [<test> ...]

EOF
	if [ $1 -eq 0 ]; then
		list_all
		examples
	fi
	exit
}

list_all() {
	echo "Tests:"
	grep "^test_.*{$" $0 | sed 's/test_//;s/(.*//;s/^/	/'
	echo
	echo "Netem functions:"
	grep "^NETEM_ENV_.*{$" $0 | sed 's/NETEM_ENV_//;s/(.*//;s/^/	/'
}
examples() {
	cat<<EOF

Examples:

	$0 booth.conf
	$0 booth-5node.conf grant revoke
	NETEM_ENV=net_delay:150 $0 mybooth.conf

EOF
}

[ $# -eq 0 ] && usage 0

cnf=$1
run_cnf="/etc/booth/booth.conf"

shift 1
ERR_SETUP_FAILED=52
logf=test_booth.log
SSH_OPTS="-o StrictHostKeyChecking=no"
iprules=/usr/share/booth/tests/test/booth_path
: ${HA_LOGFACILITY:="syslog"}

get_site() {
	local n=$1
	echo $sites | awk '{print $'$n'}'
}

logmsg() {
	if [ "$WE_SERVER" -o "$_JUST_NETEM" ]; then
		logger -t "BOOTHTEST" -p $HA_LOGFACILITY.info -- $@
	else
		ssh $SSH_OPTS `get_site 1` logger -t "BOOTHTEST" -p $HA_LOGFACILITY.info -- $@
	fi
}

ext_prog_log() {
	local cmd="$@"
	echo "run: $cmd" | logmsg
	$cmd
}
get_stat_fld() {
	local fld=$1
	sed "s/.* $fld=//;s/ .*//;s/'//g"
}

# tc netem, simulate packet loss, wan, etc
netem_delay() {
	ext_prog_log tc qdisc add dev $1 root netem delay $2ms $(($2/10))ms
}
netem_loss() {
	ext_prog_log tc qdisc add dev $1 root netem loss $2%
}
netem_reset() {
	ext_prog_log tc qdisc del dev $1 root netem
}
local_netem_env() {
	local fun=$1 arg=$2
	local t netif=""
	local my_addr
	my_addr=`booth status | get_stat_fld booth_addr_string`
	if [ -z "$my_addr" ]; then
		logmsg "cannot find my address, booth running?"
		return 1
	fi
	for t in `ip link | grep '^[1-9]:' | sed 's/.: //;s/: .*//'`
	do
		if ip a l $t | fgrep -wq $my_addr; then
			netif=$t
			break
		fi
	done
	if [ -n "$netif" ]; then
		$fun $netif $arg
	else
		logmsg "cannot find netif for $my_addr, netem not set"
	fi
}

is_function() {
    test z"`command -v $1`" = z"$1"
}
runcmd() {
	local h=$1 rc
	shift 1
	echo "$h: running '$@'" | logmsg
	if ip a l | fgrep -wq $h; then
		$@
	else
		ssh $SSH_OPTS $h $@
	fi
	rc=$?
	if [ $rc -ne 0 ]; then
		echo "$h: '$@' failed (exit code $rc)" | logmsg
	fi
	return $rc
}
manage_site() {
	runcmd $1 crm resource $2 booth
}
manage_arbitrator() {
	runcmd $1 systemctl $2 booth@booth.service
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
	runcmd $1 crm --force site ticket revoke $tkt
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
booth_status() {
	test "`runcmd $1 booth status | get_stat_fld booth_state`" = "started"
}
stop_booth() {
	local h rc
	for h in $sites; do
		stop_site $h
		rc=$((rc|$?))
	done >/dev/null 2>&1
	for h in $arbitrators; do
		stop_arbitrator $h
		rc=$((rc|$?))
	done >/dev/null 2>&1
	wait_timeout
	return $rc
}
start_booth() {
	local h rc
	for h in $sites; do
		start_site $h
		rc=$((rc|$?))
	done >/dev/null 2>&1
	for h in $arbitrators; do
		start_arbitrator $h
		rc=$((rc|$?))
	done >/dev/null 2>&1
	wait_timeout
	return $rc
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
is_we_server() {
	local h
	for h in $sites $arbitrators; do
		ip a l | fgrep -wq $h && return
	done
	return 1
}
sync_conf() {
	local h rc=0
	for h in $sites $arbitrators; do
		rsync -q $cnf $h:$run_cnf
		rc=$((rc|$?))
	done
	return $rc
}
dump_conf() {
	echo "test configuration file $cnf:"
	grep -v '^#' $cnf | grep -v '^[[:space:]]*$' | sed "s/^/$cnf: /"
}
forall() {
	local h rc=0
	for h in $sites $arbitrators; do
		runcmd $h $@
		rc=$((rc|$?))
	done
	return $rc
}
forall_sites() {
	local h rc=0
	for h in $sites; do
		runcmd $h $@
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
# run on all hosts whatever function produced on stdout
forall_fun2() {
	local h rc=0 f
	f=$1
	shift 1
	for h in $sites $arbitrators; do
		$f $@ | ssh $SSH_OPTS $h
		rc=$((rc|$?))
		[ $rc -ne 0 ] && break
	done
	return $rc
}
run_site() {
	local n=$1 h
	shift 1
	h=`echo $sites | awk '{print $'$n'}'`
	runcmd $h $@
}
run_arbitrator() {
	local n=$1 h
	shift 1
	h=`echo $arbitrators | awk '{print $'$n'}'`
	runcmd $h $@
}

get_port() {
	grep "^port" | 
		sed -n 's/.*="//;s/"//p'
}
get_servers() {
	grep "^$1" | 
		sed -n 's/.*="//;s/"//p'
}
get_rsc() {
	awk '/before-acquire-handler/{print $NF}' $cnf
}

break_external_prog() {
	run_site $1 crm configure "location $PREFNAME `get_rsc` rule -inf: defined \#uname"
}
show_pref() {
	run_site $1 crm configure show $PREFNAME > /dev/null
}
repair_external_prog() {
	run_site $1 crm configure delete __pref_booth_live_test
}
get_tkt() {
	grep "^ticket=" | head -1 | sed 's/ticket=//;s/"//g'
}
get_tkt_settings() {
awk '
n && /^	/ && /expire|timeout|renewal-freq/ {
	sub(" = ", "=", $0);
	gsub("-", "_", $0);
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
wait_renewal() {
	sleep $T_renewal_freq
}
wait_timeout() {
	local t=2
	[ "$T_timeout" -gt $t ] && t=$T_timeout
	[ "$PKT_LOSS" ] && t=$((t + 2*T_timeout + PKT_LOSS/6))
	sleep $t
}

set_netem_env() {
	local modfun args
	modfun=`echo $1 | sed 's/:.*//'`
	args=`echo $1 | sed 's/[^:]*//;s/:/ /g'`
	if ! is_function NETEM_ENV_$modfun; then
		echo "NETEM_ENV_$modfun: doesn't exist"
		exit 1
	fi
	NETEM_ENV_$modfun $args
}
reset_netem_env() {
	[ -z "$NETEM_ENV" ] && return
	[ -n "$__NETEM_RESET" ] && return
	__NETEM_RESET=1
	forall $0 $run_cnf __netem__ netem_reset
}
setup_netem() {
	[ -z "$NETEM_ENV" ] && return
	__NETEM_RESET=
	for env in $NETEM_ENV; do
		set_netem_env $env
	done
	trap "reset_netem_env" EXIT
}

cib_status() {
	local h=$1 stat
	stat=`runcmd $h crm_ticket -L |
		grep "^$tkt" | awk '{print $2}'`
	test "$stat" != "-1"
}
is_cib_granted() {
	local stat h=$1
	stat=`runcmd $h crm_ticket -L |
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
	cat<<EOF | logmsg
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
		cat<<EOF | logmsg
CIB check failed
CIB grantee: $cib_grantee
booth grantee: $booth_grantee
expected grantee: $exp_grantee
EOF
	fi
	return $rc
}

booth_where_granted() {
	local grantee ticket_line
	# we don't know which sites could be stopped, so run booth
	# list on all of them (at least one should have booth
	# running)
	ticket_line=`forall_sites booth list | grep $tkt | sort -u | head -1`
	grantee=`echo "$ticket_line" | sed 's/.*leader: //;s/,.*//'`
	echo $grantee
	[ "$grantee" = "none" ] && return
	! runcmd $grantee booth list | grep -q "$tkt.*pending"
}
booth_list_fld() {
	cut -d, -f $1 | sed 's/[^:]*://'
}
max_booth_time_diff() {
	local l
	booth_list_fld 3 |
	while read l; do
		date -d "$l" "+%s"
	done |
	awk '
	{t[n++]=$0}
	END{
		for (i=0; i<n; i++)
			for (j=i+1; j<n; j++) {
				x=t[i]-t[j];
				print x >= 0 ? x : -x;
			}
	}
	' | sort -n | tail -1
}
booth_leader_consistency() {
	test `booth_list_fld 2 | sort -u | wc -l` -eq 1
}
check_booth_consistency() {
	local tlist rc maxdiff
	tlist=`forall booth list 2>/dev/null | grep $tkt |
		sed 's/commit:.*//;s/NONE/none/'`
	maxdiff=`echo "$tlist" | max_booth_time_diff`
	test "$maxdiff" -eq 0
	rc=$?
	echo "$tlist" | booth_leader_consistency
	rc=$(($rc | $?<<1))
	test $rc -eq 0 && return
	cat<<EOF | logmsg
`if [ $rc -gt 1 ]; then
	echo "booth list consistency failed (more than one leader!):"
else
	echo "booth list consistency failed (max valid time diff: $maxdiff):"
fi`
===========
"$tlist"
===========
EOF
	test $rc -le 1
}

check_consistency() {
	local exp_grantee=$1
	check_booth_consistency &&
	check_cib $exp_grantee
}

all_booth_status() {
	forall_fun booth_status
}

can_run_test() {
	if is_function applicable_$1; then
		if ! applicable_$1; then
			echo "(not applicable, skipping)"
			return 1
		fi
	fi
	if ! is_function test_$1 || ! is_function check_$1; then
		echo "(test missing)"
		return 1
	fi
}
revoke_ticket() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
}
run_report() {
	local start_ts=$1 end_ts=$2 name=$3
	local quick_opt=""
	logmsg "running hb_report"
	hb_report -Q 2>&1 | grep -sq "illegal.option" ||
		quick_opt="-Q"
	hb_report $hb_report_opts $quick_opt -f "`date -d @$((start_ts-5))`" \
		-t "`date -d @$((end_ts+60))`" \
		-n "$sites $arbitrators" $name 2>&1 | logmsg
}
runtest() {
	local start_ts end_ts rc booth_status
	local start_time end_time
	local usrmsg
	TEST=$1
	start_time=`date`
	start_ts=`date +%s`
	echo -n "Testing: $1... "
	can_run_test $1 || return 0
	echo "starting booth test $1 ..." | logmsg
	setup_netem
	test_$1
	rc=$?
	case $rc in
	0)
		check_$1
		rc=$?
		if [ $rc -eq 0 ]; then
			usrmsg="SUCCESS"
		else
			usrmsg="check FAIL: $rc"
		fi
		;;
	$ERR_SETUP_FAILED)
		usrmsg="setup FAIL"
		;;
	*)
		usrmsg="test FAIL: $rc"
		;;
	esac
	end_time=`date`
	end_ts=`date +%s`
	reset_netem_env
	echo "finished booth test $1 ($usrmsg)" | logmsg
	is_function recover_$1 && recover_$1
	sleep 3
	all_booth_status
	booth_status=$?
	if [ $rc -eq 0 -a $booth_status -eq 0 ]; then
		echo OK
		[ "$GET_REPORT" ] && run_report $start_ts $end_ts $TEST
	else
		echo "$usrmsg (running hb_report ... $1.tar.bz2; see also $logf)"
		[ $booth_status -ne 0 ] &&
			echo "unexpected: some booth daemons not running"
		run_report $start_ts $end_ts $TEST
	fi
	revoke_ticket
}

#
# the tests
#

# most tests start by granting ticket
grant_ticket() {
	run_site $1 booth grant $tkt >/dev/null
}

## TEST: grant ##

# just a grant
test_grant() {
	grant_ticket 1
}
check_grant() {
	check_consistency `get_site 1`
}

## TEST: longgrant ##

# just a grant followed by three expire times
test_longgrant() {
	grant_ticket 1 || return $ERR_SETUP_FAILED
	wait_exp
	wait_exp
	wait_exp
}
check_longgrant() {
	check_consistency `get_site 1`
}

## TEST: grant_noarb ##

# just a grant with no arbitrators
test_grant_noarb() {
	local h
	for h in $arbitrators; do
		stop_arbitrator $h || return $ERR_SETUP_FAILED
	done >/dev/null 2>&1
	sleep 1
	grant_ticket 1 || return $ERR_SETUP_FAILED
}
check_grant_noarb() {
	check_consistency `get_site 1`
}
recover_grant_noarb() {
	local h
	for h in $arbitrators; do
		start_arbitrator $h
	done >/dev/null 2>&1
}
applicable_grant_noarb() {
	[ -n "$arbitrators" ]
}

## TEST: revoke ##

# just a revoke
test_revoke() {
	grant_ticket 1 || return $ERR_SETUP_FAILED
	revoke_ticket
}
check_revoke() {
	check_consistency
}

## TEST: grant_elsewhere ##

# just a grant to another site
test_grant_elsewhere() {
	run_site 1 booth grant -s `get_site 2` $tkt >/dev/null
}
check_grant_elsewhere() {
	check_consistency `get_site 2`
}

## TEST: grant_site_lost ##

# grant with one site lost
test_grant_site_lost() {
	stop_site `get_site 2` || return $ERR_SETUP_FAILED
	wait_timeout
	grant_ticket 1 || return $ERR_SETUP_FAILED
	check_cib `get_site 1` || return 1
	wait_exp
}
check_grant_site_lost() {
	check_consistency `get_site 1`
}
recover_grant_site_lost() {
	start_site `get_site 2`
}

## TEST: grant_site_reappear ##

# grant with one site lost then reappearing
test_grant_site_reappear() {
	stop_site `get_site 2` || return $ERR_SETUP_FAILED
	sleep 1
	grant_ticket 1 || return $ERR_SETUP_FAILED
	check_cib `get_site 1` || return 1
	wait_timeout
	start_site `get_site 2` || return $ERR_SETUP_FAILED
	wait_timeout
	wait_timeout
}
check_grant_site_reappear() {
	check_consistency `get_site 1` &&
	is_cib_granted `get_site 1`
}
recover_grant_site_reappear() {
	start_site `get_site 2`
}

## TEST: simultaneous_start_even ##

# simultaneous start of even number of members
test_simultaneous_start_even() {
	local serv
	grant_ticket 2 || return $ERR_SETUP_FAILED
	stop_booth || return $ERR_SETUP_FAILED
	wait_timeout
	for serv in $(echo $sites | sed "s/`get_site 1` //"); do
		start_site $serv &
	done
	for serv in $arbitrators; do
		start_arbitrator $serv &
	done
	wait_renewal
	start_site `get_site 1`
	wait_timeout
	wait_timeout
}
check_simultaneous_start_even() {
	check_consistency `get_site 2`
}

## TEST: slow_start_granted ##

# slow start
test_slow_start_granted() {
	grant_ticket 1 || return $ERR_SETUP_FAILED
	stop_booth || return $ERR_SETUP_FAILED
	wait_timeout
	for serv in $sites; do
		start_site $serv
		wait_timeout
	done
	for serv in $arbitrators; do
		start_arbitrator $serv
		wait_timeout
	done
}
check_slow_start_granted() {
	check_consistency `get_site 1`
}

## TEST: restart_granted ##

# restart with ticket granted
test_restart_granted() {
	grant_ticket 1 || return $ERR_SETUP_FAILED
	restart_site `get_site 1` || return $ERR_SETUP_FAILED
	wait_timeout
}
check_restart_granted() {
	check_consistency `get_site 1`
}

## TEST: restart_granted_nocib ##

# restart with ticket granted (but cib empty)
test_restart_granted_nocib() {
	grant_ticket 1 || return $ERR_SETUP_FAILED
	stop_site_clean `get_site 1` || return $ERR_SETUP_FAILED
	wait_timeout
	start_site `get_site 1` || return $ERR_SETUP_FAILED
	wait_timeout
	wait_timeout
	wait_timeout
}
check_restart_granted_nocib() {
	check_consistency `get_site 1`
}

## TEST: notgranted ##

# restart with ticket not granted
test_restart_notgranted() {
	grant_ticket 1 || return $ERR_SETUP_FAILED
	stop_site `get_site 2` || return $ERR_SETUP_FAILED
	sleep 1
	start_site `get_site 2` || return $ERR_SETUP_FAILED
	wait_timeout
}
check_restart_notgranted() {
	check_consistency `get_site 1`
}

## TEST: failover ##

# ticket failover
test_failover() {
	grant_ticket 1 || return $ERR_SETUP_FAILED
	stop_site_clean `get_site 1` || return $ERR_SETUP_FAILED
	booth_status `get_site 1` && return $ERR_SETUP_FAILED
	wait_exp
	wait_timeout
	wait_timeout
	wait_timeout
}
check_failover() {
	check_consistency any
}
recover_failover() {
	start_site `get_site 1`
}

## TEST: split_leader ##

# split brain (leader alone)
test_split_leader() {
	grant_ticket 1 || return $ERR_SETUP_FAILED
	run_site 1 $iprules stop $port   >/dev/null
	wait_exp
	wait_timeout
	wait_timeout
	check_cib any || return 1
	run_site 1 $iprules start $port  >/dev/null
	wait_timeout
	wait_timeout
	wait_timeout
}
check_split_leader() {
	check_consistency any
}
recover_split_leader() {
	run_site 1 $iprules start $port  >/dev/null
}

## TEST: split_follower ##

# split brain (follower alone)
test_split_follower() {
	grant_ticket 1 || return $ERR_SETUP_FAILED
	run_site 2 $iprules stop $port  >/dev/null
	wait_exp
	wait_timeout
	run_site 2 $iprules start $port  >/dev/null
	wait_timeout
}
check_split_follower() {
	check_consistency `get_site 1`
}

## TEST: split_edge ##

# split brain (leader alone)
test_split_edge() {
	grant_ticket 1 || return $ERR_SETUP_FAILED
	run_site 1 $iprules stop $port  >/dev/null
	wait_exp
	run_site 1 $iprules start $port  >/dev/null
	wait_timeout
	wait_timeout
}
check_split_edge() {
	check_consistency any
}

## TEST: external_prog_failed ##

# external test prog failed
test_external_prog_failed() {
	grant_ticket 1 || return $ERR_SETUP_FAILED
	break_external_prog 1
	show_pref 1 || return $ERR_SETUP_FAILED
	wait_renewal
	wait_timeout
}
check_external_prog_failed() {
	check_consistency any &&
	[ `booth_where_granted` != `get_site 1` ]
}
recover_external_prog_failed() {
	repair_external_prog 1
}
applicable_external_prog_failed() {
	[ -n `get_rsc` ]
}

#
# environment modifications
#

# packet loss at one site 30%
NETEM_ENV_single_loss() {
	run_site 1 $0 $run_cnf __netem__ netem_loss ${1:-30}
	PKT_LOSS=${1:-30}
}

# packet loss everywhere 30%
NETEM_ENV_loss() {
	forall $0 $run_cnf __netem__ netem_loss ${1:-30}
	PKT_LOSS=${1:-30}
}

# network delay 100ms
NETEM_ENV_net_delay() {
	forall $0 $run_cnf __netem__ netem_delay ${1:-100}
}

[ -f "$cnf" ] || {
	ls $cnf
	usage 1
}

sites=`get_servers site < $cnf`
arbitrators=`get_servers arbitrator < $cnf`
port=`get_port < $cnf`
: ${port:=9929}
site_cnt=`echo $sites | wc -w`
arbitrator_cnt=`echo $arbitrators | wc -w`
tkt=`get_tkt < $cnf`
eval `get_tkt_settings`

if [ "$1" = "__netem__" ]; then
	shift 1
	_JUST_NETEM=1
	local_netem_env $@
	exit
fi

[ -z "$sites" ] && {
	echo no sites in $cnf
	usage 1
}

[ -z "$T_expire" ] && {
	echo set $tkt expire time in $cnf
	usage 1
}

if [ -z "$T_renewal_freq" ]; then
	T_renewal_freq=$((T_expire/2))
fi

exec 2>$logf
BASH_XTRACEFD=2
PS4='+ `date +"%T"`: '
set -x

WE_SERVER=""
is_we_server && WE_SERVER=1

PREFNAME=__pref_booth_live_test

sync_conf || exit
restart_booth
all_booth_status || {
	start_booth
	all_booth_status || {
		echo "some booth servers couldn't be started"
		exit 1
	}
}
revoke_ticket

dump_conf | logmsg

TESTS="$@"

: ${TESTS:="grant longgrant grant_noarb grant_elsewhere
grant_site_lost grant_site_reappear revoke
simultaneous_start_even slow_start_granted
restart_granted restart_granted_nocib restart_notgranted
failover split_leader split_follower split_edge
external_prog_failed"}

for t in $TESTS; do
	runtest $t
done
