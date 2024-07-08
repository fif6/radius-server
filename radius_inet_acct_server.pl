#!/usr/bin/perl -w

BEGIN {
	use FindBin;
	unshift(@INC, "${FindBin::RealBin}/modules"); # add custom Modules path at the first of position in @INC
};


use strict;
use warnings;
use POSIX qw(strftime setsid);
use Cwd qw(abs_path);
use Switch;
use Socket;
use IO::Socket::INET;
use Net::Radius::Packet;
use Net::Radius::Dictionary;
use DBI;
use DBD::mysql;
#use Data::Dumper; # print Dumper(\@INC);


use constant DAEMON_MODE	=> 1; # 0 - Off, 1 - ON
use constant LOG_STDOUT		=> 1; # 0 - Off, 1 - ON
#use constant DEBUG		=> 2; # 0 - SYS INFO & ERRORS, 1 - DHCP INFO, 2 - DHCP WARN, 3 - DHCP PKT DEBUG
use constant PID_FILE		=> '/var/run/radius_acct_server.pid';
use constant LOG_FILE		=> '/var/log/radius_acct_server.log';

use constant BIND_ADDR		=> '1.2.3.4'; # or 0.0.0.0
use constant BIND_PORT		=> 1813;
use constant SERVER_SECRET	=> 'SecString';
use constant DICTIONARY_FILE	=> $FindBin::RealBin.'/raddb/dictionary';

use constant DB_HOST		=> '8.7.6.5';
use constant DB_PORT		=> 3306;
use constant DB_LOGIN		=> 'dbuser';
use constant DB_PASSWD		=> 'dbpasswd';
use constant DB_NAME		=> 'dbname';


# Unbuffer output
$| = 1;

# for subroutine scope
my $RUNNING = 1;
my ($SOCKET_RCV, $dbh);

sub signal_handler { # exit signal received. Stopping threads from main process
	logger("INFO: TERMINATE signal catched. Shutting down jobs!");
	$RUNNING = 0;
	close($SOCKET_RCV) if $SOCKET_RCV;
}

sub norm_exit($) {
	#print "Socket alive\n" if $SOCKET_RCV;
	close($SOCKET_RCV) if $SOCKET_RCV;

	#print "connected\n" if $dbh;
	$dbh->disconnect() if $dbh;
	unlink(PID_FILE) || print "ERROR: Can't remove PID file '".PID_FILE."' on exit: $!\n";
	print "Terminated\n";
	exit($_[0]);
}

sub logger($) {
	if ( !open(MYLOG, ">> ".LOG_FILE) ) {
		print "ERROR: Log file '".LOG_FILE."' write error: $!";
		norm_exit(254);
	}
	my $curr_time = strftime("%d/%m/%y %H:%M:%S", localtime);
	if ( LOG_STDOUT ) { print STDOUT "[$curr_time] ". $_[0] ."\n"; }
	print(MYLOG "[$curr_time] ". $_[0] ."\n");
	close(MYLOG);
}

sub send_reply ($$$$$){
	my $socket = $_[0];
	my $toaddr = $_[1];
	my $rad_req = $_[2];
	my $rad_resp = $_[3];
	my $rad_serv_secret = $_[4];

	my ($to_port, $to_ip) = unpack_sockaddr_in($toaddr);
	$to_ip = inet_ntoa($to_ip);

	my $resp_udp_pkt = auth_resp($rad_resp->pack, $rad_serv_secret);

	#logger("> response ". $rad_resp->code ." to $to_ip:$to_port for User-Name ". $rad_req->attr('User-Name') .", NAS-Identifier ". $rad_req->attr('NAS-Identifier') );
	#$rad_resp->dump;
	send($socket, $resp_udp_pkt, 0, $toaddr) || logger("ERROR: Reply UDP packet send error: $!");
}


# -------- Only check and read PID file
my $pid = 0;
if ( -e PID_FILE ) {
	print "WARN: PID file exists.\n";
	open(PIDF, PID_FILE); # opening for read only
	$pid = <PIDF>;
	close(PIDF);
}

if ( $pid && -e "/proc/$pid/stat" ) { # Is proccess number already running by OS KERNEL
	print "ERROR: My process is already exists (PID $pid). Exiting.\n";
	exit(254);
}
# ---

#print "Manual exiting..";
#exit(0);

# -------- Catch terminate signals
$SIG{INT} = $SIG{TERM} = $SIG{HUP} = \&signal_handler;
$SIG{PIPE} = 'IGNORE';

# -------- Create PID file
if ( !open(PIDNF, ">".PID_FILE) ) {
	logger("ERROR: PID file '".PID_FILE."' write error: $!");
	norm_exit(254);
}
print(PIDNF "$$"); # write in to file current PID
close(PIDNF);
# ---

unless ( -r DICTIONARY_FILE ) {
	logger("ERROR: Can't read RADIUS dictionary '". DICTIONARY_FILE ."': $!");
	norm_exit(254);
}
my $rad_dict = new Net::Radius::Dictionary( DICTIONARY_FILE );

# open listening socket
if ( !socket($SOCKET_RCV, PF_INET, SOCK_DGRAM, getprotobyname('udp')) ) {
	logger("ERROR: Socket creation: $!");
	norm_exit(254);
}

if ( !bind($SOCKET_RCV, sockaddr_in(BIND_PORT, inet_aton(BIND_ADDR))) ) {
	logger("ERROR: Can't bind socket to '". BIND_ADDR .":". BIND_PORT ."': $!");
	norm_exit(254);
}

# make DB connection
$dbh = DBI->connect("DBI:mysql:database=".DB_NAME.";host=".DB_HOST.";port=".DB_PORT, DB_LOGIN, DB_PASSWD);
if ( defined($dbh) == 0 ) {
	logger("ERROR: Can't connect to database: ". $DBI::errstr);
	norm_exit(254); # this check only at first start of a script
}
$dbh->{mysql_auto_reconnect} = 1;




logger("STARTED script: '". abs_path($0) ."', BIND_ADDR: ".BIND_ADDR.", PORT: ".BIND_PORT.", PID_FILE: '".PID_FILE."'");

if ( DAEMON_MODE == 1 ) {
	logger("INFO: Conf DAEMON_MODE=1. Entering Daemon mode.");

	delete @ENV{qw(IFS CDPATH ENV BASH_ENV)}; # Make %ENV safer
	open(STDIN,  "+>/dev/null") or die "Can't open STDIN: $!\n";
	open(STDOUT, "+>&STDIN") or die "Can't open STDOUT: $!\n";
	open(STDERR, "+>&STDIN") or die "Can't open STDERR: $!\n";
	defined(my $tm = fork)  or die "Can't fork script proccess: $!\n";
	exit(254) if $tm;
	setsid() or die "Can't start a new session: $!\n";
	umask 0;
	# ---- Updating PID_FILE with new PID
	if ( !open(PIDNF, ">".PID_FILE) ) {
		logger("ERROR: PID file '".PID_FILE."' write error after daemonizing: $!");
		norm_exit(254);
	}
	print(PIDNF "$$"); # write in to file current PID
	close(PIDNF);
	logger("INFO: New PID is $$");
}


# Loop forever, recieving packets and replying to them
my ($recv_udp_pkt, $recv_udp_from_addr, $recv_udp_from_ip, $recv_udp_from_port, $rad_req, $rad_resp);
my ($sth, $data);
my ($Acct_Status_Type);
my ($qUser_Name, $qAcct_Session_Id, $qNAS_IP_Address);
my ($db_aid, $db_uid);
my ($Acct_Session_Time, $bytes_Uploaded, $bytes_Downloaded);

while ($RUNNING == 1) {
	$recv_udp_pkt = undef;
	$recv_udp_from_addr = undef;
	$rad_req = undef; $rad_resp = undef;
	$sth = undef; $data = undef;
	$Acct_Status_Type = undef;
	$qUser_Name = undef; $qAcct_Session_Id = undef; $qNAS_IP_Address = undef;
	$db_aid = undef; $db_uid = undef;
	$Acct_Session_Time = undef; $bytes_Uploaded = undef; $bytes_Downloaded = undef;


	$recv_udp_from_addr = recv($SOCKET_RCV, $recv_udp_pkt, 1500, 0) || logger("ERROR: UDP packet recv err: $!");
	if ( $RUNNING == 0 ) {
		logger("Terminating.\n");
		norm_exit(0);
	}
	#sleep(1);

	($recv_udp_from_port, $recv_udp_from_ip) = unpack_sockaddr_in($recv_udp_from_addr);
	$recv_udp_from_ip = inet_ntoa($recv_udp_from_ip);

	# filter to small packets
	if ( length($recv_udp_pkt) < 20 ) {
		logger("WARN: Received to small UDP packet! From $recv_udp_from_ip:$recv_udp_from_port, length=".length($recv_udp_pkt)."b");
		next;
	}
	
	# Unpack it
	$rad_req = new Net::Radius::Packet $rad_dict, $recv_udp_pkt;

	if ( !defined($rad_req->code) ) {
		logger("WARN: Undefined packet CODE recieved from $recv_udp_from_ip:$recv_udp_from_port.");
		next;
	}

	# Accounting-Request
	if ( $rad_req->code ne 'Accounting-Request' ) {
		# It's not an Accounting-Request
		logger("WARN: Unexpected packet CODE '". $rad_req->code ."' recieved from $recv_udp_from_ip:$recv_udp_from_port.");
		next;
	}

	if ( !auth_acct_verify($recv_udp_pkt, SERVER_SECRET) ) {
		logger("WARN: Verified bad 'authenticator' in a packet (may be SERVER_SECRET mismatch) recieved from $recv_udp_from_ip:$recv_udp_from_port.");
		next;
	}

	if ( !defined($rad_req->attr('Framed-Protocol')) ) {
		logger("WARN: Attribute 'Framed-Protocol' is not defined in a request message from $recv_udp_from_ip:$recv_udp_from_port");
		next;
	}

	if ( $rad_req->attr('Framed-Protocol') ne 'ISG' ) {
	#if ( $rad_req->attr('Framed-Protocol') ne 'PPP' ) {
		logger("WARN: Disallowed Framed-Protocol '". $rad_req->attr('Framed-Protocol') ."' in a request message from $recv_udp_from_ip:$recv_udp_from_port");
		next;
	}

	$Acct_Status_Type = $rad_req->attr('Acct-Status-Type');
	if ( !defined($Acct_Status_Type) ) {
		logger("WARN: Attribute 'Acct-Status-Type' is not defined in a request message from $recv_udp_from_ip:$recv_udp_from_port");
		next;
	}

	#print "Req Accounting-Request from:\n"
	#	."-> Acct-Status-Type: ".$rad_req->attr('Acct-Status-Type') ."\n"
	#	."-> User-Name: ".$rad_req->attr('User-Name') ."\n"
	#	."-> NAS-IP-Address: ".$rad_req->attr('NAS-IP-Address') ."\n"
	#	."-> NAS-Identifier: ".$rad_req->attr('NAS-Identifier') ."\n"
	#	#."-> NAS-Port: ".$rad_req->attr('NAS-Port') ."\n"
	#	."-> Framed-Protocol: ".$rad_req->attr('Framed-Protocol') ."\n"
	#	."-> Acct-Session-Id: ".$rad_req->attr('Acct-Session-Id') ."\n"
	#	."\n";

	$rad_resp = new Net::Radius::Packet($rad_dict);

	$rad_resp->set_identifier($rad_req->identifier);
	$rad_resp->set_authenticator($rad_req->authenticator);
	$rad_resp->set_code('Accounting-Response');

	# $p->set_vsattr("Cisco", "Cisco-Service-Info", "N" . $ev->{'service_name'});
	if ( defined($rad_req->vsattr('Cisco','Cisco-Service-Info')) ) { logger($rad_req->vsattr('Cisco','Cisco-Service-Info')); }

	# Acct-Status-Type
	if ( $Acct_Status_Type eq 'Start' ) {
		#logger("recv Start");
		$qUser_Name = $dbh->quote( $rad_req->attr('User-Name') );
		$qAcct_Session_Id = $dbh->quote( $rad_req->attr('Acct-Session-Id') );
		$qNAS_IP_Address = $dbh->quote( $rad_req->attr('NAS-IP-Address') );
		#$qNAS_IP_Address = $dbh->quote( $rad_req->attr('NAS-Identifier') );

		$sth = $dbh->prepare("SELECT
					params_lan.account_id AS aid,
					params_lan.uid AS uid
				FROM
					params_lan
				WHERE
					params_lan.ip = INET_ATON($qUser_Name)
				LIMIT 1;
		") or logger("ERROR: Can't prepare SQL statement: ".$DBI::errstr);
		$sth->execute() or logger("ERROR: Can't execute SQL statement: ".$DBI::errstr);

		unless ( $data = $sth->fetchrow_hashref() ) {
			logger("WARN: Failed START ISG acct for Acct-Session-Id: ".$rad_req->attr('Acct-Session-Id').". User ".$rad_req->attr('User-Name')." not found.");
			$sth->finish();
			next;
		}
		$sth->finish();

		$db_aid = $data->{'aid'};
		$db_uid = $data->{'uid'};

		logger("START ISG acct for AID: ". $db_aid .", User-Name: ". $rad_req->attr('User-Name') );
		# mark all previous active user sessions flagged closed
		$dbh->do("UPDATE radius_accounting SET session_ended=1, end_date_unix=(recv_date_unix+session_time) WHERE account_id=$db_aid AND session_ended=0 AND service='ipoe';") or logger("ERROR: Can't do SQL statement: ".$DBI::errstr);

		# insert new user session
		$dbh->do("INSERT INTO
					radius_accounting
				SET
					radius_accounting.account_id = $db_aid,
					radius_accounting.uid = $db_uid,
					radius_accounting.recv_date_unix = UNIX_TIMESTAMP(),
					radius_accounting.remote_ip = INET_ATON($qUser_Name),
					radius_accounting.session_id = $qAcct_Session_Id,
					radius_accounting.nas_ip = INET_ATON($qNAS_IP_Address),
					radius_accounting.session_ended = 0,
					radius_accounting.service = 'ipoe';
		") or logger("ERROR: Can't do SQL statement: ".$DBI::errstr);

		# update user account
		$dbh->do("UPDATE params_inet
				SET
					params_inet.online = 1,
					params_inet.last_nas_ip = INET_ATON($qNAS_IP_Address),
					params_inet.last_session_id = $qAcct_Session_Id,
					params_inet.last_online_date = UNIX_TIMESTAMP()
				WHERE
					params_inet.account_id = $db_aid
				LIMIT 1;
		") or logger("ERROR: Can't do SQL statement: ".$DBI::errstr);


		send_reply($SOCKET_RCV, $recv_udp_from_addr, $rad_req, $rad_resp, SERVER_SECRET);


	} elsif ( $Acct_Status_Type eq 'Alive' ) { # aka Interim-Update
		logger("UPDATE ISG acct for Acct-Session-Id: ". $rad_req->attr('Acct-Session-Id') .", User-Name: ". $rad_req->attr('User-Name') );

		#print $rad_req->attr('Acct-Input-Octets')."aIO\n";
		#print $rad_req->attr('Acct-Output-Octets')."aOO\n";
		#print $rad_req->attr('Acct-Input-Gigawords')."aIG\n";
		#print $rad_req->attr('Acct-Output-Gigawords')."aOG\n";

		$qAcct_Session_Id = $dbh->quote( $rad_req->attr('Acct-Session-Id') );
		$Acct_Session_Time = sprintf("%u", $rad_req->attr('Acct-Session-Time') );
		$bytes_Uploaded = sprintf("%u", $rad_req->attr('Acct-Input-Octets') + $rad_req->attr('Acct-Input-Gigawords') * 2**32 );
		$bytes_Downloaded = sprintf("%u", $rad_req->attr('Acct-Output-Octets') + $rad_req->attr('Acct-Output-Gigawords') * 2**32 );

		$dbh->do("UPDATE radius_accounting, params_inet
				SET
					radius_accounting.session_time = $Acct_Session_Time,
					radius_accounting.downloaded_bytes = $bytes_Downloaded,
					radius_accounting.uploaded_bytes = $bytes_Uploaded,
					params_inet.online = 1,
					params_inet.last_online_date = UNIX_TIMESTAMP()
				WHERE
					radius_accounting.account_id = params_inet.account_id
					AND radius_accounting.session_id = $qAcct_Session_Id
					AND radius_accounting.session_ended = 0;
		") or logger("ERROR: Can't do SQL statement: ".$DBI::errstr);

		send_reply($SOCKET_RCV, $recv_udp_from_addr, $rad_req, $rad_resp, SERVER_SECRET);


	} elsif ( $Acct_Status_Type eq 'Stop' ) {
		logger("STOP ISG acct for Acct-Session-Id: ". $rad_req->attr('Acct-Session-Id') .", User-Name: ". $rad_req->attr('User-Name') );

		$qAcct_Session_Id = $dbh->quote( $rad_req->attr('Acct-Session-Id') );
		$Acct_Session_Time = sprintf("%u", $rad_req->attr('Acct-Session-Time') );
		$bytes_Uploaded = sprintf("%u", $rad_req->attr('Acct-Input-Octets') + $rad_req->attr('Acct-Input-Gigawords') * 2**32 );
		$bytes_Downloaded = sprintf("%u", $rad_req->attr('Acct-Output-Octets') + $rad_req->attr('Acct-Output-Gigawords') * 2**32 );

		$dbh->do("UPDATE radius_accounting, params_inet
				SET
					radius_accounting.session_time = $Acct_Session_Time,
					radius_accounting.downloaded_bytes = $bytes_Downloaded,
					radius_accounting.uploaded_bytes = $bytes_Uploaded,
					radius_accounting.session_ended = 1,
					radius_accounting.end_date_unix = UNIX_TIMESTAMP(),
					params_inet.online = 0,
					params_inet.last_online_date = UNIX_TIMESTAMP()
				WHERE
					radius_accounting.account_id = params_inet.account_id
					AND radius_accounting.session_id = $qAcct_Session_Id
					AND radius_accounting.session_ended = 0;
		");

		send_reply($SOCKET_RCV, $recv_udp_from_addr, $rad_req, $rad_resp, SERVER_SECRET);


	} else {
		logger("WARN: Unknown attribute Acct-Status-Type: '".$rad_req->attr('Acct-Status-Type')."' in a request message from $recv_udp_from_ip:$recv_udp_from_port");
	}
} # end while

logger("Terminating.\n");
norm_exit(0);


