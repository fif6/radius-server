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
use constant PID_FILE		=> '/var/run/radius_auth_server.pid';
use constant LOG_FILE		=> '/var/log/radius_auth_server.log';

use constant BIND_ADDR		=> '1.2.3.4'; # or 0.0.0.0
use constant BIND_PORT		=> 1812;
use constant SERVER_SECRET	=> 'seckey';
use constant DICTIONARY_FILE	=> $FindBin::RealBin.'/raddb/dictionary';

use constant DB_HOST		=> '7.6.5.4';
use constant DB_PORT		=> 3306;
use constant DB_LOGIN		=> 'dbusr';
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

	logger("Sending response ". $rad_resp->code ." to $to_ip:$to_port for User-Name ". $rad_req->attr('User-Name') .", "
	. ( defined($rad_req->attr('NAS-Identifier')) ? "NAS-Identifier ".$rad_req->attr('NAS-Identifier') : "NAS-IP-Address ".$rad_req->attr('NAS-IP-Address') ) );
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
my ($sth, $data, $qUser_Name, $db_aid, $qAcct_Session_Id, $qNAS_IP_Address);
my ($Dbps, $Ubps, $Dburst, $Uburst);


while ($RUNNING == 1) {
	$recv_udp_pkt = undef;
	$recv_udp_from_addr = undef;
	$rad_req = undef;
	$rad_resp = undef;
	$sth = undef;
	$data = undef;
	$qUser_Name = undef;
	$db_aid = undef;

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
		# It's not an Access-Request
		logger("WARN: Undefined packet CODE recieved from $recv_udp_from_ip:$recv_udp_from_port.");
		next;
	}

	if ( $rad_req->code ne 'Access-Request' ) {
		# It's not an Access-Request
		logger("WARN: Unexpected packet CODE '". $rad_req->code ."' recieved from $recv_udp_from_ip:$recv_udp_from_port.");
		next;
	}

	if ( !defined($rad_req->attr('Framed-Protocol')) ) {
		logger("WARN: Attribute 'Framed-Protocol' is not defined in a request message from $recv_udp_from_ip:$recv_udp_from_port");
		next;
	}

	#if ( $rad_req->attr('Framed-Protocol') ne 'ISG' ) {
	#if ( $rad_req->attr('Framed-Protocol') ne 'PPP' ) {
	#	logger("WARN: Disallowed Framed-Protocol '". $rad_req->attr('Framed-Protocol') ."' in a request message from $recv_udp_from_ip:$recv_udp_from_port");
	#	next;
	#}



	if ( $rad_req->attr('Framed-Protocol') eq 'ISG' ) {
	#if ( $rad_req->attr('Framed-Protocol') eq 'PPP' ) {
		if ( $rad_req->attr('User-Name') ne $rad_req->password(SERVER_SECRET) ) {
			logger("WARN: Attributes 'User-Name' <=> 'Password' mismatch for ISG auth. Check Client-Server SECRET identity");
			next;
		}
		# OK! Its Cisco ISG Access-Request

		#print "Req Access-Request from:\n"
		#	."-> User-Name: ".$rad_req->attr('User-Name') ."\n"
		#	."-> User-Password: ". $rad_req->password(SERVER_SECRET) ."\n"
		#	."-> NAS-IP-Address: ".$rad_req->attr('NAS-IP-Address') ."\n"
		#	."-> NAS-Identifier: ".$rad_req->attr('NAS-Identifier') ."\n"
		#	."-> NAS-Port: ".$rad_req->attr('NAS-Port') ."\n"
		#	."-> Framed-Protocol: ".$rad_req->attr('Framed-Protocol') ."\n"
		#	."\n";

		$rad_resp = new Net::Radius::Packet($rad_dict);

		$rad_resp->set_identifier($rad_req->identifier);
		$rad_resp->set_authenticator($rad_req->authenticator);


		$qUser_Name = $dbh->quote( $rad_req->attr('User-Name') );
		$sth = $dbh->prepare("SELECT
				usr_acc.id AS aid,
				usr_acc.uid AS uid,
				IFNULL(params_inet.download_speed,0) AS download_speed,
				IFNULL(params_inet.upload_speed,0) AS upload_speed,
				IFNULL(params_inet.service_blocked,1) AS service_blocked,
				params_inet.ppp_enable AS ppp_enabled
			FROM usr_acc
				LEFT JOIN params_inet ON params_inet.account_id = usr_acc.id
				LEFT JOIN service_lan ON service_lan.account_id = usr_acc.id
			WHERE
				service_lan.ip = INET_ATON($qUser_Name)
			LIMIT 1;
		") or logger("ERROR: Can't prepare SQL statement: ".$DBI::errstr);

		#$sth = $dbh->prepare("select null from dual where false;") or logger("ERROR: Can't prepare SQL statement: ".$DBI::errstr);

		$sth->execute() or logger("ERROR: Can't execute SQL statement: ".$DBI::errstr);


		unless ( $data = $sth->fetchrow_hashref() ) {
			logger("WARN: No any DB data for User-Name: ". $rad_req->attr('User-Name') );
			$rad_resp->set_code( 'Access-Reject' );
			$rad_resp->set_attr( 'Reply-Message' => 'No any DB data for User-Name: '. $rad_req->attr('User-Name') );
			$rad_resp->set_attr( 'Session-Timeout' => 600 );
			$rad_resp->set_vsattr( 'Cisco', 'Cisco-Account-Info' => 'AREDIR' );

			send_reply($SOCKET_RCV, $recv_udp_from_addr, $rad_req, $rad_resp, SERVER_SECRET);
			$sth->finish();
			next;
		}
		$sth->finish();

		# USER FOUNDED!
		$db_aid = $data->{'aid'};

		# UPDATING params_inet at every user RADIUS auth activity
		if ( defined($rad_req->attr('Acct-Session-Id')) ) {
			$qAcct_Session_Id = $dbh->quote( $rad_req->attr('Acct-Session-Id') );
			$qNAS_IP_Address = $dbh->quote( $rad_req->attr('NAS-IP-Address') );
			#$qNAS_IP_Address = $dbh->quote( $rad_req->attr('NAS-Identifier') );
			$dbh->do("UPDATE params_inet
				SET
					params_inet.last_nas_ip = INET_ATON($qNAS_IP_Address),
					params_inet.last_session_id = $qAcct_Session_Id,
					params_inet.last_radius_auth_activity_date = UNIX_TIMESTAMP()
				WHERE
					params_inet.account_id = $db_aid
				LIMIT 1;
			") or logger("ERROR: Can't do SQL statement: ".$DBI::errstr);
			logger( "Req Acct-Session-Id: ".$rad_req->attr('Acct-Session-Id') );
		}

		if ( $data->{'ppp_enabled'} == 1 ) {
			# IPoE disabled for this user. Check and disable option PPPoE enabled
			# sending Reject
			$rad_resp->set_code( 'Access-Reject' );
			$rad_resp->set_attr( 'Reply-Message' => "IPoE disabled for User-Name: ". $rad_req->attr('User-Name') );
			$rad_resp->set_attr( 'Session-Timeout' => 600 );
			$rad_resp->set_vsattr( 'Cisco', 'Cisco-Account-Info' => 'AREDIR' );
			#$dbh->do("UPDATE params_inet 
			#		SET params_inet.last_radius_auth_activity_date=UNIX_TIMESTAMP(), params_inet.online=2
			#		WHERE params_inet.account_id=$db_aid LIMIT 1;") or logger("ERROR: Can't do SQL statement: ".$DBI::errstr);

			send_reply($SOCKET_RCV, $recv_udp_from_addr, $rad_req, $rad_resp, SERVER_SECRET);
			next;
		}

		if ( $data->{'service_blocked'} == 1 ) {
			# Service Inet blocked for this Account
			# sending Reject with settings for Guest ISG session
			# IPoE Reject (TCP 80 dst redirect to NGINX) - service REDIR
			$rad_resp->set_code( 'Access-Reject' );
			$rad_resp->set_attr( 'Reply-Message' => "IPoE enabled, but Inet blocked for User-Name: ". $rad_req->attr('User-Name') );
			$rad_resp->set_attr( 'Session-Timeout' => 600 );
			$rad_resp->set_vsattr( 'Cisco', 'Cisco-Account-Info' => 'AREDIR' );

			send_reply($SOCKET_RCV, $recv_udp_from_addr, $rad_req, $rad_resp, SERVER_SECRET);
			next;
		}

		$Dbps = $data->{'download_speed'} * 1000; # download
		if ( $Dbps > 1000000 ) { # if over 1 Mbps
			$Dburst = int( ($Dbps*0.125) * 0.25 ); # Dbps/8 * COEFF 0.25
		} else {
			$Dburst = int( ($Dbps*0.125) * 1.5 ); # Dbps/8 * COEFF 1.5
		}

		$Ubps = $data->{'upload_speed'} * 1000; # upload
		if ( $Ubps > 1000000 ) { # if over 1 Mbps
			$Uburst = int( ($Ubps*0.125) * 0.25 );
		} else {
			$Uburst = int( ($Ubps*0.125) * 1.5 );
		}

		$rad_resp->set_code( 'Access-Accept' );
		$rad_resp->set_attr( 'Reply-Message' => "IPoE enabled, Inet Accepted for User-Name: ". $rad_req->attr('User-Name') );
		$rad_resp->set_attr( 'Class' => 'aid_'. $db_aid );
		$rad_resp->set_attr( 'Session-Timeout' => 172800 ); # 48 hours
		$rad_resp->set_attr( 'Idle-Timeout' => 43200 ); # 12 hours
		$rad_resp->set_attr( 'Acct-Interim-Interval' => 600 ); # accounting interval 10 min
		$rad_resp->set_vsattr( 'Cisco', 'Cisco-Account-Info' => "QU;$Dbps;$Dburst;D;$Ubps;$Uburst" );

		send_reply($SOCKET_RCV, $recv_udp_from_addr, $rad_req, $rad_resp, SERVER_SECRET);
	} else {
		logger("WARN: Disallowed Framed-Protocol '". $rad_req->attr('Framed-Protocol') ."' in a request message from $recv_udp_from_ip:$recv_udp_from_port");
		next;
	}
} # end while

logger("Terminating.\n");
norm_exit(0);


