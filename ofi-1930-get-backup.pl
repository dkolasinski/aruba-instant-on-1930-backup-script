#!/usr/bin/perl
## Author: Dariusz Zielinski-Kolasinski
## Licence: GPL
## Version: 1.1 (2025-02-07)
##
## This is Aruba Instant ON 1930 Switch startup-configuration download script
##
## WARNING: disables TLS certificate validation
## 
## Tested with 2.9.0.x firmware on JL685A (Aruba Instant ON 1930)
## Tested with 3.1.0.x firmware on JL685A (Aruba Instant ON 1930)
## Tested with v3.4.0.17:
## * CISCO CBS350-24XS (whole stack)
## * CISCO CBS350-24T-4X (whole stack)
## * CISCO CBS350-48T-4X (whole stack)
## * CISCO CBS350-48P-4X (whole stack)


use strict;
use LWP::UserAgent;
use HTTP::Cookies;
use HTTP::Request::Common;
use Term::ANSIColor qw(:constants);
#
use Crypt::OpenSSL::RSA;
use URI::Escape;
#
# FOR DEBUGGING:
# DEBUG: use LWP::ConsoleLogger::Easy qw(debug_ua);

### INPUT
if ($#ARGV != 3) {
	print "Usage: $0 <ip/hostname> <user> <pass> <output filename>\n";
	exit(1);
}

### VALIDATE INPUT
my $username = $ARGV[1];
my $password = $ARGV[2];
my $host = $ARGV[0];
my $filename = $ARGV[3];

unless ($host =~ /^[0-9a-zA-Z\.\-]+$/) {
	print RED,"IP/Hostname - input does not match pattern!\n",RESET;
	exit(1);
}

### INIT
my $cookie_jar = HTTP::Cookies->new();

# Some cookies :P
# maybe not needed
$cookie_jar->set_cookie(0,'activeLangId', 'english','/',$host,443,0,0,86400,0);
$cookie_jar->set_cookie(0,'sessionID', '','/',$host,443,0,0,86400,0);
$cookie_jar->set_cookie(0,'userName', '','/',$host,443,0,0,86400,0);
$cookie_jar->set_cookie(0,'firstWelcomeBanner', 'true','/',$host,443,0,0,86400,0);
$cookie_jar->set_cookie(0,'LogOff_Reason', 'Manual','/',$host,443,0,0,86400,0);

my $ua = LWP::UserAgent->new;

# FOR DEBUGGING:
#DEBUG: debug_ua($ua);

## SSL Options - nobody uses valid certs on switches :P
$ua->ssl_opts(verify_hostname => 0);
$ua->ssl_opts(SSL_verify_mode => 0x00);

$ua->cookie_jar( $cookie_jar );


########### 1 - REQ - get document root
# no, don`t follow
$ua->max_redirect(0);

my $resp = $ua->get('https://'.$host);

my $documentRoot = '';
my $initialLocation = '';
if ($resp->is_redirect) {
	$initialLocation = $resp->header("Location");
	if ($initialLocation =~ /^\/([^\/]+)/) {
		$documentRoot = $1;
		print GREEN,"req 1. LOCATION REQ OK",RESET,"\n";

	} else {
		print RED,"req 1. LOCATION REQ OK, BUT CANNOT PARSE LOCATION STRING: ",RESET,$initialLocation,"\n";
		exit(1);
	}
} else {
	print RED,"req 1. LOCATION HEADER EXPECTED BUT NOT FOUND: ",RESET,$resp->status_line,"\n";
	exit(1);
}

########### 2 - REQ - get cookies and login page
my $resp = $ua->get('https://'.$host.$initialLocation);

if ($resp->is_success) {
	if (index($resp->content, 'inputUsername') != -1) {
		print GREEN,"req 2. INITIAL REQ OK: ", YELLOW, " ARUBA INSTANT ON DETECTED\n", RESET;
	} elsif (index($resp->content, 'UserCntrl') != -1) {
		print GREEN,"req 2. INITIAL REQ OK: ", YELLOW, " CISCO CBS DETECTED\n", RESET;
	} else {
		print RED,"req 2. INITIAL REQ OK, BUT LOGIN FIELD NOT FOUND: ",RESET,$resp->content,"\n";
		exit(1);
	}
} else {
	print RED,"req 2. INITIAL REQ ERROR: ", RESET, $resp->status_line,"\n";
	exit(1);
}

########### 3 - REQ - get encryption key and encryption settings
$resp = $ua->get('https://'.$host.'/device/wcd?{EncryptionSetting}',
    'Accept' => 'application/xml, text/xml');

my $rsaPublicKey = '';
my $loginToken = '';
my $passwEncryptEnable = '';
if ($resp->is_success) {
	# this should be done via XML modules
	# no time for that - just regexp it out :P
	my $content = $resp->content;

	if ($content =~ /<rsaPublicKey>(.+)<\/rsaPublicKey>/s) {
		$rsaPublicKey = $1;
		print GREEN,"req 3. RSA KEY REQ OK\n",RESET;
	} else {
		print RED,"req 3. RSA KEY REQ OK, BUT NO RSA KEY FOUND, RESPONSE: ",RESET,$resp->content,"\n";
		exit(1);
	}

	if ($content =~ /<loginToken>(.+)<\/loginToken>/s) {
		$loginToken = $1;
		print GREEN,"req 3. LOGIN TOKEN REQ OK\n",RESET;
	} else {
		print RED,"req 3. LOGIN TOKEN OK, BUT NO LOGIN TOKEN FOUND, RESPONSE: ",RESET,$resp->content,"\n";
		exit(1);
	}

	if ($content =~ /<passwEncryptEnable>(.+)<\/passwEncryptEnable>/s) {
		$passwEncryptEnable = $1;
		print GREEN,"req 3. PASSWORD ENCRYPT ENABLE REQ OK\n",RESET;
	} else {
		print RED,"req 3. PASSWORD ENCRYPT ENABLE REQ OK, BUT NO PASSWORD ENCRYPT ENABLE FOUND, RESPONSE: ",RESET,$resp->content,"\n";
		exit(1);
	}

} else {
	print RED,"req 3. INITIAL ENCRYPTION REQ ERROR: ", RESET, $resp->status_line,"\n";
	exit(1);
}

########### 4 - REQ - login
# WARNING! orignal used encodeURIComponent on password and username
# IF SOMETHING IS NOT WORKING HERE TRY REMOVING IT!
# uri_escape is a bit more aggresive than encodeURIComponent
my $login_string = 'user=' .  uri_escape($username) . '&password=' .  uri_escape($password) . '&ssd=true' . '&token=' . $loginToken . '&';

my $hex_encrypted = '';
if ($passwEncryptEnable eq '1') {
	# encryption required?
	my $rsa_public = Crypt::OpenSSL::RSA->new_public_key($rsaPublicKey);
	$rsa_public->use_sha1_hash();
	$rsa_public->use_pkcs1_padding();
	my $encrypted = $rsa_public->encrypt($login_string);
	$hex_encrypted = unpack('H*', $encrypted);
} else {
	$hex_encrypted = $login_string;
}

$resp = $ua->get('https://'.$host.'/'.$documentRoot.'/hpe/config/system.xml?action=login&cred='.$hex_encrypted);

if ($resp->is_success) {
	my $lresp = '';
	if ($resp->content =~ /<statusString>(.+)<\/statusString>/s) {
		$lresp = $1;
	}

	if ($lresp ne 'OK') {
		print RED,"req 4. LOGIN FAILED, RESPONSE: ",RESET,$lresp,"\n";
		exit(1);
	} else {
		print GREEN,"req 4. LOGIN OK\n", RESET;
	}
} else {
	print RED,"req 4. LOGIN REQUEST ERROR: ", RESET, $resp->status_line,"\n";
	exit(1);
}

########### 5 - REQ - request startup-config
my $resp = $ua->get('https://'.$host.'/'.$documentRoot.'/hpe/http_download?action=3&ssd=4');

if ($resp->is_success) {
	print GREEN,"req 5. DOWNLOAD OK\n",RESET;
	open(FD, ">$filename") || die "Can`t open: $filename: $!\n";
	print FD $resp->content;
	close(FD);
} else {
	print RED,"req 5. DOWNLOAD ERROR: ",RESET, $resp->status_line,"\n";
	exit(1);
}

print GREEN,"END OF SCRIPT, EXITING\n",RESET;
