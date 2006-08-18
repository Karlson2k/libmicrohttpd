#!/usr/bin/perl
# Perl CGI document template... by Luis Figueiredo (stdio@netc.pt)
#
#
#


#use strict;
my %POST;
my %QUERY_STRING;
my %COOKIE;
my $stdindata;

while(<STDIN>) {
	$stdindata.=$_;
};
if($ENV{QUERY_STRING}) {
        my (@varsdata)=split(/&/,$ENV{QUERY_STRING});
        foreach (@varsdata) {
                my ($name,$value)=split(/=/,$_);
                $value =~ s/\+/ /g;
                $value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C",hex($1))/eg;
                $QUERY_STRING{$name}=$value;
        };
 
};                        
if($ENV{REQUEST_METHOD} =~ m/POST/ && $ENV{CONTENT_TYPE} =~ m/application\/x-www-form-urlencoded/i) {
        my (@varsdata)=split(/&/,$stdindata);
        foreach (@varsdata) {
                my ($name,$value)=split(/=/,$_);
                $value =~ s/\+/ /g;
                $value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C",hex($1))/eg;
                $POST{$name}=$value;
        };
 
};                              
if($ENV{HTTP_COOKIE} || $ENV{COOKIE}) {
	my $cookie=$ENV{HTTP_COOKIE} || $ENV{COOKIE};
	my(@cookiedata)=split(/; /,$cookie);
	foreach(@cookiedata) {
		$_ =~ /(.*?)=(.*)/;	
		$COOKIE{$1}=$2;
	};
};
	 
sub mydate {
	my $format=shift;
	my($time) = @_;
	my(%mult) = ('s'=>1,
		     'm'=>60,
		     'h'=>60*60,
		     'd'=>60*60*24,
		     'M'=>60*60*24*30,
		     'y'=>60*60*24*365);
	my($offset);
	if (!$time || (lc($time) eq 'now')) {
	    $offset = 0;
	} elsif ($time=~/^\d+/) {
	    $offset=($time-time);
	} elsif ($time=~/^([+-]?(?:\d+|\d*\.\d*))([mhdMy]?)/) {
	    $offset = ($mult{$2} || 1)*$1;
	} else {
	    $offset=($time-time);
	}
	my(@MON)=qw/Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec/;
	my(@LMON)=qw/January February March April May June July August September October November December/;
	my(@WDAY) = qw/Sun Mon Tue Wed Thu Fri Sat/;   	
	my(@LWDAY) = qw/Sunday Monday Tuesday Wednesday Thursday Friday Saturdat/;   	
	my($sec,$min,$hour,$mday,$mon,$year,$wday) = gmtime(time+$offset);      
	$year+=1900;
	$format =~ s/\%Y/$year/eg;
	$format =~ s/\%a/$WDAY[$wday]/eg;
	$format =~ s/\%A/$LWDAY[$wday]/eg;
	$format =~ s/\%m/sprintf("%02d",$mon+1)/eg;
	$format =~ s/\%d/sprintf("%02d",$mday)/eg;
	$format =~ s/\%H/sprintf("%02d",$hour)/eg;
	$format =~ s/\%M/sprintf("%02d",$min)/eg;
	$format =~ s/\%S/sprintf("%02d",$sec)/eg;
	$format =~ s/\%b/$MON[$mon]/eg;
	$format =~ s/\%B/$LMON[$mon]/eg;
	$format =~ s/\%Z/GMT/g;
	return $format;
}                     

sub cookie {
	my $name=shift;
	my $value=shift;
	my $expire=shift;
	if($value eq "") {
		print "Set-Cookie: $name; path=$ENV{SCRIPT_NAME}; ";
	} else {
		print "Set-Cookie: $name=$value; path=$ENV{SCRIPT_NAME}; ";
	};
	if($expire) {
		print "expires=".mydate("%a, %d-%b-%Y %H:%M:%S %Z",$expire);
	};
	#print " secure";
	print "\r\n"; # end cookie
};


#COOKIES


#print "Date: ".mydate("%a, %d %b %Y %H:%M:%S %Z","+5m")."\n";	
cookie("teste1","maria","+5m");
cookie("login","manel","+5m");
print "Content-type: text/html\r\n\r\n";



print "<HTML>\n";
print "<BODY bgcolor='EFEFEF'>\n";
print "Simple cgi demo<BR>\n";
print "<form action='$ENV{SCRIPT_NAME}?teste=new' method='POST'>\n";
print "post value: <input type='text' name='login'>\n";
print "<input type=submit name='go' value='send'>\n";
print "</form><BR>\n";

print "results:<table border=1><TR><TD>cookie 'maria'</TD><TD> $COOKIE{teste1}</TD></TR>\n";
print "<TR><TD>post 'login':</TD><TD> $POST{login}</TD></TR>\n";
print "<TR><TD>querystring 'teste':</TD><TD> $QUERY_STRING{teste}</TD></TR>\n";
print "</TABLE>\n";

print "</BODY></HTML>\n";
