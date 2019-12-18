# NSEC/NSEC3のType Bit Mapsについて

本投稿は、2019年11月28日の[DNS BoFでの発表内容](https://speakerdeck.com/sischkg/nsec3falsetype-bit-mapsnituite)と同じものです。
また、DNS温泉番外編2のLTの最後のスライド(未公開)の詳細でもあります。

## PowerDNS RecursorのType Bit Mapsの実装に起因するメモリ使用量の問題

### 概要

* PowerDNS Recursor 4.2.0未満には、NSEC/NSEC3のType Bit Mapの実装に問題があり、
  特殊なリソースレコードをキャッシュすると想定以上のメモリ（リソースレコードあたり3MB)を消費します。
* PowerDNS Recursorにはキャッシュのエントリ数を制限する機能はありますが、
  メモリ使用量でキャッシュを制限する機能はありません。
* PowerDNS Recursorに特殊なリソースレコードを多くキャッシュさせることで、
  管理者の想定以上にメモリを消費しサービスのパフォーマンスの低下や停止を
  発生させることができます。

### 影響

攻撃者は特殊なNSEC/NSECレコードを応答する攻撃用のドメイン名とその権威サーバを用意し、
攻撃対象のPowerDNS Recursorへ攻撃用のドメイン名の問い合わせを送信し続けることで、
攻撃対象のサーバのメモリ使用量を増加させることができます。

### 対象

* PowerDNS Recursor 4.2.0未満(DNSSEC Validationの有無は関係ありません)

### 回避策

リソースレコードあたり3MBのメモリを消費する前提で、
キャッシュのエントリ数を制限します([max-cache-entries](https://doc.powerdns.com/recursor/settings.html#setting-max-cache-entries) )。
ただし、キャッシュのエントリ数が少なるなるためヒット率が低下します。

### 対策

PowerDNS Recursor 4.2.0へバージョンアップします。

### 詳細

#### Type Bit Maps

DNSSECおいてドメイン名もしくはRRSetが存在しないことを証明するために、NSECリソースレコードが導入されました。
NSECレコードのType Bit Mapsフィールドでは、Ownerに存在するリソースレコードタイプを示ししています。
Type Bit MapsのWire Formatは、単純なリソースレコードタイプ(16bit)の配列ではなくサイズがより小さくなるように定義されています。
詳細は[BoFの発表資料](https://speakerdeck.com/sischkg/nsec3falsetype-bit-mapsnituite?slide=5)を参照してください。

#### PowerDNS RecursorのType Bit Mapsの実装

4.2.0未満のPowerDNS Recursorでは、Type Bit Mapsの値をC++のSTLのstd::set<uint16_t>で保持しています
([class NSECRecordContent](https://github.com/PowerDNS/pdns/blob/rec-4.1.14/pdns/dnsrecords.hh#L506) )。
Type Bit MapsのTypeの1bitが、std::set<uinit16_t>の1エントリに対応しています。

```c++
class NSECRecordContent : public DNSRecordContent
{
public:
  static void report(void);

// snip

DNSName d_next;
  std::set<uint16_t> d_set;
private:
};
```

C++(CentOS 7.6のGCC 4.8.5)においてstd::setはRed-Black treeを用いて実装しているため、
std::setの一つのエントリには、Colorとparent node、left, right nodeへのポインタが付属します。

```c++
  struct _Rb_tree_node_base
  {
    typedef _Rb_tree_node_base* _Base_ptr;
    typedef const _Rb_tree_node_base* _Const_Base_ptr;

    _Rb_tree_color      _M_color;
    _Base_ptr           _M_parent;
    _Base_ptr           _M_left;
    _Base_ptr           _M_right;
```

Type Bit Mapsの全てのbitを1にするとWire Formatでは8704bytesになりますが、PowerDNS Recursor上ではおよそ3MB程度になります。
そのため通常の署名済みゾーンのNSECレコードでは問題になりませんが、故意に多くのbitを1にしたNSECレコードをキャッシュした場合、
PowerDNS Recursor のメモリ使用量は非常に大きくなります。

```text
Wire Format
size of Type Bit Map = bit map count x ( Window Block + Bitmap Length + Bitmap ) bytes
                     = 256 x ( 1 + 1 + 32 ) bytes
                     = 8704 bytes

PowerDNS Recursor
size of Type Bit Map = ( node size of red-black tree ) * 65536 + Overhead bytes
                     = 40 x 65535 + Overhead bytes
                     = 2,621,400 + Overhead bytes
                     ~ 3MB
```

sample code to estimate memory usage: [set-uint16_t-x100.cpp](https://github.com/sischkg/huge_nsec_response/blob/master/set-uint16_t-x100.cpp)

#### PowerDNS Recursorでのキャッシュの制限

BINDやUnboundでは、リソースレコードのキャッシュの量をメモリ使用量で制限することが出来ますが、
PowerDNS Recursorではキャッシュ内のリソースレコードの数で制限します。PowerDNS Recursorで、
NSECのメモリ使用量(リソースレコードあたり3MB)に従ってエントリ数を制限すると、キャッシュを
多く持つことが出来なくなり、キャッシュヒット率が低下します。

#### PowerDNS 4.2.0での変更点

以下のPull Requestがマージされ、PowerDNS Recursor 4.2.0にて修正されています。

https://github.com/PowerDNS/pdns/pull/7345

PowerDNS 4.2.0ではBit Map Types内のTypeが200に達した場合、それを保存するコンテナを `std::set<uint16_t>` から `std::bitset` へ変更します。

##  Type Bit Mapsのテキスト表現について

リソースレコードのテキスト表現は、以下のような場面で利用されます。

* dig/drillなどの出力
* ゾーンファイル
* キャッシュのダンプ

NSECのテキスト表現の例

```text
example.com. IN NSEC  dns01.example.com. A NS SOA MX RRSIG NSEC DNSKEY
```

Type Bit MapsのWire Formatはサイズが小さくなるように定義されていますが、NSECレコードのテキスト表現ではサイズについて考慮されていません。
そこで先ほどPowerDNS Recursorの説明で利用したType Bit Mapsのすべてのbitを1にしたNSECレコードを、テキスト形式に変換すると約640KBの非常に大きなものになります。

```text
example.com. 3600 IN NSEC a.example.com. RESERVED0 A NS MD MF CNAME SOA MB MG MR NULL WKS PTR HINFO MINFO MX TXT RP AFSDB X25 ISDN RT NSAP NSAP-PTR SIG KEY PX GPOS AAAA LOC NXT EID NIMLOC SRV ATMA NAPTR KX CERT A6 DNAME SINK OPT APL DS SSHFP IPSECKEY RRSIG NSEC DNSKEY DHCID NSEC3 NSEC3PARAM TLSA SMIMEA TYPE54 HIP NINFO RKEY TALINK CDS CDNSKEY OPENPGPKEY CSYNC

...

TYPE65530 TYPE65531 TYPE65532 TYPE65533 TYPE65534 TYPE65535
```

[NSECレコード全体](https://raw.githubusercontent.com/sischkg/huge_nsec_response/master/nsec_response.txt)

### ゾーン転送で受信したゾーン

BINDでは、ゾーン転送で受信したゾーンのデータを次のファイル形式で保存します。

* 9.8.0未満: テキスト
* 9.8.0以上で”masterfile-format text;”: テキスト
* 9.8.0以上で”masterfile-format”未指定: raw

1000個のNSECレコードを持つゾーンを転送すると、スレーブ側では以下のサイズのファイルが作成されます。

* テキスト形式:　645 MB
* raw形式:      8.8 MB

## キャッシュのダンプ

フルリゾルバでは、以下のようにキャッシュの内容を出力することができます。

* BIND: `rndc dumpdb`を実行すると、namedは`named.conf`の`dump-file`にて指定されたパスに、ゾーンファイル形式のキャッシュデータを保存します。
* Unbound: `unbound-control dump_cache`を実行すると、`unbound`は`unbound-control`へゾーンファイル形式のキャッシュデータを送信し、`unbound-control`はそれを標準出力へ出力します。
* PowerDNS Recursor: `rec_control dump-cache /tmp/dumpdb.txt`を実行すると、`pdns_recursor`は`rec_control`の引数で指定したパスへ、ゾーンファイル形式のキャッシュデータを保存します。

1000個のNSECレコードをキャッシュさせた状態でそれをダンプすると次のサイズのファイルが作成されます。

* BIND:              約640MB
* Unbound:           約1.1MB
* PowerDNS Recursor: 約1.3GB

UnboundではType Bit Mapsをすべて出力しないため、ダンプファイルが小さくなります。

```text
1.example.com.  3215    IN      NSEC    a.1.example.com. A NS MD MF CNAME SOA MB .... TYPE152 TYPE1;rrset 10415 1 1 7 0
```

PowerDNS Recursorでは、

* キャッシュをダンプ中、pdns_recusorが応答しない時があります。
* Threadごとにキャッシュを持っているため、同じレコードが複数回出力されることでダンプファイルが大きくなります。

> rec_control(https://doc.powerdns.com/recursor/manpages/rec_control.1.html)
> Dumps the entire cache to FILENAME. This file should not exist already, PowerDNS will refuse to overwrite it. While dumping, the recursor will not answer questions.
> Typical PowerDNS Recursors run multiple threads, therefore you’ll see duplicate, different entries for the same domains. The negative cache is also dumped to the same file. The per-thread positive > and negative cache dumps are separated with an appropriate comment.

## まとめ

* PowerDNS Recursorは特殊なNSEC/NSEC3をキャッシュするときのメモリ使用量が大きくなります。
* エントリ数制限値が大きい場合は、メモリを使い切る可能性があります。
* Type Bit Mapsのテキスト表現は、非常に大きなサイズになる場合があります。
* そのためゾーン転送後のゾーンファイルや、キャッシュのダンプファイルのサイズも大きくなります。
* ただし、特殊なNSEC/NSEC3を作成して実際に実行する人が存在するかは不明です。

