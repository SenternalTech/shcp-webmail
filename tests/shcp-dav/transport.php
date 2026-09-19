<?php
// SPDX-License-Identifier: MIT
require dirname(__DIR__,2).'/plugins/shcp_dav/lib/Transport.php';
use Shcp\Webmail\Dav\Transport;
$fixture=$argv[1];
function expectFailure(callable $call,string $why):void {$failed=false;try{$call();}catch(Throwable $e){$failed=true;}if(!$failed)throw new RuntimeException($why);}
$t=new Transport('https://fixture.shcp.invalid:18980',$fixture.'/tls.crt');
$r=$t->request('GET',$t->origin().'/dav/host');
if((json_decode($r['body'],true)['host']??null)!=='fixture.shcp.invalid:18980')throw new RuntimeException('Canonical Host not preserved');
expectFailure(fn()=>(new Transport('https://wrong.shcp.invalid:18980',$fixture.'/tls.crt'))->request('GET','https://wrong.shcp.invalid:18980/dav/host'),'Wrong certificate name accepted');
expectFailure(fn()=>(new Transport('https://fixture.shcp.invalid:18980'))->request('GET',$t->origin().'/dav/host'),'Untrusted certificate accepted');
@unlink($fixture.'/redirect-followed');
expectFailure(fn()=>$t->request('GET',$t->origin().'/dav/redirect',[], '',['alice@example.test','test-only-secret']),'Redirect accepted');
if(is_file($fixture.'/redirect-followed'))throw new RuntimeException('Redirect followed');
$t->request('GET',$t->origin().'/dav/host'); // Fixture still alive after each rejected handshake.
echo "SHCP_DAV_TRANSPORT_OK canonical loopback Host, verified peer name and trust, redirects denied\n";