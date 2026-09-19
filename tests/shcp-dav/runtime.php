<?php
// SPDX-License-Identifier: MIT
// Integration fixture inputs are disposable and contain pinned upstream Roundcube/CardDAV, never live data.
ob_start();
$fixture=$argv[1];
define('INSTALL_PATH',$fixture.'/roundcube/');
$_SERVER['REMOTE_ADDR']='127.0.0.1';
require INSTALL_PATH.'program/include/iniset.php';
function need(bool $ok,string $why):void {if(!$ok)throw new RuntimeException($why);}
$pdo=new PDO('sqlite:'.$fixture.'/roundcube.sqlite');
$pdo->exec(file_get_contents(INSTALL_PATH.'SQL/sqlite.initial.sql'));
$pdo->exec("INSERT INTO users(username,mail_host,created,language,preferences) VALUES('alice@example.test','localhost',datetime('now'),'en_US','a:0:{}')");
$rc=rcube::get_instance(rcube::INIT_WITH_DB|rcube::INIT_WITH_PLUGINS);
$rc->config->set('temp_dir',$fixture.'/roundcube/temp');
$rc->session_init();
$rc->user=new rcube_user(1);
$_SESSION=['language'=>'en_US','user_id'=>1,'username'=>'alice@example.test','password'=>$rc->encrypt('fake-scoped-grant')];
$original=$_SESSION['password'];
require INSTALL_PATH.'plugins/carddav/carddav.php';
$infra=\MStilkerich\RCMCardDAV\Config::inst();
$infra->db()->checkMigrations('',INSTALL_PATH.'plugins/carddav/dbmigrations/');
require dirname(__DIR__,2).'/plugins/shcp_dav/shcp_dav.php';
$binding=new \Shcp\Webmail\Dav\Bindings($pdo);$binding->install();
$rc->config->set('shcp_dav_origin','https://localhost:18980');
$rc->config->set('shcp_dav_cafile',$fixture.'/tls.crt');
$bridge=new shcp_dav($rc->plugins);$bridge->init();
\MStilkerich\RCMCardDAV\Config::$inst=null;
$plugin=new carddav($rc->plugins);
(new ReflectionMethod($plugin,'basicInit'))->invoke($plugin);
$infra=\MStilkerich\RCMCardDAV\Config::inst();
$mgr=new \MStilkerich\RCMCardDAV\Frontend\AddressbookManager();
$infra->admPrefs()->initPresets($mgr,$infra);
foreach($mgr->getAccountIds() as $acct) $mgr->discoverAddressbooks($mgr->getAccountConfig($acct),$infra->admPrefs()->getAddressbookTemplate($mgr,$acct));
$ids=$mgr->getAddressbookIds();need(count($ids)===1,'managed normal-login discovery failed');
$book=$mgr->getAddressbook($ids[0]);
$id=$book->insert(['name'=>'Isolated Contact','email'=>['contact@example.test']]);need((bool)$id,'managed insert failed');
need(str_contains(json_encode($book->get_record($id,true)),'Isolated Contact'),'managed cached read failed');
need($_SESSION['password']===$original,'normal session password changed');
echo "PASS product bridge normal-password discovery, secure account transport, insert and cached read\n";
// A new request must authorize remotely before exposing existing cached contacts.
touch($fixture.'/invalid-binding');
try {
 $deniedBridge=new shcp_dav($rc->plugins);
 $deniedBridge->prepareAccounts([]);
 $filtered=$deniedBridge->filterAccounts(['accounts'=>[(int)$mgr->getAccountIds()[0]=>$mgr->getAccountConfig($mgr->getAccountIds()[0])]]);
 need($filtered['accounts']===[],'invalid binding property exposed cached account');
 $denied=false;try{$deniedBridge->cacheAccess(['book_id'=>$ids[0]]);}catch(Throwable $e){$denied=true;}
 need($denied,'invalid binding property exposed cached contacts');
} finally {unlink($fixture.'/invalid-binding');}
echo "PASS invalid uncached principal binding hides existing cached contacts\n";
// Same-email reuse: request B replaces mapping while request A retains its Addressbook object.
$exportSnapshot=$book->list_records();
$oldAccount=(int)$mgr->getAccountIds()[0];
$newAccount=$binding->activate(1,'shcp',str_repeat('b',32),'alice@example.test','https://localhost:18980');
need($newAccount!==$oldAccount,'account ID reused');
foreach(['get_record'=>fn()=>$book->get_record($id,true),'search'=>fn()=>$book->search('name','Isolated'),'list_records'=>fn()=>$book->list_records(),'get_result'=>fn()=>$book->get_result(),'count'=>fn()=>$book->count(),'resync'=>fn()=>$book->resync(),'export'=>fn()=>$plugin->exportVCards(['result'=>$exportSnapshot])] as $name=>$call) {
 $denied=false;try{$call();}catch(Throwable $e){$denied=true;}need($denied,'retired cache bypass: '.$name);
}
need($mgr->getAddressbookIds()===[],'stale manager exposed replacement generation');
echo "PASS held Addressbook denies retired read/search/list/count/result/sync and stale manager cannot see replacement\n";
// Secure Account cannot send even an authenticated request to another origin/path.
$transport=new \Shcp\Webmail\Dav\Transport('https://localhost:18980',$fixture.'/tls.crt');
$account=new \Shcp\Webmail\Dav\Account('https://localhost:18980/dav/',$transport,['alice@example.test','fake-scoped-grant'],static fn()=>null);
foreach(['https://attacker.invalid/dav/x','https://localhost:18980/api/internal/webmail/dav/exchange','https://localhost:18980/dav/%2e%2e/x'] as $url) {
 $denied=false;try{$account->getClient('https://localhost:18980/')->getResource($url);}catch(Throwable $e){$denied=true;}need($denied,'account allowed hostile target');
}
echo "PASS actual CardDAV Account adapter refuses hostile hrefs before sending credentials\n";
echo "SHCP_DAV_RUNTIME_OK\n";
ob_end_flush();