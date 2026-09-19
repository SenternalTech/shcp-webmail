<?php
// SPDX-License-Identifier: MIT
// Usage: php tests/shcp-dav/bindings.php /path/to/extracted/carddav
require dirname(__DIR__,2).'/plugins/shcp_dav/lib/Bindings.php';
require dirname(__DIR__,2).'/plugins/shcp_dav/lib/Transport.php';
use Shcp\Webmail\Dav\Bindings;
function check(bool $ok,string $message):void {if(!$ok)throw new RuntimeException($message);}
function denied(callable $fn,string $message):void {$failed=false;try{$fn();}catch(Throwable $e){$failed=true;}check($failed,$message);}
$dir=sys_get_temp_dir().'/shcp-dav-test-'.bin2hex(random_bytes(8));mkdir($dir,0700);
$db=new PDO('sqlite:'.$dir.'/cache.db');$db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
$db->exec('PRAGMA journal_mode=WAL');$db->exec('CREATE TABLE users(user_id INTEGER PRIMARY KEY)');$db->exec('INSERT INTO users VALUES(1)');
$db->exec(str_replace('TABLE_PREFIX','',file_get_contents($argv[1].'/dbmigrations/INIT-currentschema/sqlite3.sql')));
$store=new Bindings($db);$store->install();$store->install();
$first=str_repeat('a',32);$second=str_repeat('b',32);
$a=$store->activate(1,'shcp',$first,'alice@example.test','https://panel.example.test');
check($a===$store->activate(1,'shcp',$first,'alice@example.test','https://panel.example.test'),'rerun reallocated active account');
$db->exec("INSERT INTO carddav_addressbooks(id,name,url,account_id) VALUES(1,'Old','https://panel.example.test/dav/old',$a)");
$db->exec("INSERT INTO carddav_contacts(id,abook_id,name,vcard,etag,uri,cuid) VALUES(1,1,'Old Person','old-card','old-etag','old.vcf','old-uid')");
$db->exec("INSERT INTO carddav_groups(id,abook_id,name) VALUES(1,1,'Old group')");
// Request A captured first-generation account/book; request B now rebinds the same Roundcube user.
$b=$store->activate(1,'shcp',$second,'alice@example.test','https://panel.example.test');
check($a!==$b,'generation reused account');
check(!$store->current(1,$a,$first),'old request still authorized');
check($store->current(1,$b,$second),'new generation not active');
denied(fn()=>$store->activate(1,'shcp',$first,'alice@example.test','https://panel.example.test'),'old request resurrected tombstone');
denied(fn()=>$db->exec("UPDATE carddav_contacts SET name='late A' WHERE id=1"),'old in-flight sync wrote after rebind');
denied(fn()=>$db->exec("DELETE FROM carddav_accounts WHERE id=$a"),'account tombstone deleted');
$db->exec("INSERT INTO carddav_addressbooks(id,name,url,account_id) VALUES(2,'New','https://panel.example.test/dav/new',$b)");
denied(fn()=>$db->exec('UPDATE carddav_contacts SET abook_id=2 WHERE id=1'),'old contact moved into replacement generation');
denied(fn()=>$db->exec("UPDATE carddav_accounts SET presetname=NULL WHERE id=$b"),'managed identity escaped mapping with NULL');
check($db->query('SELECT name FROM carddav_contacts WHERE id=1')->fetchColumn()==='Old Person','old card changed');
check((int)$db->query('SELECT COUNT(*) FROM carddav_contacts WHERE abook_id=2')->fetchColumn()===0,'replacement saw old contacts');
$db->exec("INSERT INTO carddav_contacts(id,abook_id,name,vcard,etag,uri,cuid) VALUES(2,2,'New Person','new-card','new-etag','new.vcf','new-uid')");
denied(fn()=>$db->exec("INSERT INTO carddav_group_user(group_id,contact_id) VALUES(1,2)"),'new contact linked into retired group');
// Concurrent order: A takes a WAL read snapshot, B replaces generation, A cannot upgrade stale snapshot into writer.
$other=new PDO('sqlite:'.$dir.'/cache.db');$other->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);$otherStore=new Bindings($other);
$db->beginTransaction();$db->query('SELECT * FROM shcp_dav_bindings')->fetchAll();
$c=$otherStore->activate(1,'shcp',str_repeat('c',32),'alice@example.test','https://panel.example.test');
denied(fn()=>$db->exec("UPDATE carddav_addressbooks SET name='late snapshot' WHERE id=2"),'stale transaction wrote');$db->rollBack();
// Opposite order: existing writer holds fence stable; rebind cannot commit until that writer completes.
$db->beginTransaction();$db->exec("UPDATE carddav_accounts SET accountname='C' WHERE id=$c");$other->exec('PRAGMA busy_timeout=0');
denied(fn()=>$otherStore->activate(1,'shcp',str_repeat('d',32),'alice@example.test','https://panel.example.test'),'rebind crossed active writer');$db->commit();
$d=$otherStore->activate(1,'shcp',str_repeat('d',32),'alice@example.test','https://panel.example.test');check($d!==$c,'writer order reused id');
// Transport validation rejects malformed/hostile hrefs before any network attempt.
$t=new Shcp\Webmail\Dav\Transport('https://panel.example.test');
$t->assertDavUrl('https://panel.example.test/dav/addressbooks/alice%40example.test/default/');
foreach(['http://panel.example.test/dav/','https://evil.example.test/dav/','https://panel.example.test:444/dav/','https://user@panel.example.test/dav/','https://panel.example.test/dav/../api/','https://panel.example.test/dav/%2e%2e/','https://panel.example.test/dav/%252e/','https://panel.example.test/dav/%0a','https://panel.example.test/dav/a#x','https://panel.example.test/api/'] as $url) denied(fn()=>$t->assertDavUrl($url),'hostile URL accepted');
echo "PASS bindings idempotency, retained identities, stale read/write fences in both race orders, hostile URI policy\n";// Upstream users cascade must not delete the map before its identity guards can inspect it.
$before=$db->query('SELECT * FROM shcp_dav_bindings ORDER BY account_id')->fetchAll(PDO::FETCH_ASSOC);
$denial='';try{$db->exec('DELETE FROM users WHERE user_id=1');}catch(PDOException $e){$denial=$e->getMessage();}
check(str_contains($denial,'Managed DAV cache cleanup required'),'user cascade erased managed identities');
check($before===$db->query('SELECT * FROM shcp_dav_bindings ORDER BY account_id')->fetchAll(PDO::FETCH_ASSOC),'user deletion changed retained mapping');
check((int)$db->query('SELECT COUNT(*) FROM carddav_contacts')->fetchColumn()===2,'user cascade erased cached rows');
$db->exec('INSERT INTO users VALUES(2)');
$db->exec("INSERT INTO carddav_accounts(id,accountname,username,password,discovery_url,user_id) VALUES(50,'Custom','other@example.test','%p','https://custom.example.test/',2)");
$db->exec("INSERT INTO carddav_addressbooks(id,name,url,account_id) VALUES(50,'Custom','https://custom.example.test/book',50)");
$db->exec('DELETE FROM users WHERE user_id=2');
check((int)$db->query('SELECT COUNT(*) FROM carddav_addressbooks WHERE id=50')->fetchColumn()===0,'ordinary cache cascade blocked');
check((int)$db->query('SELECT COUNT(*) FROM users WHERE user_id=2')->fetchColumn()===0,'ordinary user deletion blocked');
echo "PASS actual upstream user cascade preserves managed identities; ordinary user deletion remains available\n";