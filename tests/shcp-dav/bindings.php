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
// A deployment that never installed the managed cache has nothing to purge and no guard to satisfy;
// the delete hook must not turn that into a refusal to remove any user at all.
$bare=new PDO('sqlite:'.$dir.'/bare.db');$bare->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
$bare->exec('CREATE TABLE users(user_id INTEGER PRIMARY KEY)');$bare->exec('INSERT INTO users VALUES(1)');
$bare->exec(str_replace('TABLE_PREFIX','',file_get_contents($argv[1].'/dbmigrations/INIT-currentschema/sqlite3.sql')));
check((new Bindings($bare))->purge(1)===0,'purge refused a deployment with no managed cache');
$bare->exec('DELETE FROM users WHERE user_id=1');
check((int)$bare->query('SELECT COUNT(*) FROM users')->fetchColumn()===0,'unmanaged deployment lost ordinary user deletion');
echo "PASS purge is a no-op where the managed cache was never installed\n";
// Premise, on an untouched upstream schema: the rowid aliases really are handed out again, so a
// cleanup that only deletes rows would let a later owner inherit a purged book.
$plain=new PDO('sqlite:'.$dir.'/plain.db');$plain->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
$plain->exec('CREATE TABLE users(user_id INTEGER PRIMARY KEY)');$plain->exec('INSERT INTO users VALUES(1)');
$plain->exec(str_replace('TABLE_PREFIX','',file_get_contents($argv[1].'/dbmigrations/INIT-currentschema/sqlite3.sql')));
$plain->exec("INSERT INTO carddav_accounts(accountname,username,password,discovery_url,user_id) VALUES('A','a@example.test','%p','https://panel.example.test/',1)");
$plainAccount=(int)$plain->lastInsertId();
$plain->exec("INSERT INTO carddav_addressbooks(name,url,account_id) VALUES('B','https://panel.example.test/dav/b',$plainAccount)");
$plainBook=(int)$plain->lastInsertId();
$plain->exec("DELETE FROM carddav_addressbooks WHERE id=$plainBook");
$plain->exec("INSERT INTO carddav_addressbooks(name,url,account_id) VALUES('B2','https://panel.example.test/dav/b2',$plainAccount)");
check((int)$plain->lastInsertId()===$plainBook,'premise refuted: upstream book identifiers were already non-reusable');
// Upgrading an existing deployment converts both identifier spaces in place, with its cache intact.
$plain->exec("INSERT INTO carddav_contacts(abook_id,name,vcard,etag,uri,cuid) VALUES((SELECT MAX(id) FROM carddav_addressbooks),'Kept','kept-card','kept-etag','kept.vcf','kept-uid')");
$keptBook=(int)$plain->query('SELECT MAX(id) FROM carddav_addressbooks')->fetchColumn();
(new Bindings($plain))->install();
check((int)$plain->query('SELECT COUNT(*) FROM carddav_accounts')->fetchColumn()===1,'upgrade lost accounts');
check((int)$plain->query('SELECT account_id FROM carddav_addressbooks')->fetchColumn()===$plainAccount,'upgrade lost book ownership');
check($plain->query('SELECT name FROM carddav_contacts')->fetchColumn()==='Kept','upgrade lost cached contacts');
check($plain->query('PRAGMA foreign_key_check')->fetch()===false,'upgrade left dangling references');
$plain->exec("DELETE FROM carddav_addressbooks WHERE id=$keptBook");
$plain->exec("INSERT INTO carddav_addressbooks(name,url,account_id) VALUES('B3','https://panel.example.test/dav/b3',$plainAccount)");
check((int)$plain->lastInsertId()>$keptBook,'upgraded schema still reused a deleted book identifier');
echo "PASS upstream identifier reuse reproduced, then converted in place with the existing cache intact\n";
// Managed-cache cleanup: the live generation has real cached data to remove.
$db->exec("INSERT INTO carddav_addressbooks(name,url,account_id) VALUES('Live','https://panel.example.test/dav/live',$d)");
$liveBook=(int)$db->lastInsertId();
$db->exec("INSERT INTO carddav_contacts(abook_id,name,vcard,etag,uri,cuid) VALUES($liveBook,'Live Person','live-card','live-etag','live.vcf','live-uid')");
$used=[$a,$b,$c,$d];$usedBooks=[1,2,$liveBook];
check($store->purge(1)===count($used),'purge did not remove every mapped account');
check((int)$db->query('SELECT COUNT(*) FROM carddav_accounts WHERE id IN ('.implode(',',$used).')')->fetchColumn()===0,'purge left mapped accounts');
check((int)$db->query('SELECT COUNT(*) FROM carddav_contacts')->fetchColumn()===0,'purge left cached contacts');
check((int)$db->query('SELECT COUNT(*) FROM carddav_addressbooks')->fetchColumn()===0,'purge left cached books');
check((int)$db->query('SELECT COUNT(*) FROM shcp_dav_bindings WHERE user_id=1')->fetchColumn()===0,'purge left mapping rows');
check((int)$db->query('SELECT COUNT(*) FROM shcp_dav_cleanup')->fetchColumn()===0,'purge left its journal open');
$db->exec('DELETE FROM users WHERE user_id=1');
check((int)$db->query('SELECT COUNT(*) FROM users WHERE user_id=1')->fetchColumn()===0,'purged user still undeletable');
echo "PASS purge removes the requested user's managed cache and restores ordinary deletion\n";
// Reuse case: a later owner must not be handed anything the purged generation held, and the stale
// request that outlived the purge must have nowhere to land.
$db->exec('INSERT INTO users VALUES(3)');
$next=$store->activate(3,'shcp',str_repeat('e',32),'bob@example.test','https://panel.example.test');
check(!in_array($next,$used,true),'later generation inherited a purged account identifier');
$db->exec("INSERT INTO carddav_addressbooks(name,url,account_id) VALUES('Next','https://panel.example.test/dav/next',$next)");
$nextBook=(int)$db->lastInsertId();
check(!in_array($nextBook,$usedBooks,true),'later generation inherited a purged book identifier');
check($store->accountForBook((string)$liveBook)===null,'purged book resolved to a later owner');
denied(fn()=>$db->exec("INSERT INTO carddav_contacts(abook_id,name,vcard,etag,uri,cuid) VALUES($liveBook,'Stale','stale-card','stale-etag','stale.vcf','stale-uid')"),'stale request wrote into a reissued book');
denied(fn()=>$db->exec("INSERT INTO carddav_accounts(id,accountname,username,password,discovery_url,user_id) VALUES($d,'Reused','bob@example.test','%p','https://panel.example.test/',3)"),'purged account identifier reissued explicitly');
denied(fn()=>$db->exec("INSERT INTO carddav_addressbooks(id,name,url,account_id) VALUES($liveBook,'Reused','https://panel.example.test/dav/reused',$next)"),'purged book identifier reissued explicitly');
echo "PASS purged account and book identifiers cannot be inherited, claimed, or written to by a stale request\n";
// Interrupted cleanup: purge()'s own first commit lands, then its second transaction dies. The
// fence must already be on disk, stay closed, and the re-run must finish it.
$db->exec('INSERT INTO users VALUES(4)');
$f=$store->activate(4,'shcp',str_repeat('f',32),'carol@example.test','https://panel.example.test');
$db->exec("INSERT INTO carddav_addressbooks(name,url,account_id) VALUES('Carol','https://panel.example.test/dav/carol',$f)");
$fBook=(int)$db->lastInsertId();
$db->exec("INSERT INTO carddav_contacts(abook_id,name,vcard,etag,uri,cuid) VALUES($fBook,'Carol Person','carol-card','carol-etag','carol.vcf','carol-uid')");
$db->exec("CREATE TRIGGER test_interrupt_purge BEFORE DELETE ON carddav_accounts WHEN OLD.id=$f BEGIN SELECT RAISE(ABORT,'staged interruption'); END");
denied(fn()=>$store->purge(4),'staged interruption did not stop the purge');
$db->exec('DROP TRIGGER test_interrupt_purge');
check(!$store->current(4,$f,str_repeat('f',32)),'interrupted cleanup left the generation authorized');
check((int)$db->query('SELECT COUNT(*) FROM shcp_dav_cleanup WHERE user_id=4')->fetchColumn()===1,'interrupted cleanup left no journal to resume from');
denied(fn()=>$db->exec("UPDATE carddav_contacts SET name='late' WHERE abook_id=$fBook"),'interrupted cleanup allowed a cache write');
denied(fn()=>$store->activate(4,'shcp',str_repeat('g',32),'carol@example.test','https://panel.example.test'),'interrupted cleanup allowed a replacement generation');
denied(fn()=>$db->exec('DELETE FROM users WHERE user_id=4'),'interrupted cleanup released the user deletion guard');
check($store->purge(4)===1,'resumed purge did not finish');
$db->exec('DELETE FROM users WHERE user_id=4');
check((int)$db->query('SELECT COUNT(*) FROM users WHERE user_id=4')->fetchColumn()===0,'resumed purge left the user undeletable');
$db->exec('INSERT INTO users VALUES(5)');
$h=$store->activate(5,'shcp',str_repeat('h',32),'dave@example.test','https://panel.example.test');
check($h!==$f,'resumed purge released its account identifier');
$db->exec("INSERT INTO carddav_addressbooks(name,url,account_id) VALUES('Dave','https://panel.example.test/dav/dave',$h)");
check((int)$db->lastInsertId()!==$fBook,'resumed purge released its book identifier');
echo "PASS interrupted cleanup stays fenced, resumes, and still retires both identifiers\n";
