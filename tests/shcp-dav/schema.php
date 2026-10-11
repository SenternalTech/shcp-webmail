<?php
// SPDX-License-Identifier: MIT
require dirname(__DIR__,2).'/plugins/shcp_dav/lib/Bindings.php';

function check(bool $ok,string $message):void {if (!$ok) throw new RuntimeException($message);}

function database():PDO
{
    $db=new PDO('sqlite::memory:');
    $db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
    $db->exec('CREATE TABLE users(user_id INTEGER PRIMARY KEY)');
    $db->exec('CREATE TABLE identities(id INTEGER PRIMARY KEY,user_id INTEGER REFERENCES users(user_id))');
    $db->exec('CREATE TABLE carddav_accounts(id integer NOT NULL PRIMARY KEY,user_id INTEGER REFERENCES users(user_id))');
    $db->exec('CREATE TABLE carddav_addressbooks(id integer NOT NULL PRIMARY KEY,account_id INTEGER REFERENCES carddav_accounts(id))');
    $db->exec('CREATE TABLE carddav_contacts(id INTEGER PRIMARY KEY,abook_id INTEGER REFERENCES carddav_addressbooks(id))');
    $db->exec('CREATE TABLE carddav_groups(id INTEGER PRIMARY KEY,abook_id INTEGER REFERENCES carddav_addressbooks(id))');
    $db->exec('CREATE TABLE carddav_xsubtypes(id INTEGER PRIMARY KEY,abook_id INTEGER REFERENCES carddav_addressbooks(id))');
    $db->exec('CREATE TABLE carddav_group_user(group_id INTEGER REFERENCES carddav_groups(id),contact_id INTEGER REFERENCES carddav_contacts(id))');
    return $db;
}

$db=database();
$db->exec('INSERT INTO identities VALUES(7,99)');
(new Shcp\Webmail\Dav\Bindings($db))->install();
(new Shcp\Webmail\Dav\Bindings($db))->install();
check((int)$db->query('SELECT version FROM shcp_dav_schema')->fetchColumn()===2,'unrelated orphan blocked migration');
check(str_contains((string)$db->query("SELECT sql FROM sqlite_master WHERE name='carddav_accounts'")->fetchColumn(),'AUTOINCREMENT'),'account allocator was not rebuilt');
check(str_contains((string)$db->query("SELECT sql FROM sqlite_master WHERE name='carddav_addressbooks'")->fetchColumn(),'AUTOINCREMENT'),'book allocator was not rebuilt');
check($db->query('PRAGMA foreign_key_check')->fetch()[0]==='identities','test lost its unrelated orphan');
echo "PASS unrelated Roundcube orphan does not block DAV migration\n";

$db=database();
$db->exec('INSERT INTO carddav_addressbooks VALUES(11,99)');
$reason='';
try {(new Shcp\Webmail\Dav\Bindings($db))->install();} catch (RuntimeException $e) {$reason=$e->getMessage();}
check(str_contains($reason,'carddav_addressbooks') && str_contains($reason,'11'),'DAV orphan failure did not name its table and rowid');
check(!str_contains((string)$db->query("SELECT sql FROM sqlite_master WHERE name='carddav_accounts'")->fetchColumn(),'AUTOINCREMENT'),'failed rebuild was not rolled back');
echo "PASS DAV orphan blocks migration with table and rowid\n";

$db=database();
$db->exec('CREATE TABLE custom_dav_link(id INTEGER PRIMARY KEY,account_id INTEGER REFERENCES carddav_accounts(id))');
$db->exec('INSERT INTO custom_dav_link VALUES(12,99)');
$reason='';
try {(new Shcp\Webmail\Dav\Bindings($db))->install();} catch (RuntimeException $e) {$reason=$e->getMessage();}
check(str_contains($reason,'custom_dav_link') && str_contains($reason,'12'),'referencing table orphan escaped the DAV check');
echo "PASS tables referencing DAV allocators are checked\n";

$cmd=escapeshellarg(PHP_BINARY).' '.escapeshellarg(dirname(__DIR__,2).'/plugins/shcp_dav/schema.php');
$process=proc_open($cmd,[1=>['pipe','w'],2=>['pipe','w']],$pipes);
check(is_resource($process),'schema entry point did not start');
$stdout=stream_get_contents($pipes[1]);$stderr=stream_get_contents($pipes[2]);
fclose($pipes[1]);fclose($pipes[2]);
check(proc_close($process)===1 && $stdout==='','schema entry point did not fail as expected');
check((bool)preg_match('/SHCP DAV schema migration failed: [\\w\\\\]+: .+/', $stderr),'schema entry point hid the exception class or message');
echo "PASS schema failure prints exception class and message\n";
