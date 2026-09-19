<?php
// SPDX-License-Identifier: MIT
namespace Shcp\Webmail\Dav;

/** Persistent generation tombstones and atomic SQLite cache-write fences. */
final class Bindings
{
    private string $p;
    public function __construct(private \PDO $db,string $prefix='')
    {
        if (!preg_match('/\A[a-zA-Z0-9_]*\z/',$prefix)) throw new \RuntimeException('Invalid database prefix');
        $this->p=$prefix;
        $db->setAttribute(\PDO::ATTR_ERRMODE,\PDO::ERRMODE_EXCEPTION);
        $db->exec('PRAGMA foreign_keys=ON'); $db->exec('PRAGMA busy_timeout=5000');
    }
    public function install(): void
    {
        $p=$this->p;
        $this->db->beginTransaction();
        try {
            $this->db->exec("CREATE TABLE IF NOT EXISTS {$p}shcp_dav_schema(version INTEGER PRIMARY KEY CHECK(version=1))");
            $this->db->exec("CREATE TABLE IF NOT EXISTS {$p}shcp_dav_bindings(user_id INTEGER NOT NULL REFERENCES {$p}users(user_id) ON DELETE CASCADE,preset TEXT NOT NULL,binding_id TEXT NOT NULL,account_id INTEGER UNIQUE,state TEXT NOT NULL CHECK(state IN ('provisioning','active','retired')),verified_at INTEGER NOT NULL,PRIMARY KEY(user_id,preset,binding_id))");
            $this->db->exec("CREATE UNIQUE INDEX IF NOT EXISTS {$p}shcp_dav_one_active ON {$p}shcp_dav_bindings(user_id,preset) WHERE state='active'");
            // SQLite may cascade the binding FK before accounts, making account triggers blind.
            // Refuse that administrative operation until quiesced, non-reusing cleanup is supported.
            $this->db->exec("CREATE TRIGGER IF NOT EXISTS {$p}shcp_dav_user_delete BEFORE DELETE ON {$p}users WHEN EXISTS(SELECT 1 FROM {$p}shcp_dav_bindings WHERE user_id=OLD.user_id) BEGIN SELECT RAISE(ABORT,'Managed DAV cache cleanup required; do not remove identity guards'); END");
            // The upstream INTEGER PRIMARY KEY is reusable after deletion. Preserve mapped account and book rows
            // as tombstones; all later generations allocate different rows. No FK can silently retarget a mapping.
            foreach (['UPDATE','DELETE'] as $op) {
                $this->db->exec("CREATE TRIGGER IF NOT EXISTS {$p}shcp_dav_account_".strtolower($op)." BEFORE $op ON {$p}carddav_accounts WHEN EXISTS(SELECT 1 FROM {$p}shcp_dav_bindings b WHERE b.account_id=OLD.id".($op==='UPDATE' ? " AND (b.state!='active' OR NEW.id IS NOT OLD.id OR NEW.user_id IS NOT OLD.user_id OR NEW.presetname IS NOT OLD.presetname)" : '').") BEGIN SELECT RAISE(ABORT,'Managed DAV account identity is immutable'); END");
            }
            foreach (['INSERT','UPDATE','DELETE'] as $op) {
                foreach (['addressbooks','contacts','groups','xsubtypes','group_user'] as $table) {
                    $ref=$op==='DELETE'?'OLD':'NEW';
                    $account=match($table) {
                        'addressbooks'=>"$ref.account_id",
                        'group_user'=>"(SELECT a.account_id FROM {$p}carddav_addressbooks a JOIN {$p}carddav_contacts c ON c.abook_id=a.id WHERE c.id=$ref.contact_id)",
                        default=>"(SELECT account_id FROM {$p}carddav_addressbooks WHERE id=$ref.abook_id)",
                    };
                    $condition="EXISTS(SELECT 1 FROM {$p}shcp_dav_bindings b WHERE b.account_id=$account AND b.state!='active')";
                    if ($table === 'group_user') {
                        $condition .= " OR EXISTS(SELECT 1 FROM {$p}shcp_dav_bindings b JOIN {$p}carddav_addressbooks a ON a.account_id=b.account_id JOIN {$p}carddav_groups g ON g.abook_id=a.id WHERE g.id=$ref.group_id AND b.state!='active')";
                        if ($op !== 'DELETE') $condition .= " OR (SELECT abook_id FROM {$p}carddav_groups WHERE id=$ref.group_id) IS NOT (SELECT abook_id FROM {$p}carddav_contacts WHERE id=$ref.contact_id)";
                    }
                    if ($op === 'UPDATE') $condition .= ' OR ' . str_replace('NEW.', 'OLD.', $condition);
                    $this->db->exec("CREATE TRIGGER IF NOT EXISTS {$p}shcp_dav_{$table}_".strtolower($op)." BEFORE $op ON {$p}carddav_$table WHEN $condition BEGIN SELECT RAISE(ABORT,'Retired DAV cache generation'); END");
                }
            }
            // Retained books cannot be moved to another account, even while their former generation is active.
            $this->db->exec("CREATE TRIGGER IF NOT EXISTS {$p}shcp_dav_book_identity BEFORE UPDATE ON {$p}carddav_addressbooks WHEN (NEW.id!=OLD.id OR NEW.account_id!=OLD.account_id) AND EXISTS(SELECT 1 FROM {$p}shcp_dav_bindings WHERE account_id=OLD.account_id) BEGIN SELECT RAISE(ABORT,'Managed DAV book identity is immutable'); END");
            $this->db->exec("INSERT OR IGNORE INTO {$p}shcp_dav_schema VALUES(1)");
            $this->db->commit();
        } catch (\Throwable $e) {$this->db->rollBack();throw $e;}
    }
    /** Allocate once per generation under a writer lock. Never resurrect a retired generation. */
    public function activate(int $user,string $preset,string $binding,string $username,string $origin): int
    {
        $p=$this->p;
        if ((int)$this->db->query("SELECT version FROM {$p}shcp_dav_schema")->fetchColumn()!==1) throw new \RuntimeException('DAV cache schema unavailable');
        $this->db->exec('BEGIN IMMEDIATE');
        try {
            $q=$this->db->prepare("SELECT * FROM {$p}shcp_dav_bindings WHERE user_id=? AND preset=? AND binding_id=?");$q->execute([$user,$preset,$binding]);$row=$q->fetch(\PDO::FETCH_ASSOC);
            if ($row && $row['state']==='retired') throw new \RuntimeException('DAV generation retired');
            if ($row && $row['state']==='active') {$this->db->exec('COMMIT');return (int)$row['account_id'];}
            $q=$this->db->prepare("UPDATE {$p}shcp_dav_bindings SET state='retired' WHERE user_id=? AND preset=? AND state!='retired'");$q->execute([$user,$preset]);
            // Keep account tombstones instead of deleting them: INTEGER ids remain monotonic by construction.
            $id=(int)$this->db->query("SELECT COALESCE(MAX(id),0)+1 FROM {$p}carddav_accounts")->fetchColumn();
            $q=$this->db->prepare("INSERT INTO {$p}carddav_accounts(id,accountname,username,password,discovery_url,user_id,presetname) VALUES(?,?,?,?,?,?,?)");
            $q->execute([$id,'SHCP Contacts',$username,'%p',$origin.'/dav/',$user,$preset.':'.$binding]);
            $q=$this->db->prepare("INSERT INTO {$p}shcp_dav_bindings(user_id,preset,binding_id,account_id,state,verified_at) VALUES(?,?,?,?, 'active',?)");$q->execute([$user,$preset,$binding,$id,time()]);
            $this->db->exec('COMMIT'); return $id;
        } catch (\Throwable $e) {$this->db->exec('ROLLBACK');throw $e;}
    }
    public function current(int $user,int $account,string $binding): bool
    {
        $q=$this->db->prepare("SELECT 1 FROM {$this->p}shcp_dav_bindings WHERE user_id=? AND account_id=? AND binding_id=? AND state='active'");$q->execute([$user,$account,$binding]);return (bool)$q->fetchColumn();
    }
    public function accountForBook(string $book): ?int
    {
        $q=$this->db->prepare("SELECT account_id FROM {$this->p}carddav_addressbooks WHERE id=?");$q->execute([$book]);$id=$q->fetchColumn();return $id===false?null:(int)$id;
    }
    public function managed(int $account): bool
    {
        $q=$this->db->prepare("SELECT 1 FROM {$this->p}shcp_dav_bindings WHERE account_id=?");$q->execute([$account]);return (bool)$q->fetchColumn();
    }
}