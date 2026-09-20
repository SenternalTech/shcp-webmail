<?php
// SPDX-License-Identifier: MIT
namespace Shcp\Webmail\Dav;

/** Persistent generation tombstones, non-reusing identifier allocation, and atomic SQLite cache-write fences. */
final class Bindings
{
    private const SCOPES=['carddav_accounts'=>'account','carddav_addressbooks'=>'addressbook'];
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
        // The ledger and the cleanup journal deliberately carry no foreign key to users: they outlive
        // the row being removed, which is what makes an interrupted cleanup resumable.
        $this->db->exec("CREATE TABLE IF NOT EXISTS {$p}shcp_dav_idfloor(scope TEXT PRIMARY KEY,high INTEGER NOT NULL)");
        $this->db->exec("CREATE TABLE IF NOT EXISTS {$p}shcp_dav_cleanup(user_id INTEGER PRIMARY KEY,started_at INTEGER NOT NULL)");
        $this->allocator();
        $this->db->beginTransaction();
        try {
            $schema=$this->db->query("SELECT sql FROM sqlite_master WHERE type='table' AND name='{$p}shcp_dav_schema'")->fetchColumn();
            if (is_string($schema) && !str_contains($schema,'version IN (1,2)')) $this->db->exec("DROP TABLE {$p}shcp_dav_schema");
            $this->db->exec("CREATE TABLE IF NOT EXISTS {$p}shcp_dav_schema(version INTEGER PRIMARY KEY CHECK(version IN (1,2)))");
            $this->db->exec("CREATE TABLE IF NOT EXISTS {$p}shcp_dav_bindings(user_id INTEGER NOT NULL REFERENCES {$p}users(user_id) ON DELETE CASCADE,preset TEXT NOT NULL,binding_id TEXT NOT NULL,account_id INTEGER UNIQUE,state TEXT NOT NULL CHECK(state IN ('provisioning','active','retired')),verified_at INTEGER NOT NULL,PRIMARY KEY(user_id,preset,binding_id))");
            $this->db->exec("CREATE UNIQUE INDEX IF NOT EXISTS {$p}shcp_dav_one_active ON {$p}shcp_dav_bindings(user_id,preset) WHERE state='active'");
            // Removal of a retired generation's rows is permitted only while that user's cleanup is
            // journaled. The journal never unlocks an active generation and never unlocks a write.
            $open=" AND NOT EXISTS(SELECT 1 FROM {$p}shcp_dav_cleanup c WHERE c.user_id=b.user_id)";
            $triggers=['user_delete','account_update','account_delete','account_floor','book_floor','book_identity'];
            foreach (['insert','update','delete'] as $op) foreach (['addressbooks','contacts','groups','xsubtypes','group_user'] as $table) $triggers[]=$table.'_'.$op;
            foreach ($triggers as $trigger) $this->db->exec("DROP TRIGGER IF EXISTS {$p}shcp_dav_{$trigger}");
            // SQLite may cascade the binding FK before accounts, making account triggers blind.
            // Refuse that administrative operation until the managed cache has been purged.
            $this->db->exec("CREATE TRIGGER {$p}shcp_dav_user_delete BEFORE DELETE ON {$p}users WHEN EXISTS(SELECT 1 FROM {$p}shcp_dav_bindings WHERE user_id=OLD.user_id) BEGIN SELECT RAISE(ABORT,'Managed DAV cache cleanup required; do not remove identity guards'); END");
            // Both upstream identifier spaces are AUTOINCREMENT (see allocator()), so a generation that
            // has been purged cannot be walked back into. These two guards make that loud instead of
            // silent if anything ever rebuilds a table and drops its sequence.
            foreach (self::SCOPES as $table=>$scope) {
                $trigger=$scope==='account'?'account_floor':'book_floor';
                $this->db->exec("CREATE TRIGGER {$p}shcp_dav_{$trigger} AFTER INSERT ON {$p}{$table} WHEN NEW.id<=COALESCE((SELECT high FROM {$p}shcp_dav_idfloor WHERE scope='{$scope}'),0) BEGIN SELECT RAISE(ABORT,'Purged DAV cache identifier reused'); END");
            }
            // Mapped account and book rows are tombstones for as long as their user exists; all later
            // generations allocate different rows. No FK can silently retarget a mapping.
            foreach (['UPDATE','DELETE'] as $op) {
                $exempt=$op==='DELETE'?$open:'';
                $this->db->exec("CREATE TRIGGER {$p}shcp_dav_account_".strtolower($op)." BEFORE $op ON {$p}carddav_accounts WHEN EXISTS(SELECT 1 FROM {$p}shcp_dav_bindings b WHERE b.account_id=OLD.id".($op==='UPDATE' ? " AND (b.state!='active' OR NEW.id IS NOT OLD.id OR NEW.user_id IS NOT OLD.user_id OR NEW.presetname IS NOT OLD.presetname)" : $exempt).") BEGIN SELECT RAISE(ABORT,'Managed DAV account identity is immutable'); END");
            }
            foreach (['INSERT','UPDATE','DELETE'] as $op) {
                $exempt=$op==='DELETE'?$open:'';
                foreach (['addressbooks','contacts','groups','xsubtypes','group_user'] as $table) {
                    $ref=$op==='DELETE'?'OLD':'NEW';
                    $account=match($table) {
                        'addressbooks'=>"$ref.account_id",
                        'group_user'=>"(SELECT a.account_id FROM {$p}carddav_addressbooks a JOIN {$p}carddav_contacts c ON c.abook_id=a.id WHERE c.id=$ref.contact_id)",
                        default=>"(SELECT account_id FROM {$p}carddav_addressbooks WHERE id=$ref.abook_id)",
                    };
                    $condition="EXISTS(SELECT 1 FROM {$p}shcp_dav_bindings b WHERE b.account_id=$account AND b.state!='active' $exempt)";
                    if ($table === 'group_user') {
                        $condition .= " OR EXISTS(SELECT 1 FROM {$p}shcp_dav_bindings b JOIN {$p}carddav_addressbooks a ON a.account_id=b.account_id JOIN {$p}carddav_groups g ON g.abook_id=a.id WHERE g.id=$ref.group_id AND b.state!='active' $exempt)";
                        if ($op !== 'DELETE') $condition .= " OR (SELECT abook_id FROM {$p}carddav_groups WHERE id=$ref.group_id) IS NOT (SELECT abook_id FROM {$p}carddav_contacts WHERE id=$ref.contact_id)";
                    }
                    if ($op === 'UPDATE') $condition .= ' OR ' . str_replace('NEW.', 'OLD.', $condition);
                    $this->db->exec("CREATE TRIGGER {$p}shcp_dav_{$table}_".strtolower($op)." BEFORE $op ON {$p}carddav_$table WHEN $condition BEGIN SELECT RAISE(ABORT,'Retired DAV cache generation'); END");
                }
            }
            // Retained books cannot be moved to another account, even while their former generation is active.
            $this->db->exec("CREATE TRIGGER {$p}shcp_dav_book_identity BEFORE UPDATE ON {$p}carddav_addressbooks WHEN (NEW.id!=OLD.id OR NEW.account_id!=OLD.account_id) AND EXISTS(SELECT 1 FROM {$p}shcp_dav_bindings WHERE account_id=OLD.account_id) BEGIN SELECT RAISE(ABORT,'Managed DAV book identity is immutable'); END");
            $this->db->exec("DELETE FROM {$p}shcp_dav_schema");
            $this->db->exec("INSERT INTO {$p}shcp_dav_schema VALUES(2)");
            $this->db->commit();
        } catch (\Throwable $e) {$this->db->rollBack();throw $e;}
    }
    /**
     * Upstream declares both identifier columns as plain rowid aliases, which SQLite hands out again
     * once the highest row is gone. Cleanup that deletes rows is therefore unsafe until the columns
     * are AUTOINCREMENT: the retained sequence, not a tombstone row, is what a later generation
     * cannot walk back into. Idempotent; the ledger re-seeds the sequence if a table is ever rebuilt.
     */
    private function allocator(): void
    {
        $p=$this->p;$rebuild=[];
        foreach (self::SCOPES as $table=>$scope) {
            $ddl=$this->db->query("SELECT sql FROM sqlite_master WHERE type='table' AND name='{$p}{$table}'")->fetchColumn();
            if (!is_string($ddl)) throw new \RuntimeException('DAV cache schema unavailable');
            if (stripos($ddl,'AUTOINCREMENT')===false) $rebuild[$p.$table]=$ddl;
        }
        $this->db->exec('PRAGMA foreign_keys=OFF');
        $this->db->exec('PRAGMA legacy_alter_table=ON');
        try {
            $this->db->beginTransaction();
            foreach ($rebuild as $table=>$ddl) {
                $converted=preg_replace('/\bid\s+integer\s+NOT\s+NULL\s+PRIMARY\s+KEY\b/i','id integer NOT NULL PRIMARY KEY AUTOINCREMENT',$ddl,1,$hits);
                $create=preg_replace('/'.preg_quote($table,'/').'/',$table.'_shcp_new',(string)$converted,1,$named);
                if ($hits!==1 || $named!==1) throw new \RuntimeException('Unexpected DAV cache schema');
                $indexes=$this->db->query("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='{$table}' AND sql IS NOT NULL")->fetchAll(\PDO::FETCH_COLUMN);
                $this->db->exec($create);
                $this->db->exec("INSERT INTO {$table}_shcp_new SELECT * FROM {$table}");
                $this->db->exec("DROP TABLE {$table}");
                $this->db->exec("ALTER TABLE {$table}_shcp_new RENAME TO {$table}");
                foreach ($indexes as $index) $this->db->exec($index);
            }
            foreach (self::SCOPES as $table=>$scope) {
                $high=(int)$this->db->query("SELECT MAX((SELECT COALESCE(MAX(id),0) FROM {$p}{$table}),COALESCE((SELECT seq FROM sqlite_sequence WHERE name='{$p}{$table}'),0),COALESCE((SELECT high FROM {$p}shcp_dav_idfloor WHERE scope='{$scope}'),0))")->fetchColumn();
                $this->db->exec("DELETE FROM sqlite_sequence WHERE name='{$p}{$table}'");
                $this->db->exec("INSERT INTO sqlite_sequence(name,seq) VALUES('{$p}{$table}',{$high})");
            }
            if ($this->db->query('PRAGMA foreign_key_check')->fetch()!==false) throw new \RuntimeException('DAV cache schema rebuild left dangling references');
            $this->db->commit();
        } catch (\Throwable $e) {
            if ($this->db->inTransaction()) $this->db->rollBack();
            $this->db->exec('PRAGMA legacy_alter_table=OFF');$this->db->exec('PRAGMA foreign_keys=ON');
            throw $e;
        }
        $this->db->exec('PRAGMA legacy_alter_table=OFF');
        $this->db->exec('PRAGMA foreign_keys=ON');
    }
    /** Allocate once per generation under a writer lock. Never resurrect a retired generation. */
    public function activate(int $user,string $preset,string $binding,string $username,string $origin): int
    {
        $p=$this->p;
        if ((int)$this->db->query("SELECT version FROM {$p}shcp_dav_schema")->fetchColumn()!==2) throw new \RuntimeException('DAV cache schema unavailable');
        $this->db->exec('BEGIN IMMEDIATE');
        try {
            $q=$this->db->prepare("SELECT 1 FROM {$p}shcp_dav_cleanup WHERE user_id=?");$q->execute([$user]);
            if ($q->fetchColumn()) throw new \RuntimeException('DAV cache cleanup in progress');
            $q=$this->db->prepare("SELECT * FROM {$p}shcp_dav_bindings WHERE user_id=? AND preset=? AND binding_id=?");$q->execute([$user,$preset,$binding]);$row=$q->fetch(\PDO::FETCH_ASSOC);
            if ($row && $row['state']==='retired') throw new \RuntimeException('DAV generation retired');
            if ($row && $row['state']==='active') {$this->db->exec('COMMIT');return (int)$row['account_id'];}
            $q=$this->db->prepare("UPDATE {$p}shcp_dav_bindings SET state='retired' WHERE user_id=? AND preset=? AND state!='retired'");$q->execute([$user,$preset]);
            $q=$this->db->prepare("INSERT INTO {$p}carddav_accounts(accountname,username,password,discovery_url,user_id,presetname) VALUES(?,?,?,?,?,?)");
            $q->execute(['SHCP Contacts',$username,'%p',$origin.'/dav/',$user,$preset.':'.$binding]);
            $id=(int)$this->db->lastInsertId();
            $q=$this->db->prepare("INSERT INTO {$p}shcp_dav_bindings(user_id,preset,binding_id,account_id,state,verified_at) VALUES(?,?,?,?, 'active',?)");$q->execute([$user,$preset,$binding,$id,time()]);
            $this->db->exec('COMMIT'); return $id;
        } catch (\Throwable $e) {$this->db->exec('ROLLBACK');throw $e;}
    }
    /**
     * Supported managed-cache cleanup. The generation is retired and the identifier floor is raised in
     * a committed transaction before a single row is removed, so an interrupted run resumes without
     * ever exposing the generation again and without releasing an identifier a later owner could take.
     */
    public function purge(int $user): int
    {
        $p=$this->p;
        // No managed cache means no rows to remove and no users guard to satisfy. A schema that is
        // present but not at this version still refuses: its guards exist, its cleanup does not.
        if ($this->db->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='{$p}shcp_dav_bindings'")->fetchColumn()===false) return 0;
        if ((int)$this->db->query("SELECT version FROM {$p}shcp_dav_schema")->fetchColumn()!==2) throw new \RuntimeException('DAV cache schema unavailable');
        $this->db->exec('BEGIN IMMEDIATE');
        try {
            $q=$this->db->prepare("INSERT OR IGNORE INTO {$p}shcp_dav_cleanup(user_id,started_at) VALUES(?,?)");$q->execute([$user,time()]);
            $q=$this->db->prepare("UPDATE {$p}shcp_dav_bindings SET state='retired' WHERE user_id=? AND state!='retired'");$q->execute([$user]);
            $this->raise();
            $this->db->exec('COMMIT');
        } catch (\Throwable $e) {$this->db->exec('ROLLBACK');throw $e;}
        $this->db->exec('BEGIN IMMEDIATE');
        try {
            $q=$this->db->prepare("SELECT account_id FROM {$p}shcp_dav_bindings WHERE user_id=? AND account_id IS NOT NULL");$q->execute([$user]);
            $accounts=$q->fetchAll(\PDO::FETCH_COLUMN);
            $drop=$this->db->prepare("DELETE FROM {$p}carddav_accounts WHERE id=?");
            foreach ($accounts as $account) $drop->execute([(int)$account]);
            $q=$this->db->prepare("DELETE FROM {$p}shcp_dav_bindings WHERE user_id=?");$q->execute([$user]);
            $q=$this->db->prepare("DELETE FROM {$p}shcp_dav_cleanup WHERE user_id=?");$q->execute([$user]);
            $this->db->exec('COMMIT');
        } catch (\Throwable $e) {$this->db->exec('ROLLBACK');throw $e;}
        return count($accounts);
    }
    /** Record the high-water mark of both identifier spaces. Integers only: no credential ever lands here. */
    private function raise(): void
    {
        $p=$this->p;
        foreach (self::SCOPES as $table=>$scope)
            $this->db->exec("INSERT INTO {$p}shcp_dav_idfloor(scope,high) SELECT '{$scope}',MAX((SELECT COALESCE(MAX(id),0) FROM {$p}{$table}),COALESCE((SELECT seq FROM sqlite_sequence WHERE name='{$p}{$table}'),0)) ON CONFLICT(scope) DO UPDATE SET high=MAX(high,excluded.high)");
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
