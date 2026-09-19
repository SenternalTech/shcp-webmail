<?php
// SPDX-License-Identifier: MIT
namespace Shcp\Webmail\Dav;

/** Tokens live only in the encrypted dedicated Roundcube session field. */
final class Credentials
{
    public const FIELD = 'shcp_dav_credentials';
    private const CONTEXT = 'shcp-dav-session-v1:';
    private $lock = null;
    public function __construct(private \rcube $rc, private Transport $transport) {}
    private function lock(): void
    {
        if ($this->lock !== null) return;
        $sid=session_id();
        if ($sid === '' || !$this->rc->session) throw new \RuntimeException('DAV session unavailable');
        $dir=$this->rc->config->get('temp_dir');
        if (!is_string($dir) || !is_dir($dir)) throw new \RuntimeException('DAV session lock unavailable');
        $path=rtrim($dir,'/').'/shcp-dav-'.hash('sha256',$sid).'.lock';
        $mask=umask(0077);
        try {$lock=fopen($path,'c');} finally {umask($mask);}
        if ($lock === false || !flock($lock,LOCK_EX)) throw new \RuntimeException('DAV session lock unavailable');
        $this->lock=$lock;
        // Read current durable state AFTER taking the per-session lock. Roundcube's DB session handler itself
        // does not provide a request-long lock. Never replay a request's pre-lock refresh pair.
        $serialized=$this->rc->session->read($sid);
        $current=$_SESSION; unset($current[self::FIELD]);
        try {
            $_SESSION=[];
            if (is_string($serialized) && $serialized !== '' && session_decode($serialized)) {
                if (isset($_SESSION[self::FIELD])) $current[self::FIELD]=$_SESSION[self::FIELD];
                else unset($current[self::FIELD]);
            }
        } finally {$_SESSION=$current;}
    }
    private function persist(?array $value): void
    {
        if ($value === null) $_SESSION[self::FIELD] = '';
        else {
            $encrypted=$this->rc->encrypt(self::CONTEXT.json_encode($value,JSON_THROW_ON_ERROR));
            if (!is_string($encrypted) || $encrypted === '') throw new \RuntimeException('DAV session encryption failed');
            $_SESSION[self::FIELD]=$encrypted;
        }
        if (!$this->rc->session->sess_write(session_id(),session_encode()) || $this->rc->get_dbh()->is_error()) throw new \RuntimeException('DAV session persistence failed');
        $expected=$_SESSION[self::FIELD]; $current=$_SESSION;
        try {
            $persisted=$this->rc->session->read(session_id()); $_SESSION=[];
            if (!is_string($persisted) || !session_decode($persisted) || ($_SESSION[self::FIELD]??null)!==$expected) throw new \RuntimeException('DAV session persistence failed');
        } finally {$_SESSION=$current;}
    }
    public function exchange(string $ticket, string $username): void
    {
        $this->lock(); $this->persist(null);
        $value=$this->transport->api('exchange',['ticket'=>$ticket]);
        $this->validate($value,$username);
        $this->persist($value);
    }
    public function get(string $username): array
    {
        $this->lock();
        $raw=$this->rc->decrypt($_SESSION[self::FIELD] ?? '');
        if (!is_string($raw) || !str_starts_with($raw,self::CONTEXT)) throw new \RuntimeException('Sign in again to access contacts');
        $v=json_decode(substr($raw,strlen(self::CONTEXT)),true,16,JSON_THROW_ON_ERROR);
        $this->validate($v,$username);
        if ($v['expires_at'] <= time()+60) {
            // Erase before request: a lost rotation response must never resurrect retired credentials.
            $this->persist(null);
            $next=$this->transport->api('renew',['access_token'=>$v['access_token'],'refresh_token'=>$v['refresh_token']]);
            $this->validate($next,$username);
            if ($next['binding_id'] !== $v['binding_id'] || $next['auth_epoch'] !== $v['auth_epoch'] || $next['absolute_expires_at'] !== $v['absolute_expires_at']) throw new \RuntimeException('DAV session identity changed');
            $this->persist($next); $v=$next;
        }
        return $v;
    }
    public function revoke(): void
    {
        try {
            $this->lock();
            $raw=$this->rc->decrypt($_SESSION[self::FIELD] ?? '');
            $v=is_string($raw) && str_starts_with($raw,self::CONTEXT) ? json_decode(substr($raw,strlen(self::CONTEXT)),true) : null;
            $this->persist(null);
            if (is_array($v) && isset($v['access_token'],$v['refresh_token'])) $this->transport->api('revoke',['access_token'=>$v['access_token'],'refresh_token'=>$v['refresh_token']]);
        } finally {unset($_SESSION[self::FIELD]);}
    }
    private function validate(mixed $v,string $username): void
    {
        if (!is_array($v) || ($v['username'] ?? null)!==$username
            || !is_string($v['access_token']??null) || !preg_match('/\Ashcp-dav-v1:[a-f0-9]{64}\z/',$v['access_token'])
            || !is_string($v['refresh_token']??null) || !preg_match('/\A[a-f0-9]{64}\z/',$v['refresh_token'])
            || !is_string($v['binding_id']??null) || !preg_match('/\A[a-f0-9-]{32,64}\z/',$v['binding_id'])
            || !is_int($v['auth_epoch']??null) || $v['auth_epoch']<0
            || !is_int($v['expires_at']??null) || !is_int($v['absolute_expires_at']??null)
            || $v['expires_at']<=time() || $v['absolute_expires_at']<=time()
            || $v['expires_at']>$v['absolute_expires_at'] || $v['expires_at']>time()+900
            || $v['absolute_expires_at']>time()+43200) throw new \RuntimeException('Invalid DAV session');
    }
    public function __destruct()
    {
        if (is_resource($this->lock)) {flock($this->lock,LOCK_UN);fclose($this->lock);}
    }
}