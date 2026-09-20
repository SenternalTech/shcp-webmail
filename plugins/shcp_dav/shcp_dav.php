<?php
// SPDX-License-Identifier: MIT
require_once __DIR__.'/lib/Transport.php';
require_once __DIR__.'/lib/Credentials.php';
require_once __DIR__.'/lib/Bindings.php';

/** Managed contacts bridge. Mail and local address books do not depend on DAV availability. */
class shcp_dav extends rcube_plugin
{
    private ?\Shcp\Webmail\Dav\Transport $transport=null;
    private ?\Shcp\Webmail\Dav\Credentials $credentials=null;
    private ?\Shcp\Webmail\Dav\Bindings $bindings=null;
    private bool $attempted=false;
    private ?array $identity=null;
    private ?int $accountId=null;
    private array $auth=[];
    private string $preset='shcp';

    public function init(): void
    {
        $this->load_config();
        $this->add_texts('localization/');
        $this->add_hook('shcp_sso_authenticated',[$this,'ssoAuthenticated']);
        $this->add_hook('startup', [$this, 'startup']);
        $this->add_hook('session_destroy',[$this,'logout']);
        $this->add_hook('user_delete_prepare',[$this,'userDelete']);
        $this->add_hook('carddav_admin_settings',[$this,'settings']);
        $this->add_hook('carddav_accounts_prepare',[$this,'prepareAccounts']);
        $this->add_hook('carddav_accounts_filter',[$this,'filterAccounts']);
        $this->add_hook('carddav_account',[$this,'account']);
        $this->add_hook('carddav_cache_access',[$this,'cacheAccess']);
        $this->add_hook('carddav_cache_namespace',[$this,'cacheNamespace']);
    }
    /** Lock/reload the dedicated credential field on every SSO request, including tasks with no address book. */
    public function startup(array $args): array
    {
        if (!empty($_SESSION['shcp_sso_active']) && is_string($_SESSION['username']??null)) {
            try {$this->services();$this->credentials->get($_SESSION['username']);}
            catch (Throwable $e) {$_SESSION[\Shcp\Webmail\Dav\Credentials::FIELD]='';$this->unavailable();}
        }
        return $args;
    }
    private function services(): void
    {
        if ($this->transport!==null) return;
        $rc=rcube::get_instance();
        $origin=$rc->config->get('shcp_dav_origin');$ca=$rc->config->get('shcp_dav_cafile');
        if (!is_string($origin) || ($ca!==null && !is_string($ca))) throw new RuntimeException('Contacts configuration unavailable');
        $this->transport=new \Shcp\Webmail\Dav\Transport($origin,$ca);
        $this->credentials=new \Shcp\Webmail\Dav\Credentials($rc,$this->transport);
        $this->cache();
    }
    /** The managed cache alone, with no transport configuration: user deletion must work without DAV. */
    private function cache(): \Shcp\Webmail\Dav\Bindings
    {
        if ($this->bindings===null) {
            $rc=rcube::get_instance();
            $dsn=$rc->config->get('db_dsnw');
            if (!is_string($dsn) || !str_starts_with($dsn,'sqlite:') || str_contains($dsn,'?')) throw new RuntimeException('Contacts require SQLite');
            $this->bindings=new \Shcp\Webmail\Dav\Bindings(new PDO($dsn),(string)$rc->config->get('db_prefix',''));
        }
        return $this->bindings;
    }
    public function ssoAuthenticated(array $args): array
    {
        $this->attempted=false;$this->identity=null;$this->accountId=null;
        try {
            $this->services();
            $username=$_SESSION['username']??null;
            if (!is_string($username) || ($args['email']??null)!==$username || empty($_SESSION['shcp_sso_active'])) throw new RuntimeException('Invalid contacts session');
            $ticket=$args['dav_ticket']??null;
            if (!is_string($ticket) || $ticket==='') {
                unset($_SESSION[\Shcp\Webmail\Dav\Credentials::FIELD]);
                return $args; // No entitlement must not prevent mail login.
            }
            $this->credentials->exchange($ticket,$username);
        } catch (Throwable $e) {
            unset($_SESSION[\Shcp\Webmail\Dav\Credentials::FIELD]);
            $this->unavailable();
        }
        unset($args['dav_ticket']);
        return $args;
    }
    private function unavailable(): void
    {
        // Deliberately no exception/body logging: endpoint errors can contain credential material.
        $rc=rcube::get_instance();
        if ($rc->output && method_exists($rc->output,'show_message')) $rc->output->show_message('shcp_dav.contactsunavailable','warning');
    }
    private function prepare(): bool
    {
        if ($this->attempted) return $this->identity!==null;
        $this->attempted=true;
        try {
            $this->services();
            $username=$_SESSION['username']??null;
            if (!is_string($username) || !filter_var($username,FILTER_VALIDATE_EMAIL) || empty($_SESSION['user_id'])) return false;
            $grant=null;
            if (!empty($_SESSION['shcp_sso_active'])) {$grant=$this->credentials->get($username);$password=$grant['access_token'];}
            else {$password=rcube::get_instance()->decrypt($_SESSION['password']??'');}
            if (!is_string($password) || $password==='') return false;
            $this->auth=[$username,$password];
            $url=$this->transport->origin().'/dav/principals/'.rawurlencode($username);
            $body='<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:s="urn:shcp:dav"><d:prop><s:binding-id/><s:auth-epoch/></d:prop></d:propfind>';
            $r=$this->transport->request('PROPFIND',$url,['Depth'=>'0','Content-Type'=>'application/xml; charset=utf-8'],$body,$this->auth);
            if ($r['status']!==207 || stripos($r['body'],'<!DOCTYPE')!==false) throw new RuntimeException('Contacts not authorized');
            $doc=new DOMDocument();
            if (!@$doc->loadXML($r['body'],LIBXML_NONET)) throw new RuntimeException('Invalid contacts response');
            $xp=new DOMXPath($doc,false);$xp->registerNamespace('d','DAV:');$xp->registerNamespace('s','urn:shcp:dav');
            $matches=[];
            foreach ($xp->query('/d:multistatus/d:response') as $response) {
                $href=$xp->evaluate('string(d:href)',$response);
                $hrefPath=parse_url($href,PHP_URL_PATH);
                if (rawurldecode(rtrim((string)$hrefPath,'/'))!=='/dav/principals/'.$username) continue;
                foreach ($xp->query('d:propstat',$response) as $propstat) {
                    if (!preg_match('/\AHTTP\/\S+ 200(?: |$)/',$xp->evaluate('string(d:status)',$propstat))) continue;
                    $binding=$xp->evaluate('string(d:prop/s:binding-id)',$propstat);
                    $epoch=$xp->evaluate('string(d:prop/s:auth-epoch)',$propstat);
                    if (preg_match('/\A[a-f0-9-]{32,64}\z/',$binding) && ctype_digit($epoch)) $matches[]=['binding_id'=>$binding,'auth_epoch'=>(int)$epoch,'username'=>$username];
                }
            }
            if (count($matches)!==1) throw new RuntimeException('Missing contacts identity');
            $id=$matches[0];
            if ($grant!==null && ($grant['binding_id']!==$id['binding_id'] || $grant['auth_epoch']!==$id['auth_epoch'])) throw new RuntimeException('Contacts identity changed');
            $this->identity=$id;
            return true;
        } catch (Throwable $e) {$this->identity=null;$this->unavailable();return false;}
    }
    public function settings(array $args): array
    {
        $prefs=$args['prefs'];
        unset($prefs[$this->preset]);
        // The managed preset is generated from trusted configuration, never copied from user settings.
        if ($this->prepare()) {
            $key=$this->preset.':'.$this->identity['binding_id'];
            $prefs[$key]=['accountname'=>'SHCP Contacts','username'=>'%u','password'=>'%p','discovery_url'=>$this->transport->origin().'/dav/','refresh_time'=>'00:15:00','fixed'=>['username','password','discovery_url','ssl_noverify','preemptive_basic_auth'],'readonly'=>false,'active'=>true,'ssl_noverify'=>false];
        }
        $args['prefs']=$prefs;return $args;
    }
    public function prepareAccounts(array $args): array
    {
        if ($this->accountId===null && $this->prepare()) {
            try {$this->accountId=$this->bindings->activate((int)$_SESSION['user_id'],$this->preset,$this->identity['binding_id'],$this->identity['username'],$this->transport->origin());}
            catch (Throwable $e) {$this->identity=null;$this->unavailable();}
        }
        return $args;
    }
    public function filterAccounts(array $args): array
    {
        foreach ($args['accounts'] as $id=>$cfg) {
            $preset=$cfg['presetname']??'';
            if ($preset===$this->preset || str_starts_with($preset,$this->preset.':')) {
                if (!$this->allowed((int)$id)) unset($args['accounts'][$id]);
            }
        }
        return $args;
    }
    private function allowed(int $account): bool
    {
        return $this->identity!==null && $account===$this->accountId
            && $this->bindings->current((int)$_SESSION['user_id'],$account,$this->identity['binding_id']);
    }
    private function fence(int $account): void
    {
        if (!$this->allowed($account)) throw new RuntimeException('Contacts generation is unavailable');
    }
    public function account(array $args): array
    {
        $cfg=$args['config'];$preset=$cfg['presetname']??'';
        if ($preset!==$this->preset && !str_starts_with($preset,$this->preset.':')) return $args;
        $id=(int)($cfg['id']??0);$this->fence($id);
        if ($preset!==$this->preset.':'.$this->identity['binding_id'] || ($cfg['discovery_url']??null)!==$this->transport->origin().'/dav/') throw new RuntimeException('Invalid managed contacts account');
        require_once __DIR__.'/lib/Account.php';
        $args['account']=new \Shcp\Webmail\Dav\Account($this->transport->origin().'/dav/',$this->transport,$this->auth,fn()=>$this->fence($id));
        return $args;
    }
    public function cacheAccess(array $args): array
    {
        $this->services();
        $id=$this->bindings->accountForBook((string)$args['book_id']);
        if ($id!==null && $this->bindings->managed($id)) $this->fence($id);
        return $args;
    }
    public function cacheNamespace(array $args): array
    {
        // Photo cache must not share UID keys between principal generations.
        if ($this->prepare()) $args['namespace']='carddav-shcp-'.hash('sha256',$this->identity['binding_id']);
        return $args;
    }
    /**
     * Roundcube fires this before it opens its own deletion transaction, so the managed cache is
     * purged on its own writer lock. Failing here aborts the deletion rather than leaving a user
     * whose guards have been removed.
     */
    public function userDelete(array $args): array
    {
        try {
            $user=$args['user']??null;
            if (!$user instanceof rcube_user || (int)$user->ID<1) throw new RuntimeException('Unknown user');
            $this->cache()->purge((int)$user->ID);
        } catch (Throwable $e) {$args['abort']=true;}
        return $args;
    }
    public function logout(array $args): array
    {
        try {$this->services();$this->credentials->revoke();} catch (Throwable $e) { /* bounded expiry, not a revocation claim */ }
        unset($_SESSION[\Shcp\Webmail\Dav\Credentials::FIELD]);return $args;
    }
}