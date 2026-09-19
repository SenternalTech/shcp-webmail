<?php
// SPDX-License-Identifier: MIT
ob_start();
$fixture=$argv[1];$mode=$argv[2];$sid=$argv[3];
define('INSTALL_PATH',$fixture.'/roundcube/');$_SERVER['REMOTE_ADDR']='127.0.0.1';
require INSTALL_PATH.'program/include/iniset.php';
require dirname(__DIR__,2).'/plugins/shcp_dav/lib/Transport.php';
require dirname(__DIR__,2).'/plugins/shcp_dav/lib/Credentials.php';
$rc=rcube::get_instance(rcube::INIT_WITH_DB|rcube::INIT_WITH_PLUGINS);$rc->config->set('temp_dir',$fixture.'/roundcube/temp');
$rc->session=rcube_session::factory($rc->config);session_id($sid);$rc->session->start();
if($mode==='exchange') $_SESSION=['user_id'=>1,'username'=>'alice@example.test','password'=>$rc->encrypt(''),'shcp_sso_active'=>true];
$password=$_SESSION['password']??null;
$transport=new \Shcp\Webmail\Dav\Transport('https://localhost:18980',$fixture.'/tls.crt');
$credentials=new \Shcp\Webmail\Dav\Credentials($rc,$transport);
try {
 if($mode==='exchange')$credentials->exchange('fixture-child-ticket','alice@example.test');
 elseif($mode==='revoke')$credentials->revoke();
 else {$value=$credentials->get('alice@example.test');if(str_contains(session_encode(),$value['access_token'])||str_contains(session_encode(),$value['refresh_token']))throw new RuntimeException('Plain credential in session');}
 if(($_SESSION['password']??null)!==$password)throw new RuntimeException('Session password changed');
 echo 'SHCP_DAV_SESSION_OK '.$mode."\n";
} catch(Throwable $e) {echo 'SHCP_DAV_SESSION_DENIED '.$mode."\n";}
$rc->session->write_close();
ob_end_flush();