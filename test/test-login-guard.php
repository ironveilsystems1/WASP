<?php
/**
 * The login lockout, run the way WordPress runs it.
 *
 * The guard returned a WP_Error from the `authenticate` filter at priority 5 and
 * was tested only by reading it. Core's authenticators run at priority 20 and do
 * not stop for an incoming error when a username and password are present, so a
 * "locked" account still logged in with the right password. Reproduced on real
 * WordPress 7.1.4 over HTTP. So this drives the real plugin through a filter
 * chain with the same shape as core's: the password check at 20 overwrites
 * whatever came in, exactly as wp_authenticate_username_password() does.
 *
 * Run: php test/test-login-guard.php
 */
define('ABSPATH', sys_get_temp_dir());
class WP_User { public $ID; public $user_login; function __construct($i,$l){$this->ID=$i;$this->user_login=$l;} }
class WP_Error { public $c; function __construct($c,$m=''){$this->c=$c;} function get_error_code(){return $this->c;} }
function is_wp_error($x){ return $x instanceof WP_Error; }

// A filter table with WordPress's semantics: priority order, and remove_filter
// matching on the callback and the priority.
$GLOBALS['F'] = [];
function add_filter($h,$cb,$p=10,$a=1){ $GLOBALS['F'][$h][$p][]=$cb; return true; }
function add_action($h,$cb,$p=10,$a=1){ return add_filter($h,$cb,$p,$a); }
function remove_filter($h,$cb,$p=10){
  foreach (($GLOBALS['F'][$h][$p] ?? []) as $k=>$c) { if ($c===$cb) { unset($GLOBALS['F'][$h][$p][$k]); return true; } }
  return false;
}
function apply_auth($user,$u,$pw){
  // Each priority is read when it is reached. A callback that removes a later
  // one takes effect within the same run, as it does in WP_Hook.
  $ps=array_keys($GLOBALS['F']['authenticate']); sort($ps);
  foreach ($ps as $p) { foreach (($GLOBALS['F']['authenticate'][$p] ?? []) as $cb) {
    $n=(new ReflectionFunction(Closure::fromCallable($cb)))->getNumberOfParameters();
    $user = $n>=3 ? $cb($user,$u,$pw) : $cb($user);
  } }
  return $user;
}
function do_failed($u,$e){ foreach ($GLOBALS['F']['wp_login_failed'] as $cbs) foreach ($cbs as $cb) $cb($u,$e); }

// Core's behaviour, by shape: an incoming WP_Error does not stop it.
$GLOBALS['hashes']=0;
function wp_authenticate_username_password($user,$u,$pw){
  if ($user instanceof WP_User) return $user;
  $GLOBALS['hashes']++;
  return $pw==='right' ? new WP_User(1,$u) : new WP_Error('incorrect_password');
}
function wp_authenticate_email_password($user,$u,$pw){ return $user; }
function wp_authenticate_application_password($user,$u,$pw){ return $user; }

$GLOBALS['T']=[]; $GLOBALS['mail']=[];
function get_transient($k){ return $GLOBALS['T'][$k] ?? false; }
function set_transient($k,$v,$e=0){ $GLOBALS['T'][$k]=$v; return true; }
function delete_transient($k){ unset($GLOBALS['T'][$k]); return true; }
function __($s){ return $s; }
function get_option($k){ return 'admin@example.test'; }
function home_url(){ return 'https://site.example'; }
function wp_parse_url($u,$c=-1){ return 'site.example'; }
function wp_mail($to,$s,$b){ $GLOBALS['mail'][]=$b; return true; }
function add_shortcode(){} function is_admin(){ return false; } function current_user_can(){ return false; }
function esc_html($s){ return $s; } function esc_html__($s){ return $s; }
$_SERVER['REMOTE_ADDR']='203.0.113.9';

function fresh(){
  $GLOBALS['F']=[]; $GLOBALS['T']=[]; $GLOBALS['mail']=[]; $GLOBALS['hashes']=0;
  add_filter('authenticate','wp_authenticate_username_password',20,3);
  add_filter('authenticate','wp_authenticate_email_password',20,3);
  add_filter('authenticate','wp_authenticate_application_password',20,3);
}
fresh();
$src = file_get_contents((getenv('WASP_TEST_REPO') ?: dirname(__DIR__)) . '/payload/mu-plugins/02-wpvm-login-guard.php');
$src = preg_replace('/^<\?php/', '', $src);
// The plugin's add_filter calls run once. Keep them so each case can start clean.
eval($src);
$plugin_hooks = $GLOBALS['F'];

$pass=0; $fail=0;
function check($d,$ok,$why=''){ global $pass,$fail;
  if($ok){$pass++;} else {$fail++; echo "  FAIL: $d".($why!==''?" ($why)":'')."\n";} }
function login($u,$pw){
  $r=apply_auth(null,$u,$pw);
  if ($r instanceof WP_Error) { do_failed($u,$r); }
  return $r;
}
function reset_case(){ global $plugin_hooks; $GLOBALS['F']=$plugin_hooks; $GLOBALS['T']=[]; $GLOBALS['mail']=[]; $GLOBALS['hashes']=0; }

reset_case();
$r=login('alice','right');
check('a correct password logs in', $r instanceof WP_User);
reset_case();
$r=login('alice','wrong');
check('a wrong password is refused', $r instanceof WP_Error && $r->get_error_code()==='incorrect_password');

reset_case();
for($i=0;$i<WPVM_LOGIN_MAX_ATTEMPTS;$i++){ login('alice','wrong'); }
check('five failures set the lock', wpvm_login_lock_remaining('alice')>0);
$h=$GLOBALS['hashes'];
$r=login('alice','right');
check('the RIGHT password is refused while locked', $r instanceof WP_Error, $r instanceof WP_User ? 'logged in during a lockout' : '');
check('the refusal says why', $r instanceof WP_Error && $r->get_error_code()==='wpvm_locked_out');
check('a locked attempt never reaches the hash', $GLOBALS['hashes']===$h, 'hash ran '.($GLOBALS['hashes']-$h).' time(s)');

reset_case();
for($i=0;$i<WPVM_LOGIN_MAX_ATTEMPTS;$i++){ login('alice','wrong'); }
$r=login('ALICE','right');
check('the lock does not depend on the case of the name', $r instanceof WP_Error);

// An authentication plugin later on the filter cannot turn a lock into a login.
reset_case();
add_filter('authenticate', function($user,$u=null,$pw=null){ return new WP_User(9,'sso'); }, 50, 3);
for($i=0;$i<WPVM_LOGIN_MAX_ATTEMPTS;$i++){ set_transient(wpvm_login_key('lock','alice'), time()+900); }
$r=apply_auth(null,'alice','right');
check('a later authenticator cannot undo a lock', $r instanceof WP_Error);

// Hammering a locked account must not extend it, double it or mail anyone.
reset_case();
for($i=0;$i<WPVM_LOGIN_MAX_ATTEMPTS;$i++){ login('alice','wrong'); }
$lock=get_transient(wpvm_login_key('lock','alice'));
$mails=count($GLOBALS['mail']); $n=(int)get_transient(wpvm_login_key('count','alice'));
for($i=0;$i<WPVM_LOGIN_MAX_ATTEMPTS*3;$i++){ login('alice','wrong'); }
check('attempts during a lock do not extend it', get_transient(wpvm_login_key('lock','alice'))===$lock);
check('attempts during a lock do not double it', (int)get_transient(wpvm_login_key('count','alice'))===$n);
check('attempts during a lock send no more mail', count($GLOBALS['mail'])===$mails);

// A walled administrator gave the right password. Not a guess.
reset_case();
do_failed('alice', new WP_Error('wpvm_mfa_required'));
check('the MFA wall is not counted as a failed guess', wpvm_login_attempts('alice')===0);

// The address is attacker-supplied text, and it ends up in an admin's inbox.
reset_case();
$evil="alice\nClick https://evil.example/reset <now>";
for($i=0;$i<WPVM_LOGIN_MAX_ATTEMPTS;$i++){ login($evil,'wrong'); }
check('the lockout mail was sent', count($GLOBALS['mail'])===1, count($GLOBALS['mail']).' mail(s), lock='.var_export(wpvm_login_lock_remaining($evil),true));
check('the username in that mail is cleaned', !preg_match('/\nClick|<now>/', $GLOBALS['mail'][0] ?? ''), $GLOBALS['mail'][0] ?? '');

if($fail>0){ echo "Login guard: $fail FAILED\n"; exit(1); }
echo "Login guard: all $pass checks passed\n";
