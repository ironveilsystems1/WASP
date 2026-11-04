<?php
/**
 * Logic tests for the MFA enforcement mu-plugin (03-wpvm-mfa-enforce.php).
 *
 * The mu-plugin's blocking decision is exactly the kind of thing that is easy
 * to get subtly wrong -- an off-by-one in the grace maths, or treating email
 * as a sufficient second factor -- and a mistake either locks admins out or
 * silently fails open. This exercises the pure decision functions against a
 * mocked WordPress surface so a regression is caught before it reaches a VM.
 *
 * Run: php test/test-mfa-enforcement.php
 */
define('ABSPATH', sys_get_temp_dir());
define('DAY_IN_SECONDS', 86400);
define('HOUR_IN_SECONDS', 3600);

class WP_User { public $ID; public $_admin; function __construct($id,$admin){$this->ID=$id;$this->_admin=$admin;} }
$GLOBALS['_meta'] = []; $GLOBALS['_providers'] = [];
function get_user_meta($id,$k,$s){ return $GLOBALS['_meta']["$id:$k"] ?? ''; }
function update_user_meta($id,$k,$v){ $GLOBALS['_meta']["$id:$k"]=$v; return true; }
function user_can($u,$cap){ return $cap==='manage_options' ? $u->_admin : false; }
class Two_Factor_Core {
  static function get_enabled_providers_for_user($id){ return $GLOBALS['_providers'][$id] ?? []; }
  // Real plugin returns classname => instance; mock mirrors the KEYS the code reads.
  static function get_available_providers_for_user($id){
    $flat = $GLOBALS['_providers'][$id] ?? [];
    $keyed = []; foreach($flat as $c){ $keyed[$c] = true; } return $keyed;
  }
}
// Hooks are recorded rather than ignored, so the wall itself can be driven below.
$GLOBALS['_hooks'] = [];
function add_action($n,$cb,$p=10,$a=1){ $GLOBALS['_hooks'][$n][]=[$cb,$p]; }
function add_filter($n,$cb,$p=10,$a=1){ $GLOBALS['_hooks'][$n][]=[$cb,$p]; }
class WP_Error { public $c; function __construct($c,$m=''){$this->c=$c;} function get_error_code(){return $this->c;} }
function is_wp_error($x){ return $x instanceof WP_Error; }
class WallDied extends Exception {}
class WP_Session_Tokens { public $id; function __construct($i){$this->id=$i;}
  static function get_instance($i){ return new self($i); }
  function destroy_all(){ $GLOBALS['_destroyed'][]=$this->id; } }
function wp_clear_auth_cookie(){ $GLOBALS['_cleared']=true; }
function wp_die($m,$t='',$a=[]){ $GLOBALS['_died']=$a['response'] ?? 0; throw new WallDied(); }
function wp_kses_post($s){ return $s; }
function set_transient($k,$v,$e){ $GLOBALS['_nudged']=true; }
function wp_doing_ajax(){ return $GLOBALS['_ajax'] ?? false; }
function wp_get_current_user(){ return $GLOBALS['_current'] ?? null; }
function admin_url($p=''){ return 'https://site/wp-admin/'.$p; }

$file = dirname(__DIR__) . '/payload/mu-plugins/03-wpvm-mfa-enforce.php';
$src = file_get_contents($file);
$src = str_replace(['WPVM_MFA_ENFORCE_PLACEHOLDER','WPVM_MFA_GRACE_PLACEHOLDER'], ['1','7'], $src);
$src = preg_replace('/^<\?php/', '', $src);
eval($src);

$pass=0; $fail=0;
function check($d,$g,$w){ global $pass,$fail;
  if($g===$w){$pass++;} else {$fail++; echo "  FAIL: $d (got ".var_export($g,true).", want ".var_export($w,true).")\n";} }

$admin=new WP_User(1,true); $editor=new WP_User(2,false);
check('admin in scope', wpvm_mfa_user_in_scope($admin), true);
check('editor not in scope', wpvm_mfa_user_in_scope($editor), false);
check('null not in scope', wpvm_mfa_user_in_scope(null), false);

$GLOBALS['_providers'][1]=[];                       check('none=not enrolled', wpvm_mfa_user_enrolled(1), false);
$GLOBALS['_providers'][1]=['Two_Factor_Email'];     check('email-only=not enrolled', wpvm_mfa_user_enrolled(1), false);
$GLOBALS['_providers'][1]=['Two_Factor_Totp'];      check('TOTP=enrolled', wpvm_mfa_user_enrolled(1), true);
$GLOBALS['_providers'][1]=['Two_Factor_Backup_Codes']; check('backup codes=enrolled', wpvm_mfa_user_enrolled(1), true);

$GLOBALS['_meta']=[];                               check('first check anchors, not expired', wpvm_mfa_grace_expired(3), false);
$GLOBALS['_meta']['4:wpvm_mfa_grace_start']=time()-(8*86400); check('8d>7d grace=expired', wpvm_mfa_grace_expired(4), true);
$GLOBALS['_meta']['5:wpvm_mfa_grace_start']=time()-(3*86400); check('3d<7d grace=ok', wpvm_mfa_grace_expired(5), false);

$GLOBALS['_providers'][1]=[]; $GLOBALS['_meta']['1:wpvm_mfa_grace_start']=time()-(10*86400);
check('unenrolled admin past grace=BLOCK', wpvm_mfa_user_in_scope($admin)&&!wpvm_mfa_user_enrolled(1)&&wpvm_mfa_grace_expired(1), true);
$GLOBALS['_providers'][1]=['Two_Factor_Totp'];
check('enrolled admin=no block', !wpvm_mfa_user_enrolled(1), false);
$GLOBALS['_providers'][2]=[];
check('editor=never block', wpvm_mfa_user_in_scope($editor), false);

// ── the wall: past grace, nothing is left open ───────────────────────────────
// Reproduced against real WordPress: an allowlist of "enrolment" pages let a
// stolen password reach plugins.php?action=logout and promote a second admin
// through user-edit.php. So nothing here depends on the page being requested.
function hook($n){ return $GLOBALS['_hooks'][$n][0] ?? [null,null]; }
function reset_wall(){ $GLOBALS['_destroyed']=[]; $GLOBALS['_cleared']=false; $GLOBALS['_died']=0; $GLOBALS['_nudged']=false; }
function run_admin_init(){ reset_wall(); [$cb]=hook('admin_init'); try { $cb(); } catch (WallDied $e) {} }
function run_wp_login($u){ reset_wall(); [$cb]=hook('wp_login'); try { $cb('x',$u); } catch (WallDied $e) {} }

$walled=new WP_User(10,true);   $GLOBALS['_providers'][10]=[];                  $GLOBALS['_meta']['10:wpvm_mfa_grace_start']=time()-(30*86400);
$fresh=new WP_User(11,true);    $GLOBALS['_providers'][11]=[];                  $GLOBALS['_meta']['11:wpvm_mfa_grace_start']=time()-86400;
$enrolled=new WP_User(12,true); $GLOBALS['_providers'][12]=['Two_Factor_Totp']; $GLOBALS['_meta']['12:wpvm_mfa_grace_start']=time()-(30*86400);
$mailonly=new WP_User(13,true); $GLOBALS['_providers'][13]=['Two_Factor_Email'];$GLOBALS['_meta']['13:wpvm_mfa_grace_start']=time()-(30*86400);
$plain=new WP_User(14,false);   $GLOBALS['_providers'][14]=[];                  $GLOBALS['_meta']['14:wpvm_mfa_grace_start']=time()-(30*86400);

check('past grace, no factor = walled',          wpvm_mfa_is_walled($walled),   true);
check('within grace = not walled',               wpvm_mfa_is_walled($fresh),    false);
check('enrolled = not walled',                   wpvm_mfa_is_walled($enrolled), false);
check('email only, past grace = walled',         wpvm_mfa_is_walled($mailonly), true);
check('non-admin = not walled',                  wpvm_mfa_is_walled($plain),    false);
check('the page allowlist is gone',              function_exists('wpvm_mfa_request_is_enrollment_path'), false);

// The login itself. No cookies are ever issued, because nothing reaches wp_signon's
// cookie step. wp_authenticate_user would run before the password check.
[$auth,$prio]=hook('authenticate');
check('refused after core password check (20) and spam check (99)', $prio>99, true);
check('not on wp_authenticate_user, which runs before the password', isset($GLOBALS['_hooks']['wp_authenticate_user']), false);
$r=$auth($walled);   check('walled login is refused', $r instanceof WP_Error && $r->get_error_code()==='wpvm_mfa_required', true);
$r=$auth($fresh);    check('within grace login passes', $r, $fresh);
$r=$auth($enrolled); check('enrolled login passes', $r, $enrolled);
$r=$auth($plain);    check('non-admin login passes', $r, $plain);
$e=new WP_Error('incorrect_password'); check('a wrong password stays a wrong password', $auth($e), $e);
check('a failed lookup stays failed', $auth(null), null);

// Sessions that already exist. The request does not matter, so these are the
// exact requests that got through before.
foreach ([ 'plugins.php?action=logout', 'user-edit.php?user_id=2', 'profile.php', 'admin-ajax.php', 'admin-post.php' ] as $page) {
  $_SERVER['REQUEST_URI']='/wp-admin/'.$page;
  $GLOBALS['_current']=$walled; run_admin_init();
  check("$page: refused with 403", $GLOBALS['_died'], 403);
  check("$page: sessions destroyed", $GLOBALS['_destroyed'], [10]);
}
$GLOBALS['_current']=$enrolled; run_admin_init(); check('enrolled admin keeps wp-admin', $GLOBALS['_died'], 0);
$GLOBALS['_current']=$fresh;    run_admin_init(); check('within grace keeps wp-admin', $GLOBALS['_died'], 0);
$GLOBALS['_current']=null;      run_admin_init(); check('anonymous admin-ajax is untouched', $GLOBALS['_died'], 0);

// Second layer. destroy_all() rather than wp_destroy_current_session(), which
// reads $_COOKIE and finds nothing during a login.
run_wp_login($walled);
check('wp_login: refused with 403', $GLOBALS['_died'], 403);
check('wp_login: every session destroyed', $GLOBALS['_destroyed'], [10]);
check('wp_login: cookies cleared', $GLOBALS['_cleared'], true);
run_wp_login($fresh);
check('wp_login: within grace is nudged, not refused', [$GLOBALS['_died'],$GLOBALS['_nudged']], [0,true]);
if($fail>0){ echo "MFA enforcement: $fail FAILED\n"; exit(1); }
echo "MFA enforcement logic: all $pass checks passed\n";
