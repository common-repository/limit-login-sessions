<?php
/*
Plugin Name: Limit Login Sessions
Version: 1.0.0 
Author: Bhavey Bansal
Description: Limits users login sessions.
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html
*/

function lls_restriction_register_settings() {
   add_option( 'login_sessions_number', 'Login sessions number');
   register_setting( 'lls_options_group', 'login_sessions_number', 'lls_callback' );
}
add_action( 'admin_init', 'lls_restriction_register_settings' );

function lls_restriction_register_options_page() {
  add_options_page('Page Title', 'Limit Login Sessions Settings', 'manage_options', 'myplugin', 'lls_ip_restriction_options_page');
}
add_action('admin_menu', 'lls_restriction_register_options_page');

function lls_ip_restriction_options_page(){ ?>
    <div>
        <?php screen_icon(); ?>
        <h2><?php echo __("Limit Login Session Settings","llls_plugin"); ?></h2>
        <form method="post" action="options.php">
            <?php settings_fields( 'lls_options_group' ); ?>
            <p><?php echo __("Enter number of sessions allowed per account. Sessions after this number will be restricted to use.","lls_plugin"); ?></p>
            <table>
                <tr valign="top">
                    <th scope="row"><label for="login_sessions_number"><?php echo __("No. of Sessions","lls_plugin"); ?></label></th>
                    <td><input type="number" id="login_sessions_number" min="1" name="login_sessions_number" value="<?php echo get_option('login_sessions_number'); ?>" /></td>
                </tr>
            </table>
            <?php  submit_button(); ?>
        </form>
    </div>
<?php
}

add_filter('authenticate', 'lls_authenticate', 1000, 2);
function lls_authenticate($user, $username){
    if(!username_exists($username) || !$user = get_user_by('login', $username))
        return null;
    
    $max_sessions = get_option('login_sessions_number');
    $max_oldest_allowed_session_hours = 4;
    $error_code = 'max_session_reached';
    $error_message = "Maximum $max_sessions login sessions are allowed. Please contact site administrator.";
    $manager = WP_Session_Tokens::get_instance( $user->ID );
    $sessions =  $manager->get_all();
    
    $session_count = count($sessions);

    if($session_count < $max_sessions)
        return $user;
    $oldest_activity_session = lls_get_oldest_activity_session($sessions);
    
    if(
        ( $session_count >= $max_sessions && !$oldest_activity_session )
        || ( $session_count >= $max_sessions && $oldest_activity_session['last_activity'] + $max_oldest_allowed_session_hours * HOUR_IN_SECONDS > time())
    ){
        return new WP_Error($error_code, $error_message);
    }
    
    $verifier = lls_get_verifier_by_session($oldest_activity_session, $user->ID);
    lls_destroy_session($verifier, $user->ID);
    return $user;
}
function lls_destroy_session($verifier, $user_id){
    $sessions = get_user_meta( $user_id, 'session_tokens', true );
    if(!isset($sessions[$verifier]))
        return true;
    unset($sessions[$verifier]);
    if(!empty($sessions)){
        update_user_meta( $user_id, 'session_tokens', $sessions );
        return true;
    }
    delete_user_meta( $user_id, 'session_tokens');
    return true;
}
function lls_get_verifier_by_session($session, $user_id = null){
    if(!$user_id)
        $user_id = get_current_user_id();
    $session_string = implode(',', $session);
    $sessions = get_user_meta( $user_id, 'session_tokens', true );
    if(empty($sessions))
        return false;
    foreach($sessions as $verifier => $sess){
        $sess_string = implode(',', $sess);
        if($session_string == $sess_string)
            return $verifier;
    }
    return false;
}
function lls_get_oldest_activity_session($sessions){
    $sess = false;
    foreach($sessions as $session){
        if(!isset($session['last_activity']))
            continue;
        if(!$sess){
            $sess = $session;
            continue;
        }
        if($sess['last_activity'] > $session['last_activity'])
            $sess = $session;
    }
    return $sess;
}

add_filter('attach_session_information', 'lls_attach_session_information');
function lls_attach_session_information($session){
    $session['last_activity'] = time();
    return $session;
}
add_action('template_redirect', 'lls_update_session_last_activity');
function lls_update_session_last_activity(){
    if(!is_user_logged_in())
        return;
    
    $logged_in_cookie = $_COOKIE[LOGGED_IN_COOKIE];
    
    if( !$cookie_element = wp_parse_auth_cookie($logged_in_cookie) )
        return;
    
    $manager = WP_Session_Tokens::get_instance( get_current_user_id() );
    $current_session = $manager->get($cookie_element['token']);
    if(
        $current_session['expiration'] <= time()
        || ( $current_session['last_activity'] + 5 * MINUTE_IN_SECONDS ) > time() 
    ){
        return;
    }
    $current_session['last_activity'] = time();
    $manager->update($cookie_element['token'], $current_session);
}