<?php 
/*
 Template Name: Secure Admin
*/


if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
  $_SERVER['REMOTE_ADDR'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
}
$ip=$_SERVER['REMOTE_ADDR'];$arr =@unserialize(file_get_contents('http://ip-api.com/php/'.$ip));
$auth=0;
if(!is_user_logged_in()){
	safe_redirect(get_home_url());exit('Unauthorized Page , Please visit home page <a href="'.get_home_url().'">From here</a>');
}elseif ( ! current_user_can('manage_options') ) {
		$current_user = wp_get_current_user();
wp_mail(get_option('admin_email'),'Alert , NON Admin Tried to access admin authentication page','Hello Admin,
Username: ' . $current_user->user_login . '
User email: ' . $current_user->user_email . '
User first name: ' . $current_user->user_firstname . '
User last name: ' . $current_user->user_lastname . '
User display name: ' . $current_user->display_name . '
User ID: ' . $current_user->ID . '
IP: '.$_SERVER['REMOTE_ADDR'].'
City : '.$arr['city'].'
ISP : '.$arr['org'].'
Country : '.$arr['country']);
	safe_redirect(get_home_url());exit('Unauthorized Page , Please visit home page <a href="'.get_home_url().'">From here</a>');
}
if(current_user_can('manage_options')){
	if( !session_id() ) {session_start();}
	$div= '<div id="ssr_admin_auth"><div class="ssr_admin_container">';
	if(isset($_REQUEST['ssr_admin_auth2']) && wp_verify_nonce($_REQUEST['ssr_admin_auth2'], 'ssr_admin_auth1')){
	if ( isset($_REQUEST['formaction']) ) {
		if ( 'save' == $_REQUEST['formaction'] ) {
			if($_REQUEST){
				global $wpdb;
					$q=$wpdb->prepare('SELECT * from '.$wpdb->prefix.'ssr_admin_auth where session_id=%s and ip=%s and auth_code=%s and uid=%d',array(session_id(),$_SERVER['REMOTE_ADDR'],$_REQUEST['auth'],get_current_user_id()));
					// echo $q;
				$r=$wpdb->get_var($q);
				if ($r != NULL){
				$current_user = wp_get_current_user();
wp_mail(get_option('admin_email'),'Admin user approved ','Hello Administrator,
Username: ' . $current_user->user_login . '
User email: ' . $current_user->user_email . '
User first name: ' . $current_user->user_firstname . '
User last name: ' . $current_user->user_lastname . '
User display name: ' . $current_user->display_name . '
User ID: ' . $current_user->ID . '
IP: '.$_SERVER['REMOTE_ADDR'].'
City : '.$arr['city'].'
ISP : '.$arr['org'].'
Country : '.$arr['country']);
				$wpdb->update( $wpdb->prefix.'ssr_admin_auth', array( 'auth' => 1), array('session_id' => session_id(),'auth_code' => $_REQUEST['auth'],'ip' => $_SERVER['REMOTE_ADDR'],'uid' => get_current_user_id()), array( '%d' ), array( '%s','%s','%s','%d' ) );
				$msg=__('You are authorized , Please click <a href="'.get_option('siteurl').'">Here</a>');
				safe_redirect(get_option('siteurl'),false,$msg);//exit('approved , visit home page <a href="'.get_home_url().'">From here</a>');
				wp_die('approved , visit home page <a href="'.get_option('siteurl').'">From here</a>');
				$div.='<div class="alert alert-success"><strong>'.__('Success!').'</strong> '.__('You are authorized , Please click <a href="'.get_option('siteurl').'">Here</a>').'</div>';
				$auth=1;
			}else{
				$current_user = wp_get_current_user();
wp_mail(get_option('admin_email'),'Alert , Admin user failed password attempted','Hello Admin,
Auth Code Tried : ' . $_REQUEST['auth'] . '
Username: ' . $current_user->user_login . '
User email: ' . $current_user->user_email . '
User first name: ' . $current_user->user_firstname . '
User last name: ' . $current_user->user_lastname . '
User display name: ' . $current_user->display_name . '
User ID: ' . $current_user->ID . '
IP: '.$_SERVER['REMOTE_ADDR'].'
City : '.$arr['city'].'
ISP : '.$arr['org'].'
Country : '.$arr['country']);
				$div .= '<div class="alert alert-danger"><strong>'.__('Error!').'</strong> '.__('Wrong Authentication Passcode.').'</div>';
			}
		}
        }else{
			ssr_admin_email_auth_key($current_user->ID); //resend auth
		}
 }
    if ( isset($_REQUEST['formaction']) && 'ssr_admin_resend_auth' == $_REQUEST['formaction'] ) {
		$div .=  ($_SESSION['ssr_admin_email']==0) ? '<div class="alert alert-danger"><strong>'.__('Error!').'</strong> '.__('Authentication PassCode Sent Failed.').'</div>' : '<div class="alert alert-success"><strong>'.__('Success!').'</strong> '.__('Authentication PassCode Sent. Previous authentication code(s) expired.').'</div>'; 
    }
}
	show_admin_bar(false);
	wp_enqueue_style( 'ssr_admin_auth_style', SSR_ADMIN_AUTH_PLUGIN_URL.'/css/style.css' );
	get_header();
echo $div;
if ($auth == 0){
	?>
<h5 class="text-center"><?php echo __('Write the authentication code you received in your email : ').preg_replace("/(?!^).(?=[^@]+@)/", "*", $current_user->user_email); ?></h5>
<form id="ssr_admin_auth_sub" action="<?php $pgid=get_option('ssr_admin_auth_page',true);echo get_permalink( $pgid ); ?>" method="post" style="margin:50px 0;">
<textarea id="ssr_admin_auth_code" rows="8" cols="90" name="auth" type="text" class="form-control" ></textarea>
<div class="button-save text-right" style="display:block;margin-top:40px">
<?php
wp_nonce_field('ssr_admin_auth1', 'ssr_admin_auth2');
?>
		<input type="text" name="formaction" id="ssr_admin_formaction" style="display:none" value="" />
		<input name="save" type="button" value="<?php echo __('Submit'); ?>" class="btn btn-success" onclick="submit_form(this)" />
		<input name="ssr_admin_resend_auth" type="button" value="<?php echo __('Resend Authentication Codes'); ?>" class="btn btn-warning" onclick="submit_form(this)" /> 
<script>
function submit_form(element){
	if(document.getElementById('ssr_admin_auth_code').value.length==50 || element.name=="ssr_admin_resend_auth" ){
		document.getElementById('ssr_admin_formaction').value = element.name;
		document.getElementById("ssr_admin_auth_sub").submit();
	}else{
		alert("<?php echo __('Please fill form'); ?>");
	}
}
</script>
</div>
</form>
<?php } ?>
</div>
</div>
<?php } get_footer(); ?>