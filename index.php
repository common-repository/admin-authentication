<?php
/*
Plugin Name: Admin Authentication
Plugin URI: http://
Description: The Admin Authentication system
Author: Saad Amin
Author URI: https://www.saadamin.com
Version: 1.4
*/

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'SSR_ADMIN_AUTH_PLUGIN_URL', untrailingslashit( plugins_url( '', __FILE__ ) ) );

	
include_once('class.php');
include_once('safe_redirect.php');


register_activation_hook( __FILE__, 'ssr_admin_auth_create_db' );
function ssr_admin_auth_create_db(){
	global $wpdb;$table_name=$wpdb->prefix.'ssr_admin_auth';
	if($wpdb->get_var("SHOW TABLES LIKE '$table_name'")!=$table_name){
	$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE $table_name (
		  id mediumint(9) NOT NULL AUTO_INCREMENT,
		  uid bigint(20) NOT NULL,
		  auth tinyint(1) NOT NULL,
		  ip varchar(55) DEFAULT '' NOT NULL,
		  session_id varchar(55) DEFAULT '' NOT NULL,
		  auth_code varchar(55) DEFAULT '' NOT NULL,
		  PRIMARY KEY  (id)
		) $charset_collate;";

		require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
		dbDelta( $sql );
	}
}
add_action('after_setup_theme', 'ssr_admin_auth_create_pages'); 
function ssr_admin_auth_create_pages(){
    $ssr_admin_auth_page = get_option("ssr_admin_auth_page");
    if (!$ssr_admin_auth_page) {
        $post1 = array(
            'post_title' => "Pure Auth",
            'post_content' => "",
            'post_status' => "publish",
            'post_type' => 'page',
        );
        $postID = wp_insert_post($post1);
        update_post_meta($postID, "_wp_page_template", "ssr_admin_auth_template.php");
        update_option("ssr_admin_auth_page", $postID);
		
	$post_url = get_permalink( $postID );
	$subject = 'Admin Authentication Page';

	$message = "A admin authentication page has been added on your website:\n\n";
	$message .= $post1['post_title'] . ": " . $post_url;

	// Send email to admin.
	wp_mail( get_option('admin_email'), $subject, $message );
    }
}

register_deactivation_hook( __FILE__, 'ssr_admin_auth_deactivate' );

function ssr_admin_auth_deactivate(){
	$p=get_option('ssr_admin_auth_page',true);
	wp_delete_post( $p, true);
	delete_option('ssr_admin_auth_page');
	 global $wpdb;
    $wpdb->query( "DROP TABLE IF EXISTS ".$wpdb->prefix."ssr_admin_auth" );
}

//restrict admin login
function ssr_admin_auth_res_login( $username ) {
    $user = get_user_by( 'login', $username );
	if(user_can( $user->ID, 'manage_options' )){
		ssr_admin_email_auth_key($user->ID);
	}
	
}
add_action( 'wp_authenticate', 'ssr_admin_auth_res_login', 99, 2);


function ssr_admin_email_auth_key($userid){
		if( !session_id() ) {session_start();}
		global $wpdb;
		if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
		  $_SERVER['REMOTE_ADDR'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
		}
		$ip=$_SERVER['REMOTE_ADDR'];$arr =@unserialize(file_get_contents('http://ip-api.com/php/'.$ip));
		$pass=wp_generate_password( 50,false,false );
		if (is_user_logged_in()) {$current_user = wp_get_current_user();$uid=get_current_user_id();}else{$current_user = get_user_by( 'id', $userid );}
		$wpdb->delete( $wpdb->prefix.'ssr_admin_auth', array( 'ip' => $ip, 'uid' => $userid, 'session_id' => session_id() ), array( '%s','%d','%s' ) );
		$id=$wpdb->insert($wpdb->prefix.'ssr_admin_auth',array('auth_code' => $pass,'ip' => $ip,'uid' => $userid , 'session_id' => session_id(), 'auth' => 0),array('%s','%s','%d','%s','%d'));
		// $_SESSION['LOGIN_TO']=$wpdb->insert_id;
		$headers = array('Content-Type: text/html; charset=UTF-8');
		$body='<!DOCTYPE HTML><html lang="en-US"><head><meta charset="UTF-8"><title></title></head><body>Hello '.$current_user->user_firstname.' '.$current_user->user_lastname.' ( '.$current_user->display_name.' ) ,<br>
		Your passcode is : <pre style="background-color: #eff0f1;padding: 5px;margin: .5em 0 1em 0;word-wrap: normal;color: #393318;font-size: 13px;max-height: 600px;"><code style="white-space: inherit;background-color: #eff0f1;padding: 0;">'.$pass.'</code></pre><br>
		IP: '.$_SERVER['REMOTE_ADDR'].'<br>City : '.$arr['city'].'<br>ISP : '.$arr['org'].'<br>Country : '.$arr['country'].'</body></html>';
		wp_mail($current_user->user_email,'Generated Admin auth Code ', $body , $headers);
		if (get_option('admin_email') != $current_user->user_email ){wp_mail(get_option('admin_email'),'Generated Admin auth Code for an admin user '.$current_user->user_login, $body , $headers);}
		($id==1) ? $_SESSION['ssr_admin_email']=$id : $_SESSION['ssr_admin_email']=0;
}
function ssr_admin_auth_must_su(){
if(!defined('DOING_AJAX') && is_user_logged_in() && current_user_can('manage_options')){
	if(!ssr_admin_is_authenticated()){
		$pgid=get_option('ssr_admin_auth_page',true);
		$page_url = get_permalink( $pgid );
		if (get_the_id() != $pgid || is_admin()) {
			safe_redirect($page_url);exit('Sorry , You are not authorized to visit this page. Please authorize yourself from <a href="'.$page_url.'">here</a>');
			// wp_safe_redirect($page_url);exit('Sorry , You are not authorized to visit this page. Please authorize yourself from <a href="'.$page_url.'">here</a>');
		}
	}
}
	
}
add_action( 'get_header','ssr_admin_auth_must_su' );
add_action( 'admin_init','ssr_admin_auth_must_su' );

function ssr_admin_is_authenticated(){
	if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
		$_SERVER['REMOTE_ADDR'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
	}
	global $wpdb;
	$q=$wpdb->prepare('SELECT auth from '.$wpdb->prefix.'ssr_admin_auth where session_id=%s and ip=%s and uid=%d',array(session_id(),$_SERVER['REMOTE_ADDR'],get_current_user_id()));
	$r=$wpdb->get_var($q);
	return ($r == 1) ? true : false;
}