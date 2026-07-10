<?php
defined('BASEPATH') OR exit('No direct script access allowed');

$config['fa_access_token_ttl'] = 3600;
$config['fa_refresh_token_ttl'] = 2592000;
$config['fa_max_bulk_attendance'] = 100;
$config['fa_max_bulk_system_logs'] = 200;
$config['fa_max_face_image_size_bytes'] = 5242880;
$config['fa_default_heartbeat_interval_seconds'] = 60;
$config['fa_default_sync_interval_minutes'] = 30;
$config['fa_default_max_offline_queue_size'] = 10000;
$config['fa_default_minimum_recognition_confidence'] = 0.80;
$config['fa_default_minimum_liveness_score'] = 0.70;
$config['fa_default_allowed_attendance_types'] = array('check_in', 'check_out');
$config['fa_default_minimum_app_version'] = '1.0.0';
$config['fa_default_force_sync'] = FALSE;
$config['fa_default_config_version'] = '1';
$config['fa_upload_path'] = FCPATH . 'uploads/face_attendance/';

// Ensure upload path exists when used at runtime (not creating here to avoid filesystem changes at install)
return $config;
