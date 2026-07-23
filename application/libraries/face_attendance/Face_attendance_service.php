<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Face_attendance_service
{
    protected $CI;
    protected $repo;
    protected $auth;
    protected $validator;

    public function __construct()
    {
        $this->CI =& get_instance();
        $this->CI->load->library('face_attendance/Face_attendance_repository');
        $this->CI->load->library('face_attendance/Face_attendance_auth');
        $this->CI->load->library('face_attendance/Face_attendance_validator');
        $this->repo = $this->CI->face_attendance_repository;
        $this->auth = $this->CI->face_attendance_auth;
        $this->validator = $this->CI->face_attendance_validator;
    }

    protected function ip_address()
    {
        return $this->CI->input->ip_address();
    }

    public function device_login($payload, $meta)
    {
        $start = microtime(true);

        // validate payload fields
        $rules = array(
            'device_id' => 'required|string',
            'device_code' => 'required|string',
            'device_secret' => 'required|string',
            'app_name' => 'string',
            'app_version' => 'string',
            'platform' => 'string',
            'hostname' => 'string'
        );

        $errors = $this->validator->validate($payload, $rules);
        if (!empty($errors)) {
            $this->log_request($meta, $payload['device_id'] ?? null, 422, 'VALIDATION_ERROR', $start);
            return array('status' => 422, 'error_code' => 'VALIDATION_ERROR', 'errors' => $errors);
        }

        $device = $this->repo->get_device_by_id_and_code($payload['device_id'], $payload['device_code']);
        if (!$device) {
            $this->log_request($meta, $payload['device_id'], 401, 'UNAUTHORIZED', $start);
            return array('status' => 401, 'error_code' => 'UNAUTHORIZED');
        }

        if (!isset($device['status']) || $device['status'] !== 'active') {
            $this->log_request($meta, $payload['device_id'], 403, 'DEVICE_INACTIVE', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_INACTIVE');
        }

        // verify secret
        if (!isset($device['device_secret_hash']) || !password_verify($payload['device_secret'], $device['device_secret_hash'])) {
            $this->log_request($meta, $payload['device_id'], 401, 'UNAUTHORIZED', $start);
            return array('status' => 401, 'error_code' => 'UNAUTHORIZED');
        }

        // create tokens
        $meta_token = array('ip' => $this->ip_address(), 'hostname' => $payload['hostname'] ?? null, 'platform' => $payload['platform'] ?? null, 'app_version' => $payload['app_version'] ?? null);
        $tokens = $this->auth->create_tokens_for_device($payload['device_id'], $meta_token);
        if (isset($tokens['error'])) {
            $this->log_request($meta, $payload['device_id'], 500, 'INTERNAL_ERROR', $start);
            return array('status' => 500, 'error_code' => 'INTERNAL_ERROR');
        }

        // update device info
        $this->repo->update_device_login_info($payload['device_id'], array('ip' => $this->ip_address(), 'hostname' => $payload['hostname'] ?? null, 'platform' => $payload['platform'] ?? null, 'app_version' => $payload['app_version'] ?? null, 'last_login_at' => date('Y-m-d H:i:s')));

        // create session
        $this->repo->create_device_session($payload['device_id'], array('type' => 'login', 'ip' => $this->ip_address(), 'meta' => json_encode($meta_token)));

        $this->log_request($meta, $payload['device_id'], 200, null, $start);

        // return raw tokens (only here)
        return array('status' => 200, 'data' => array('access_token' => $tokens['access_token'], 'refresh_token' => $tokens['refresh_token'], 'access_expires_at' => $tokens['access_expires_at'], 'refresh_expires_at' => $tokens['refresh_expires_at']));
    }

    public function device_refresh($payload, $meta)
    {
        $start = microtime(true);

        $rules = array(
            'device_id' => 'required|string',
            'refresh_token' => 'required|string'
        );
        $errors = $this->validator->validate($payload, $rules);
        if (!empty($errors)) {
            $this->log_request($meta, $payload['device_id'] ?? null, 422, 'VALIDATION_ERROR', $start);
            return array('status' => 422, 'error_code' => 'VALIDATION_ERROR', 'errors' => $errors);
        }

        $device = $this->repo->get_device_by_id($payload['device_id']);
        if (!$device) {
            $this->log_request($meta, $payload['device_id'], 401, 'UNAUTHORIZED', $start);
            return array('status' => 401, 'error_code' => 'UNAUTHORIZED');
        }
        if (!isset($device['status']) || $device['status'] !== 'active') {
            $this->log_request($meta, $payload['device_id'], 403, 'DEVICE_INACTIVE', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_INACTIVE');
        }

        // rotate refresh token
        $rot = $this->auth->rotate_refresh_token($payload['refresh_token'], $payload['device_id'], array('ip' => $this->ip_address()));
        if (!$rot['ok']) {
            $code = ($rot['error'] === 'TOKEN_EXPIRED') ? 'TOKEN_EXPIRED' : 'UNAUTHORIZED';
            $status = ($rot['error'] === 'TOKEN_EXPIRED') ? 401 : 401;
            $this->log_request($meta, $payload['device_id'], $status, $code, $start);
            return array('status' => $status, 'error_code' => $code);
        }

        // create session record
        $this->repo->create_device_session($payload['device_id'], array('type' => 'refresh', 'ip' => $this->ip_address(), 'meta' => json_encode(array('note' => 'token rotated'))));

        $this->log_request($meta, $payload['device_id'], 200, null, $start);

        return array('status' => 200, 'data' => array('access_token' => $rot['access_token'], 'refresh_token' => $rot['refresh_token'], 'access_expires_at' => $rot['access_expires_at'], 'refresh_expires_at' => $rot['refresh_expires_at']));
    }

    public function device_logout($device_id, $access_raw, $meta)
    {
        $start = microtime(true);

        if (empty($device_id) || empty($access_raw)) {
            $this->log_request($meta, $device_id, 401, 'UNAUTHORIZED', $start);
            return array('status' => 401, 'error_code' => 'UNAUTHORIZED');
        }

        $val = $this->auth->validate_access_token($access_raw, $device_id);
        if (!$val['ok']) {
            $code = ($val['error'] === 'TOKEN_EXPIRED') ? 'TOKEN_EXPIRED' : 'UNAUTHORIZED';
            $this->log_request($meta, $device_id, 401, $code, $start);
            return array('status' => 401, 'error_code' => $code);
        }

        $token = $val['token'];
        $this->repo->revoke_token($token['id']);
        $this->repo->create_device_session($device_id, array('type' => 'logout', 'ip' => $this->ip_address(), 'meta' => json_encode(array())));

        $this->log_request($meta, $device_id, 200, null, $start);
        return array('status' => 200, 'data' => array('message' => 'Logged out'));
    }

    public function device_profile($device_id, $access_raw, $meta)
    {
        $start = microtime(true);

        if (empty($device_id) || empty($access_raw)) {
            $this->log_request($meta, $device_id, 401, 'UNAUTHORIZED', $start);
            return array('status' => 401, 'error_code' => 'UNAUTHORIZED');
        }

        $val = $this->auth->validate_access_token($access_raw, $device_id);
        if (!$val['ok']) {
            $code = ($val['error'] === 'TOKEN_EXPIRED') ? 'TOKEN_EXPIRED' : 'UNAUTHORIZED';
            $this->log_request($meta, $device_id, 401, $code, $start);
            return array('status' => 401, 'error_code' => $code);
        }

        $device = $this->repo->get_device_by_id($device_id);
        if (!$device) {
            $this->log_request($meta, $device_id, 404, 'NOT_FOUND', $start);
            return array('status' => 404, 'error_code' => 'NOT_FOUND');
        }

        if (!isset($device['status']) || $device['status'] !== 'active') {
            $this->log_request($meta, $device_id, 403, 'DEVICE_INACTIVE', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_INACTIVE');
        }

        // remove sensitive fields
        unset($device['device_secret_hash']);

        $this->log_request($meta, $device_id, 200, null, $start);

        return array('status' => 200, 'data' => $device);
    }

    public function device_config($device_id, $access_raw, $header_device_id, $meta)
    {
        $start = microtime(true);

        if (empty($device_id) || empty($access_raw) || empty($header_device_id)) {
            $this->log_request($meta, $device_id, 401, 'UNAUTHORIZED', $start);
            return array('status' => 401, 'error_code' => 'UNAUTHORIZED');
        }

        if ($device_id !== $header_device_id) {
            $this->log_request($meta, $device_id, 403, 'DEVICE_FORBIDDEN', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_FORBIDDEN');
        }

        $val = $this->auth->validate_access_token($access_raw, $device_id);
        if (!$val['ok']) {
            $code = ($val['error'] === 'TOKEN_EXPIRED') ? 'TOKEN_EXPIRED' : 'UNAUTHORIZED';
            $this->log_request($meta, $device_id, 401, $code, $start);
            return array('status' => 401, 'error_code' => $code);
        }

        $device = $this->repo->get_device_by_id($device_id);
        if (!$device) {
            $this->log_request($meta, $device_id, 404, 'NOT_FOUND', $start);
            return array('status' => 404, 'error_code' => 'NOT_FOUND');
        }

        if (!isset($device['status']) || $device['status'] !== 'active') {
            $this->log_request($meta, $device_id, 403, 'DEVICE_INACTIVE', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_INACTIVE');
        }

        $config_row = $this->repo->get_device_config($device_id);
        $defaults = array(
            'heartbeat_interval_seconds' => (int) $this->CI->config->item('fa_default_heartbeat_interval_seconds', 'face_attendance'),
            'sync_interval_minutes' => (int) $this->CI->config->item('fa_default_sync_interval_minutes', 'face_attendance'),
            'minimum_recognition_confidence' => (float) $this->CI->config->item('fa_default_minimum_recognition_confidence', 'face_attendance'),
            'minimum_liveness_score' => (float) $this->CI->config->item('fa_default_minimum_liveness_score', 'face_attendance'),
            'allowed_attendance_types' => $this->CI->config->item('fa_default_allowed_attendance_types', 'face_attendance'),
            'max_offline_queue_size' => (int) $this->CI->config->item('fa_default_max_offline_queue_size', 'face_attendance'),
            'max_bulk_attendance' => (int) $this->CI->config->item('fa_max_bulk_attendance', 'face_attendance'),
            'minimum_app_version' => $this->CI->config->item('fa_default_minimum_app_version', 'face_attendance'),
            'force_sync' => (bool) $this->CI->config->item('fa_default_force_sync', 'face_attendance'),
            'config_version' => $this->CI->config->item('fa_default_config_version', 'face_attendance')
        );

        $response = array(
            'heartbeat_interval_seconds' => isset($config_row['heartbeat_interval_seconds']) ? (int) $config_row['heartbeat_interval_seconds'] : $defaults['heartbeat_interval_seconds'],
            'sync_interval_minutes' => isset($config_row['sync_interval_minutes']) ? (int) $config_row['sync_interval_minutes'] : $defaults['sync_interval_minutes'],
            'minimum_recognition_confidence' => isset($config_row['minimum_recognition_confidence']) ? (float) $config_row['minimum_recognition_confidence'] : $defaults['minimum_recognition_confidence'],
            'minimum_liveness_score' => isset($config_row['minimum_liveness_score']) ? (float) $config_row['minimum_liveness_score'] : $defaults['minimum_liveness_score'],
            'allowed_attendance_types' => isset($config_row['allowed_attendance_types']) ? $config_row['allowed_attendance_types'] : $defaults['allowed_attendance_types'],
            'max_offline_queue_size' => isset($config_row['max_offline_queue_size']) ? (int) $config_row['max_offline_queue_size'] : $defaults['max_offline_queue_size'],
            'max_bulk_attendance' => isset($config_row['max_bulk_attendance']) ? (int) $config_row['max_bulk_attendance'] : $defaults['max_bulk_attendance'],
            'minimum_app_version' => isset($config_row['minimum_app_version']) ? $config_row['minimum_app_version'] : $defaults['minimum_app_version'],
            'force_sync' => isset($config_row['force_sync']) ? (bool) $config_row['force_sync'] : $defaults['force_sync'],
            'config_version' => isset($config_row['config_version']) ? $config_row['config_version'] : $defaults['config_version']
        );

        $this->log_request($meta, $device_id, 200, null, $start);

        return array('status' => 200, 'data' => $response);
    }

    public function device_heartbeat($device_id, $access_raw, $header_device_id, $payload, $meta)
    {
        $start = microtime(true);

        if (empty($device_id) || empty($access_raw) || empty($header_device_id)) {
            $this->log_request($meta, $device_id, 401, 'UNAUTHORIZED', $start);
            return array('status' => 401, 'error_code' => 'UNAUTHORIZED');
        }

        if ($device_id !== $header_device_id) {
            $this->log_request($meta, $device_id, 403, 'DEVICE_FORBIDDEN', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_FORBIDDEN');
        }

        $rules = array(
            'app_version' => 'string',
            'sent_at' => 'string',
            'camera_status' => 'string',
            'network_status' => 'string',
            'api_status' => 'string',
            'queue_total' => 'integer',
            'queue_failed' => 'integer',
            'storage_free_mb' => 'numeric',
            'uptime_seconds' => 'integer'
        );
        $errors = $this->validator->validate($payload, $rules);
        if (!empty($errors)) {
            $this->log_request($meta, $device_id, 422, 'VALIDATION_ERROR', $start);
            return array('status' => 422, 'error_code' => 'VALIDATION_ERROR', 'errors' => $errors);
        }

        $val = $this->auth->validate_access_token($access_raw, $device_id);
        if (!$val['ok']) {
            $code = ($val['error'] === 'TOKEN_EXPIRED') ? 'TOKEN_EXPIRED' : 'UNAUTHORIZED';
            $this->log_request($meta, $device_id, 401, $code, $start);
            return array('status' => 401, 'error_code' => $code);
        }

        $device = $this->repo->get_device_by_id($device_id);
        if (!$device) {
            $this->log_request($meta, $device_id, 404, 'NOT_FOUND', $start);
            return array('status' => 404, 'error_code' => 'NOT_FOUND');
        }

        if (!isset($device['status']) || $device['status'] !== 'active') {
            $this->log_request($meta, $device_id, 403, 'DEVICE_INACTIVE', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_INACTIVE');
        }

        $this->repo->create_device_heartbeat($device_id, array(
            'app_version' => isset($payload['app_version']) ? $payload['app_version'] : null,
            'sent_at' => isset($payload['sent_at']) ? $payload['sent_at'] : null,
            'camera_status' => isset($payload['camera_status']) ? $payload['camera_status'] : null,
            'network_status' => isset($payload['network_status']) ? $payload['network_status'] : null,
            'api_status' => isset($payload['api_status']) ? $payload['api_status'] : null,
            'queue_total' => isset($payload['queue_total']) ? (int) $payload['queue_total'] : 0,
            'queue_failed' => isset($payload['queue_failed']) ? (int) $payload['queue_failed'] : 0,
            'storage_free_mb' => isset($payload['storage_free_mb']) ? (float) $payload['storage_free_mb'] : 0,
            'uptime_seconds' => isset($payload['uptime_seconds']) ? (int) $payload['uptime_seconds'] : 0,
            'created_at' => date('Y-m-d H:i:s')
        ));

        $this->repo->update_device_heartbeat_status($device_id, array(
            'last_heartbeat_at' => date('Y-m-d H:i:s'),
            'last_seen_at' => date('Y-m-d H:i:s'),
            'app_version' => isset($payload['app_version']) ? $payload['app_version'] : null,
            'ip' => $this->ip_address()
        ));

        $config_row = $this->repo->get_device_config($device_id);
        $interval = isset($config_row['heartbeat_interval_seconds']) ? (int) $config_row['heartbeat_interval_seconds'] : (int) $this->CI->config->item('fa_default_heartbeat_interval_seconds', 'face_attendance');
        $force_sync = isset($config_row['force_sync']) ? (bool) $config_row['force_sync'] : (bool) $this->CI->config->item('fa_default_force_sync', 'face_attendance');
        $config_version = isset($config_row['config_version']) ? $config_row['config_version'] : $this->CI->config->item('fa_default_config_version', 'face_attendance');

        $this->log_request($meta, $device_id, 200, null, $start);

        return array('status' => 200, 'data' => array(
            'next_heartbeat_interval_seconds' => $interval,
            'force_sync' => $force_sync,
            'server_time' => (new DateTime('now'))->format(DATE_ATOM),
            'config_version' => $config_version
        ));
    }

    public function employees_sync($device_id, $access_raw, $header_device_id, $query, $meta)
    {
        $start = microtime(true);

        if (empty($device_id) || empty($access_raw) || empty($header_device_id)) {
            $this->log_request($meta, $device_id, 401, 'UNAUTHORIZED', $start);
            return array('status' => 401, 'error_code' => 'UNAUTHORIZED');
        }

        if ($device_id !== $header_device_id) {
            $this->log_request($meta, $device_id, 403, 'DEVICE_FORBIDDEN', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_FORBIDDEN');
        }

        $val = $this->auth->validate_access_token($access_raw, $device_id);
        if (!$val['ok']) {
            $code = ($val['error'] === 'TOKEN_EXPIRED') ? 'TOKEN_EXPIRED' : 'UNAUTHORIZED';
            $this->log_request($meta, $device_id, 401, $code, $start);
            return array('status' => 401, 'error_code' => $code);
        }

        $device = $this->repo->get_device_by_id($device_id);
        if (!$device) {
            $this->log_request($meta, $device_id, 404, 'NOT_FOUND', $start);
            return array('status' => 404, 'error_code' => 'NOT_FOUND');
        }

        if (!isset($device['status']) || $device['status'] !== 'active') {
            $this->log_request($meta, $device_id, 403, 'DEVICE_INACTIVE', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_INACTIVE');
        }

        $last_sync_at = isset($query['last_sync_at']) ? $query['last_sync_at'] : null;
        $since = $last_sync_at;
        $active_employees = $this->repo->get_active_employees($since);
        $deleted_employees = $this->repo->get_deleted_employees($since);

        $items = array();
        foreach ($active_employees as $row) {
            $faces = $this->repo->get_employee_faces($row['id']);
            $item = array(
                'employee_code' => $row['employee_code'],
                'employee_name' => isset($row['employee_name']) ? $row['employee_name'] : null,
                'status' => 'active',
                'is_deleted' => 0,
                'deleted_at' => null,
                'change_type' => 'updated',
                'updated_at' => isset($row['updated_at']) ? $row['updated_at'] : null,
                'face_count' => count($faces),
                'face_ids' => array(),
                'face_version' => null,
                'image_path' => null,
                'needs_face_refresh' => false
            );
            if (!empty($faces)) {
                foreach ($faces as $face) {
                    $item['face_ids'][] = isset($face['face_id']) ? $face['face_id'] : null;
                }
                $item['face_version'] = isset($faces[0]['face_version']) ? $faces[0]['face_version'] : null;
                $item['image_path'] = isset($faces[0]['image_path']) ? $faces[0]['image_path'] : null;
                $item['needs_face_refresh'] = !empty($faces[0]['needs_face_refresh']);
            }
            $items[] = $item;
        }

        foreach ($deleted_employees as $row) {
            $items[] = array(
                'employee_code' => $row['employee_code'],
                'status' => 'deleted',
                'is_deleted' => 1,
                'deleted_at' => isset($row['deleted_at']) ? $row['deleted_at'] : null,
                'change_type' => 'deleted',
                'updated_at' => isset($row['updated_at']) ? $row['updated_at'] : null,
                'face_count' => 0,
                'face_ids' => array(),
                'face_version' => null,
                'image_path' => null,
                'needs_face_refresh' => false
            );
        }

        $sync_id = 'SYNC-' . date('Ymd') . '-' . sprintf('%06d', mt_rand(1, 999999));
        $sync_data = array(
            'sync_id' => $sync_id,
            'device_id' => $device_id,
            'requested_at' => date('Y-m-d H:i:s'),
            'status' => 'pending',
            'last_sync_at' => $last_sync_at,
            'total_items' => count($items),
            'created_items' => 0,
            'updated_items' => 0,
            'deleted_items' => 0,
            'acknowledged' => 0,
            'acknowledged_at' => null,
            'acknowledged_status' => null,
            'acknowledged_message' => null
        );
        $sync_id_db = $this->repo->create_employee_sync($device_id, $sync_data);
        if (!$sync_id_db) {
            $this->log_request($meta, $device_id, 500, 'INTERNAL_ERROR', $start);
            return array('status' => 500, 'error_code' => 'INTERNAL_ERROR');
        }

        foreach ($items as $item) {
            $change_type = isset($item['change_type']) ? $item['change_type'] : 'updated';
            $this->repo->create_employee_sync_item($sync_id, array(
                'employee_code' => isset($item['employee_code']) ? $item['employee_code'] : null,
                'status' => isset($item['status']) ? $item['status'] : 'active',
                'is_deleted' => isset($item['is_deleted']) ? (int) $item['is_deleted'] : 0,
                'deleted_at' => isset($item['deleted_at']) ? $item['deleted_at'] : null,
                'change_type' => $change_type,
                'updated_at' => isset($item['updated_at']) ? $item['updated_at'] : null,
                'payload' => json_encode($item),
                'acknowledged_status' => null,
                'acknowledged_message' => null,
                'created_at' => date('Y-m-d H:i:s')
            ));
        }

        $created = count($active_employees);
        $updated = count($active_employees);
        $deleted = count($deleted_employees);
        $this->repo->update_employee_sync($sync_id, array('created_items' => $created, 'updated_items' => $updated, 'deleted_items' => $deleted));

        $this->log_request($meta, $device_id, 200, null, $start);

        return array('status' => 200, 'data' => array('sync_id' => $sync_id, 'server_time' => (new DateTime('now'))->format(DATE_ATOM), 'total' => count($items), 'created' => $created, 'updated' => $updated, 'deleted' => $deleted, 'items' => $items));
    }

    public function employees_sync_acknowledge($payload, $meta)
    {
        $start = microtime(true);
        $rules = array(
            'device_id' => 'required|string',
            'sync_id' => 'required|string',
            'synced_at' => 'required|string',
            'total' => 'integer',
            'created' => 'integer',
            'updated' => 'integer',
            'deleted' => 'integer',
            'failed' => 'integer',
            'items' => 'array'
        );
        $errors = $this->validator->validate($payload, $rules);
        if (!empty($errors)) {
            $this->log_request($meta, isset($payload['device_id']) ? $payload['device_id'] : null, 422, 'VALIDATION_ERROR', $start);
            return array('status' => 422, 'error_code' => 'VALIDATION_ERROR', 'errors' => $errors);
        }

        $sync = $this->repo->get_employee_sync($payload['sync_id']);
        if (!$sync) {
            $this->log_request($meta, isset($payload['device_id']) ? $payload['device_id'] : null, 404, 'NOT_FOUND', $start);
            return array('status' => 404, 'error_code' => 'NOT_FOUND');
        }

        if (!isset($sync['device_id']) || $sync['device_id'] !== $payload['device_id']) {
            $this->log_request($meta, isset($payload['device_id']) ? $payload['device_id'] : null, 403, 'DEVICE_FORBIDDEN', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_FORBIDDEN');
        }

        $ack_status = 'acknowledged';
        if (isset($payload['failed']) && (int) $payload['failed'] > 0) {
            $ack_status = 'partial';
        }

        $this->repo->update_employee_sync($payload['sync_id'], array(
            'acknowledged' => 1,
            'acknowledged_at' => date('Y-m-d H:i:s'),
            'acknowledged_status' => $ack_status,
            'acknowledged_message' => null,
            'status' => $ack_status,
            'acknowledged_payload' => json_encode($payload)
        ));

        if (isset($payload['items']) && is_array($payload['items'])) {
            foreach ($payload['items'] as $item) {
                if (!isset($item['employee_code'])) {
                    continue;
                }
                $this->repo->update_employee_sync_item($payload['sync_id'], $item['employee_code'], array(
                    'acknowledged_status' => isset($item['status']) ? $item['status'] : 'success',
                    'acknowledged_message' => isset($item['message']) ? $item['message'] : null,
                    'updated_at' => date('Y-m-d H:i:s')
                ));
            }
        }

        $this->log_request($meta, isset($payload['device_id']) ? $payload['device_id'] : null, 200, null, $start);
        return array('status' => 200, 'data' => array('sync_id' => $payload['sync_id'], 'status' => $ack_status));
    }

    public function employees_create($device_id, $access_raw, $header_device_id, $payload, $meta)
    {
        $start = microtime(true);

        if (empty($device_id) || empty($access_raw) || empty($header_device_id)) {
            $this->log_request($meta, $device_id, 401, 'UNAUTHORIZED', $start);
            return array('status' => 401, 'error_code' => 'UNAUTHORIZED');
        }

        if ($device_id !== $header_device_id) {
            $this->log_request($meta, $device_id, 403, 'DEVICE_FORBIDDEN', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_FORBIDDEN');
        }

        $allowed = array('employee_code', 'employee_name', 'status', 'source', 'client_reference_id');
        $filtered = array();
        foreach ($allowed as $field) {
            if (array_key_exists($field, $payload)) {
                $filtered[$field] = $payload[$field];
            }
        }

        $rules = array(
            'employee_code' => 'required|string',
            'employee_name' => 'required|string',
            'status' => 'required|enum:active,inactive,deleted',
            'source' => 'required|string',
            'client_reference_id' => 'string'
        );
        $errors = $this->validator->validate($filtered, $rules);
        if (!empty($errors)) {
            $this->log_request($meta, $device_id, 422, 'VALIDATION_ERROR', $start);
            return array('status' => 422, 'error_code' => 'VALIDATION_ERROR', 'errors' => $errors);
        }

        $val = $this->auth->validate_access_token($access_raw, $device_id);
        if (!$val['ok']) {
            $code = ($val['error'] === 'TOKEN_EXPIRED') ? 'TOKEN_EXPIRED' : 'UNAUTHORIZED';
            $this->log_request($meta, $device_id, 401, $code, $start);
            return array('status' => 401, 'error_code' => $code);
        }

        $device = $this->repo->get_device_by_id($device_id);
        if (!$device) {
            $this->log_request($meta, $device_id, 404, 'NOT_FOUND', $start);
            return array('status' => 404, 'error_code' => 'NOT_FOUND');
        }

        if (!isset($device['status']) || $device['status'] !== 'active') {
            $this->log_request($meta, $device_id, 403, 'DEVICE_INACTIVE', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_INACTIVE');
        }

        $existing = $this->repo->get_employee_by_code($filtered['employee_code']);
        if ($existing) {
            $this->log_request($meta, $device_id, 409, 'DUPLICATE_EMPLOYEE', $start);
            return array('status' => 409, 'error_code' => 'DUPLICATE_EMPLOYEE');
        }

        $this->repo->begin();
        try {
            $employee_id = $this->repo->create_employee(array(
                'employee_code' => $filtered['employee_code'],
                'employee_name' => $filtered['employee_name'],
                'status' => $filtered['status'],
                'source' => $filtered['source'],
                'client_reference_id' => isset($filtered['client_reference_id']) ? $filtered['client_reference_id'] : null,
                'is_deleted' => 0,
                'deleted_at' => null
            ));
            // Bug fix: CI3 does not throw PHP Exception on query failure when db_debug=FALSE.
            // Must check trans_status() explicitly to detect a failed INSERT.
            if ($this->CI->db->trans_status() === FALSE) {
                throw new Exception('DB insert failed (trans_status=FALSE)');
            }
            $this->repo->commit();
            $this->log_request($meta, $device_id, 200, null, $start);
            return array('status' => 200, 'data' => array('employee_code' => $filtered['employee_code'], 'employee_id' => $employee_id));
        } catch (Exception $e) {
            $this->repo->rollback();
            log_message('error', 'Create employee failed: ' . $e->getMessage());
            $this->log_request($meta, $device_id, 500, 'INTERNAL_ERROR', $start);
            return array('status' => 500, 'error_code' => 'INTERNAL_ERROR');
        }
    }

    public function employee_faces_create($employee_code, $device_id, $access_raw, $header_device_id, $payload, $meta)
    {
        $start = microtime(true);

        if (empty($device_id) || empty($access_raw) || empty($header_device_id)) {
            $this->log_request($meta, $device_id, 401, 'UNAUTHORIZED', $start);
            return array('status' => 401, 'error_code' => 'UNAUTHORIZED');
        }

        if ($device_id !== $header_device_id) {
            $this->log_request($meta, $device_id, 403, 'DEVICE_FORBIDDEN', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_FORBIDDEN');
        }

        $val = $this->auth->validate_access_token($access_raw, $device_id);
        if (!$val['ok']) {
            $code = ($val['error'] === 'TOKEN_EXPIRED') ? 'TOKEN_EXPIRED' : 'UNAUTHORIZED';
            $this->log_request($meta, $device_id, 401, $code, $start);
            return array('status' => 401, 'error_code' => $code);
        }

        $allowed = array('face_id', 'face_version', 'image_base64', 'embedding', 'embedding_model', 'captured_at', 'source', 'is_primary');
        $filtered = array();
        foreach ($allowed as $field) {
            if (array_key_exists($field, $payload)) {
                $filtered[$field] = $payload[$field];
            }
        }

        $rules = array(
            'face_id' => 'required|string',
            'face_version' => 'required|integer',
            'embedding_model' => 'string',
            'captured_at' => 'string',
            'source' => 'string',
            'is_primary' => 'integer'
        );
        $errors = $this->validator->validate($filtered, $rules);
        if (!empty($errors)) {
            $this->log_request($meta, $device_id, 422, 'VALIDATION_ERROR', $start);
            return array('status' => 422, 'error_code' => 'VALIDATION_ERROR', 'errors' => $errors);
        }

        $has_image = !empty($filtered['image_base64']);
        $has_embedding = !empty($filtered['embedding']) && is_array($filtered['embedding']);
        if (!$has_image && !$has_embedding) {
            $this->log_request($meta, $device_id, 422, 'VALIDATION_ERROR', $start);
            return array('status' => 422, 'error_code' => 'VALIDATION_ERROR', 'errors' => array('image_base64' => array('At least one of image_base64 or embedding is required')));
        }

        $employee = $this->repo->get_employee_by_code($employee_code);
        if (!$employee || isset($employee['is_deleted']) && (int) $employee['is_deleted'] === 1) {
            $this->log_request($meta, $device_id, 404, 'NOT_FOUND', $start);
            return array('status' => 404, 'error_code' => 'NOT_FOUND');
        }

        if ($this->repo->get_face_by_id($filtered['face_id'])) {
            $this->log_request($meta, $device_id, 409, 'DUPLICATE_FACE', $start);
            return array('status' => 409, 'error_code' => 'DUPLICATE_FACE');
        }

        $upload_root = rtrim($this->CI->config->item('fa_upload_path', 'face_attendance'), '/') . '/faces/';
        $employee_dir = $upload_root . $employee_code . '/';
        if (!is_dir($employee_dir)) {
            if (!mkdir($employee_dir, 0755, true) && !is_dir($employee_dir)) {
                $this->log_request($meta, $device_id, 500, 'INTERNAL_ERROR', $start);
                return array('status' => 500, 'error_code' => 'INTERNAL_ERROR');
            }
        }

        $relative_path = 'uploads/face_attendance/faces/' . $employee_code . '/';
        $stored_path = null;
        $image_hash = null;
        $mime = null;
        $width = null;
        $height = null;
        $size_bytes = null;

        if ($has_image) {
            $image_data = $filtered['image_base64'];
            $matches = array();
            if (preg_match('/^data:(image\/(jpeg|png));base64,(.+)$/i', $image_data, $matches)) {
                $mime = strtolower($matches[1]);
                $image_binary = base64_decode($matches[3], true);
                if ($image_binary === false) {
                    $this->log_request($meta, $device_id, 422, 'VALIDATION_ERROR', $start);
                    return array('status' => 422, 'error_code' => 'VALIDATION_ERROR', 'errors' => array('image_base64' => array('Invalid base64 image data')));
                }
                $size_bytes = strlen($image_binary);
                $max = (int) $this->CI->config->item('fa_max_face_image_size_bytes', 'face_attendance');
                if ($size_bytes > $max) {
                    $this->log_request($meta, $device_id, 422, 'VALIDATION_ERROR', $start);
                    return array('status' => 422, 'error_code' => 'VALIDATION_ERROR', 'errors' => array('image_base64' => array('Image exceeds configured size limit')));
                }
                if ($mime === 'image/jpeg') {
                    $img = @imagecreatefromstring($image_binary);
                } else {
                    $img = @imagecreatefromstring($image_binary);
                }
                if ($img === false) {
                    $this->log_request($meta, $device_id, 422, 'VALIDATION_ERROR', $start);
                    return array('status' => 422, 'error_code' => 'VALIDATION_ERROR', 'errors' => array('image_base64' => array('Unable to decode image')));
                }
                $width = imagesx($img);
                $height = imagesy($img);
                imagedestroy($img);
                $image_hash = hash('sha256', $image_binary);
                $filename = $filtered['face_id'] . '_' . time() . '.' . (($mime === 'image/png') ? 'png' : 'jpg');
                $stored_path = $relative_path . $filename;
                $full_path = $employee_dir . $filename;
                $written = file_put_contents($full_path, $image_binary);
                if ($written === false) {
                    $this->log_request($meta, $device_id, 500, 'INTERNAL_ERROR', $start);
                    return array('status' => 500, 'error_code' => 'INTERNAL_ERROR');
                }
            } else {
                $this->log_request($meta, $device_id, 422, 'VALIDATION_ERROR', $start);
                return array('status' => 422, 'error_code' => 'VALIDATION_ERROR', 'errors' => array('image_base64' => array('Image must be a valid data URL')));
            }
        }

        $this->repo->begin();
        try {
            if (!empty($filtered['is_primary']) && (int) $filtered['is_primary'] === 1) {
                $this->repo->clear_primary_face($employee['id']);
            }
            $face_id = $this->repo->create_face(array(
                'employee_id' => $employee['id'],
                'face_id' => $filtered['face_id'],
                'face_version' => isset($filtered['face_version']) ? (int) $filtered['face_version'] : 1,
                'image_path' => $stored_path,
                'image_hash' => $image_hash,
                'embedding' => is_array(isset($filtered['embedding']) ? $filtered['embedding'] : null) ? json_encode($filtered['embedding']) : null,
                'embedding_model' => isset($filtered['embedding_model']) ? $filtered['embedding_model'] : null,
                'embedding_dimensions' => is_array(isset($filtered['embedding']) ? $filtered['embedding'] : null) ? count($filtered['embedding']) : null,
                'image_mime' => $mime,
                'image_width' => $width,
                'image_height' => $height,
                'image_size_bytes' => $size_bytes,
                'captured_at' => isset($filtered['captured_at']) ? $filtered['captured_at'] : null,
                'source' => isset($filtered['source']) ? $filtered['source'] : null,
                'status' => 'active',
                'is_primary' => isset($filtered['is_primary']) ? (int) $filtered['is_primary'] : 0,
                'is_deleted' => 0,
                'deleted_at' => null
            ));
            // Bug fix: CI3 does not throw PHP Exception on query failure when db_debug=FALSE.
            if ($this->CI->db->trans_status() === FALSE) {
                throw new Exception('DB insert failed (trans_status=FALSE)');
            }
            $this->repo->commit();
            $this->log_request($meta, $device_id, 200, null, $start);
            return array('status' => 200, 'data' => array('face_id' => $filtered['face_id'], 'image_path' => $stored_path));
        } catch (Exception $e) {
            $this->repo->rollback();
            if ($stored_path && is_file($employee_dir . basename($stored_path))) {
                @unlink($employee_dir . basename($stored_path));
            }
            log_message('error', 'Create employee face failed: ' . $e->getMessage());
            $this->log_request($meta, $device_id, 500, 'INTERNAL_ERROR', $start);
            return array('status' => 500, 'error_code' => 'INTERNAL_ERROR');
        }
    }

    protected function log_request(
        $meta, $device_id, $http_status,
        $error_code = null, $start_time = null,
        $request_payload = null, $response_payload = null
    ) {
        $duration = null;
        if ($start_time !== null) {
            $duration = round((microtime(true) - $start_time) * 1000); // ms
        }
        $row = array(
            'request_id'       => isset($meta['request_id']) ? $meta['request_id'] : null,
            'device_id'        => $device_id,
            'endpoint'         => isset($meta['endpoint']) ? $meta['endpoint'] : null,
            'http_method'      => isset($meta['method']) ? $meta['method'] : null,
            'http_status'      => $http_status,
            'error_code'       => $error_code,
            'ip'               => $this->ip_address(),
            'duration_ms'      => $duration,
            // Only store sanitized payloads - callers must strip tokens/base64 before passing
            'request_payload'  => ($request_payload !== null) ? json_encode($request_payload) : null,
            'response_payload' => ($response_payload !== null) ? json_encode($response_payload) : null
        );
        $this->repo->log_api_request($row);
    }

    // ===========================================================================
    // ATTENDANCE
    // ===========================================================================

    /**
     * Record a single attendance event from a device.
     *
     * @param string $header_device_id  Value of X-Device-ID header
     * @param string $access_raw        Raw bearer token string
     * @param array  $payload           Decoded JSON body
     * @param array  $meta              Request metadata (request_id, endpoint, method)
     * @return array {status, data} or {status, error_code, [errors]}
     */
    public function attendances_create($header_device_id, $access_raw, $payload, $meta)
    {
        $start = microtime(true);

        // ------------------------------------------------------------------
        // 1. Preliminary presence checks
        // ------------------------------------------------------------------
        if (empty($header_device_id) || empty($access_raw)) {
            $this->log_request($meta, $header_device_id, 401, 'UNAUTHORIZED', $start);
            return array('status' => 401, 'error_code' => 'UNAUTHORIZED');
        }

        // ------------------------------------------------------------------
        // 2. Payload field validation
        // ------------------------------------------------------------------
        $allowed = array(
            'attendance_id', 'employee_code', 'device_id', 'attendance_type',
            'attendance_at', 'recognition_confidence', 'liveness_score',
            'face_version', 'photo_base64', 'latitude', 'longitude',
            'source', 'request_id'
        );
        $filtered = array();
        foreach ($allowed as $field) {
            if (array_key_exists($field, $payload)) {
                $filtered[$field] = $payload[$field];
            }
        }

        $rules = array(
            'attendance_id'           => 'required|string',
            'employee_code'           => 'required|string',
            'device_id'               => 'required|string',
            'attendance_type'         => 'required|enum:check_in,check_out,break_out,break_in',
            'attendance_at'           => 'required|string',
            'recognition_confidence'  => 'score',
            'liveness_score'          => 'score',
            'face_version'            => 'integer',
            'source'                  => 'string',
            'request_id'              => 'string'
        );
        $errors = $this->validator->validate($filtered, $rules);
        if (!empty($errors)) {
            $this->_log_attendance_event(
                isset($filtered['attendance_id']) ? $filtered['attendance_id'] : null,
                $header_device_id,
                isset($filtered['employee_code']) ? $filtered['employee_code'] : null,
                'rejected', 'VALIDATION_ERROR',
                isset($meta['request_id']) ? $meta['request_id'] : null,
                $start
            );
            $this->log_request($meta, $header_device_id, 422, 'VALIDATION_ERROR', $start);
            return array('status' => 422, 'error_code' => 'VALIDATION_ERROR', 'errors' => $errors);
        }

        // ------------------------------------------------------------------
        // 3. device_id body must equal X-Device-ID header
        // ------------------------------------------------------------------
        if ($filtered['device_id'] !== $header_device_id) {
            $this->_log_attendance_event(
                $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                'rejected', 'DEVICE_MISMATCH',
                isset($filtered['request_id']) ? $filtered['request_id'] : null, $start
            );
            $this->log_request($meta, $header_device_id, 403, 'DEVICE_MISMATCH', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_MISMATCH');
        }

        // ------------------------------------------------------------------
        // 4. request_id body must equal X-Request-ID header (if header sent)
        // ------------------------------------------------------------------
        $header_request_id = isset($meta['request_id']) ? $meta['request_id'] : null;
        $body_request_id   = isset($filtered['request_id']) ? $filtered['request_id'] : null;
        if (!empty($body_request_id) && !empty($header_request_id) && $body_request_id !== $header_request_id) {
            $this->_log_attendance_event(
                $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                'rejected', 'REQUEST_ID_MISMATCH',
                $body_request_id, $start
            );
            $this->log_request($meta, $header_device_id, 422, 'REQUEST_ID_MISMATCH', $start);
            return array(
                'status' => 422, 'error_code' => 'REQUEST_ID_MISMATCH',
                'errors' => array('request_id' => array('request_id body must match X-Request-ID header'))
            );
        }
        // Prefer header request_id as the canonical one (already set in $meta['request_id'])
        $canonical_request_id = !empty($header_request_id) ? $header_request_id : $body_request_id;

        // ------------------------------------------------------------------
        // 5. Validate access token
        // ------------------------------------------------------------------
        $val = $this->auth->validate_access_token($access_raw, $header_device_id);
        if (!$val['ok']) {
            $code = ($val['error'] === 'TOKEN_EXPIRED') ? 'TOKEN_EXPIRED' : 'UNAUTHORIZED';
            $this->_log_attendance_event(
                $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                'rejected', $code, $canonical_request_id, $start
            );
            $this->log_request($meta, $header_device_id, 401, $code, $start);
            return array('status' => 401, 'error_code' => $code);
        }

        // ------------------------------------------------------------------
        // 6. Verify device exists and is active
        // ------------------------------------------------------------------
        $device = $this->repo->get_device_by_id($header_device_id);
        if (!$device) {
            $this->_log_attendance_event(
                $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                'rejected', 'NOT_FOUND', $canonical_request_id, $start
            );
            $this->log_request($meta, $header_device_id, 404, 'NOT_FOUND', $start);
            return array('status' => 404, 'error_code' => 'NOT_FOUND');
        }
        if (!isset($device['status']) || $device['status'] !== 'active') {
            $this->_log_attendance_event(
                $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                'rejected', 'DEVICE_INACTIVE', $canonical_request_id, $start
            );
            $this->log_request($meta, $header_device_id, 403, 'DEVICE_INACTIVE', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_INACTIVE');
        }

        // ------------------------------------------------------------------
        // 7. Idempotency: device_id + request_id already processed?
        // ------------------------------------------------------------------
        if (!empty($canonical_request_id)) {
            $existing_by_req = $this->repo->find_attendance_by_device_request(
                $header_device_id, $canonical_request_id
            );
            if ($existing_by_req) {
                // Already recorded — return existing data without creating a new record
                $this->_log_attendance_event(
                    $existing_by_req['attendance_id'], $header_device_id,
                    $existing_by_req['employee_code'],
                    'duplicate', 'IDEMPOTENT_REPLAY', $canonical_request_id, $start
                );
                $this->log_request($meta, $header_device_id, 200, 'IDEMPOTENT_REPLAY', $start);
                return array(
                    'status' => 200,
                    'data'   => $this->_format_attendance($existing_by_req)
                );
            }
        }

        // ------------------------------------------------------------------
        // 8. Duplicate attendance_id check
        // ------------------------------------------------------------------
        $existing_att = $this->repo->find_attendance_by_id($filtered['attendance_id']);
        if ($existing_att) {
            $this->_log_attendance_event(
                $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                'rejected', 'DUPLICATE_ATTENDANCE', $canonical_request_id, $start
            );
            $this->log_request($meta, $header_device_id, 409, 'DUPLICATE_ATTENDANCE', $start);
            return array('status' => 409, 'error_code' => 'DUPLICATE_ATTENDANCE');
        }

        // ------------------------------------------------------------------
        // 9. Verify employee exists, is active, and not deleted
        // ------------------------------------------------------------------
        $employee = $this->repo->get_employee_by_code($filtered['employee_code']);
        if (!$employee) {
            $this->_log_attendance_event(
                $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                'rejected', 'EMPLOYEE_NOT_FOUND', $canonical_request_id, $start
            );
            $this->log_request($meta, $header_device_id, 404, 'EMPLOYEE_NOT_FOUND', $start);
            return array('status' => 404, 'error_code' => 'EMPLOYEE_NOT_FOUND');
        }
        if (!empty($employee['is_deleted']) && (int) $employee['is_deleted'] === 1) {
            $this->_log_attendance_event(
                $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                'rejected', 'EMPLOYEE_DELETED', $canonical_request_id, $start
            );
            $this->log_request($meta, $header_device_id, 422, 'EMPLOYEE_DELETED', $start);
            return array('status' => 422, 'error_code' => 'EMPLOYEE_DELETED');
        }
        if (!isset($employee['status']) || $employee['status'] !== 'active') {
            $this->_log_attendance_event(
                $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                'rejected', 'EMPLOYEE_INACTIVE', $canonical_request_id, $start
            );
            $this->log_request($meta, $header_device_id, 422, 'EMPLOYEE_INACTIVE', $start);
            return array('status' => 422, 'error_code' => 'EMPLOYEE_INACTIVE');
        }

        // ------------------------------------------------------------------
        // 10. Handle optional photo_base64
        // ------------------------------------------------------------------
        $photo_path      = null;
        $photo_hash      = null;
        $photo_mime      = null;
        $photo_size_bytes = null;

        if (!empty($filtered['photo_base64'])) {
            $image_data = $filtered['photo_base64'];
            $matches    = array();
            if (preg_match('/^data:(image\/(jpeg|png));base64,(.+)$/i', $image_data, $matches)) {
                $photo_mime    = strtolower($matches[1]);
                $image_binary  = base64_decode($matches[3], true);
                if ($image_binary === false) {
                    $this->_log_attendance_event(
                        $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                        'rejected', 'INVALID_PHOTO', $canonical_request_id, $start
                    );
                    $this->log_request($meta, $header_device_id, 422, 'INVALID_PHOTO', $start);
                    return array(
                        'status' => 422, 'error_code' => 'INVALID_PHOTO',
                        'errors' => array('photo_base64' => array('Invalid base64 image data'))
                    );
                }
                $photo_size_bytes = strlen($image_binary);
                $max_size = (int) $this->CI->config->item('fa_max_face_image_size_bytes', 'face_attendance');
                if ($max_size > 0 && $photo_size_bytes > $max_size) {
                    $this->_log_attendance_event(
                        $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                        'rejected', 'PHOTO_TOO_LARGE', $canonical_request_id, $start
                    );
                    $this->log_request($meta, $header_device_id, 422, 'PHOTO_TOO_LARGE', $start);
                    return array(
                        'status' => 422, 'error_code' => 'PHOTO_TOO_LARGE',
                        'errors' => array('photo_base64' => array('Photo exceeds configured size limit'))
                    );
                }
                // Ensure upload directory exists
                $upload_root  = rtrim($this->CI->config->item('fa_upload_path', 'face_attendance'), '/') . '/attendances/';
                $att_dir      = $upload_root . $filtered['attendance_id'] . '/';
                if (!is_dir($att_dir)) {
                    if (!mkdir($att_dir, 0755, true) && !is_dir($att_dir)) {
                        $this->log_request($meta, $header_device_id, 500, 'INTERNAL_ERROR', $start);
                        return array('status' => 500, 'error_code' => 'INTERNAL_ERROR');
                    }
                }
                $ext         = ($photo_mime === 'image/png') ? 'png' : 'jpg';
                $filename    = 'photo_' . time() . '.' . $ext;
                $full_path   = $att_dir . $filename;
                $relative_dir = 'uploads/face_attendance/attendances/' . $filtered['attendance_id'] . '/';
                $photo_path  = $relative_dir . $filename;
                $photo_hash  = hash('sha256', $image_binary);

                if (file_put_contents($full_path, $image_binary) === false) {
                    $this->log_request($meta, $header_device_id, 500, 'INTERNAL_ERROR', $start);
                    return array('status' => 500, 'error_code' => 'INTERNAL_ERROR');
                }
            } else {
                $this->_log_attendance_event(
                    $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                    'rejected', 'INVALID_PHOTO', $canonical_request_id, $start
                );
                $this->log_request($meta, $header_device_id, 422, 'INVALID_PHOTO', $start);
                return array(
                    'status' => 422, 'error_code' => 'INVALID_PHOTO',
                    'errors' => array('photo_base64' => array('Photo must be a valid data URL (image/jpeg or image/png)'))
                );
            }
        }

        // ------------------------------------------------------------------
        // 11. Build attendance row and persist in a transaction
        // ------------------------------------------------------------------
        $now        = date('Y-m-d H:i:s');
        $att_row    = array(
            'attendance_id'          => $filtered['attendance_id'],
            'device_id'              => $header_device_id,
            'employee_code'          => $filtered['employee_code'],
            'attendance_type'        => $filtered['attendance_type'],
            // attendance_at: store device-reported time as-is
            'attendance_at'          => $filtered['attendance_at'],
            // recorded_at: always server time
            'recorded_at'            => $now,
            'recognition_confidence' => isset($filtered['recognition_confidence']) ? (float) $filtered['recognition_confidence'] : null,
            'liveness_score'         => isset($filtered['liveness_score'])         ? (float) $filtered['liveness_score']         : null,
            'face_version'           => isset($filtered['face_version'])           ? (int)   $filtered['face_version']           : null,
            'photo_path'             => $photo_path,
            'photo_hash'             => $photo_hash,
            'latitude'               => isset($filtered['latitude'])               ? (float) $filtered['latitude']               : null,
            'longitude'              => isset($filtered['longitude'])              ? (float) $filtered['longitude']              : null,
            'source'                 => isset($filtered['source'])                 ? $filtered['source']                         : null,
            'request_id'             => $canonical_request_id,
            'status'                 => 'accepted'
        );

        $this->repo->begin();
        try {
            $db_id = $this->repo->create_attendance($att_row);
            if ($db_id === false || $this->CI->db->trans_status() === FALSE) {
                throw new Exception('DB insert failed');
            }
            $this->repo->commit();
        } catch (Exception $e) {
            $this->repo->rollback();
            // If photo was written, remove it to keep filesystem consistent
            if ($photo_path && is_file(FCPATH . $photo_path)) {
                @unlink(FCPATH . $photo_path);
            }
            log_message('error', 'Create attendance failed: ' . $e->getMessage());
            $this->log_request($meta, $header_device_id, 500, 'INTERNAL_ERROR', $start);
            return array('status' => 500, 'error_code' => 'INTERNAL_ERROR');
        }

        // ------------------------------------------------------------------
        // 12. Write attendance audit log (outside transaction — best-effort)
        // ------------------------------------------------------------------
        $this->_log_attendance_event(
            $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
            'accepted', null, $canonical_request_id, $start
        );

        // ------------------------------------------------------------------
        // 13. Write API request log
        // ------------------------------------------------------------------
        $this->log_request($meta, $header_device_id, 200, null, $start);

        return array(
            'status' => 200,
            'data'   => $this->_format_attendance($att_row)
        );
    }

    /**
     * Retrieve a single attendance record by attendance_id.
     * Access is restricted to the device that created the record.
     *
     * @param string $attendance_id
     * @param string $header_device_id  Value of X-Device-ID header
     * @param string $access_raw        Raw bearer token string
     * @param array  $meta
     * @return array
     */
    public function attendances_detail($attendance_id, $header_device_id, $access_raw, $meta)
    {
        $start = microtime(true);

        // ------------------------------------------------------------------
        // 1. Preliminary checks
        // ------------------------------------------------------------------
        if (empty($header_device_id) || empty($access_raw)) {
            $this->log_request($meta, $header_device_id, 401, 'UNAUTHORIZED', $start);
            return array('status' => 401, 'error_code' => 'UNAUTHORIZED');
        }

        // ------------------------------------------------------------------
        // 2. Validate access token
        // ------------------------------------------------------------------
        $val = $this->auth->validate_access_token($access_raw, $header_device_id);
        if (!$val['ok']) {
            $code = ($val['error'] === 'TOKEN_EXPIRED') ? 'TOKEN_EXPIRED' : 'UNAUTHORIZED';
            $this->log_request($meta, $header_device_id, 401, $code, $start);
            return array('status' => 401, 'error_code' => $code);
        }

        // ------------------------------------------------------------------
        // 3. Verify device exists and is active
        // ------------------------------------------------------------------
        $device = $this->repo->get_device_by_id($header_device_id);
        if (!$device) {
            $this->log_request($meta, $header_device_id, 404, 'NOT_FOUND', $start);
            return array('status' => 404, 'error_code' => 'NOT_FOUND');
        }
        if (!isset($device['status']) || $device['status'] !== 'active') {
            $this->log_request($meta, $header_device_id, 403, 'DEVICE_INACTIVE', $start);
            return array('status' => 403, 'error_code' => 'DEVICE_INACTIVE');
        }

        // ------------------------------------------------------------------
        // 4. Find the attendance record
        // ------------------------------------------------------------------
        $attendance = $this->repo->find_attendance_by_id($attendance_id);
        if (!$attendance) {
            $this->log_request($meta, $header_device_id, 404, 'NOT_FOUND', $start);
            return array('status' => 404, 'error_code' => 'NOT_FOUND');
        }

        // ------------------------------------------------------------------
        // 5. Enforce device ownership
        //    Only the device that created the record may read it.
        // ------------------------------------------------------------------
        if ($attendance['device_id'] !== $header_device_id) {
            $this->log_request($meta, $header_device_id, 403, 'FORBIDDEN', $start);
            return array('status' => 403, 'error_code' => 'FORBIDDEN');
        }

        $this->log_request($meta, $header_device_id, 200, null, $start);
        return array(
            'status' => 200,
            'data'   => $this->_format_attendance($attendance)
        );
    }

    /**
     * Normalise an attendance row for API response.
     * Removes internal DB fields (id, created_at, updated_at).
     * Never exposes photo_hash or raw token data.
     */
    protected function _format_attendance($row)
    {
        return array(
            'attendance_id'          => isset($row['attendance_id'])          ? $row['attendance_id']          : null,
            'device_id'              => isset($row['device_id'])              ? $row['device_id']              : null,
            'employee_code'          => isset($row['employee_code'])          ? $row['employee_code']          : null,
            'attendance_type'        => isset($row['attendance_type'])        ? $row['attendance_type']        : null,
            'attendance_at'          => isset($row['attendance_at'])          ? $row['attendance_at']          : null,
            'recorded_at'            => isset($row['recorded_at'])            ? $row['recorded_at']            : null,
            'recognition_confidence' => isset($row['recognition_confidence']) ? (float) $row['recognition_confidence'] : null,
            'liveness_score'         => isset($row['liveness_score'])         ? (float) $row['liveness_score']         : null,
            'face_version'           => isset($row['face_version'])           ? (int)   $row['face_version']           : null,
            'photo_path'             => isset($row['photo_path'])             ? $row['photo_path']             : null,
            'latitude'               => isset($row['latitude'])               ? (float) $row['latitude']               : null,
            'longitude'              => isset($row['longitude'])              ? (float) $row['longitude']              : null,
            'source'                 => isset($row['source'])                 ? $row['source']                 : null,
            'request_id'             => isset($row['request_id'])             ? $row['request_id']             : null,
            'status'                 => isset($row['status'])                 ? $row['status']                 : null
        );
    }

    /**
     * Insert a record into fa_attendance_logs.
     * This is separate from the main transaction so audit log is always written.
     * IMPORTANT: must never log photo_base64, access_token, or refresh_token.
     * Maps inputs to the actual database table columns.
     *
     * @param string      $attendance_id
     * @param string      $device_id
     * @param string|null $employee_code
     * @param string      $status        accepted | rejected | duplicate
     * @param string|null $reason        Error code string or null
     * @param string|null $request_id
     * @param float       $start_time    microtime(true) at request start
     */
    protected function _log_attendance_event(
        $attendance_id, $device_id, $employee_code,
        $status, $reason, $request_id, $start_time
    ) {
        if (empty($attendance_id)) {
            return;
        }

        // Verify that the attendance_id exists in fa_attendances to satisfy the FK constraint.
        // If the attendance record does not exist (e.g. for rejected requests), we cannot write to fa_attendance_logs.
        $existing = $this->repo->find_attendance_by_id($attendance_id);
        if (!$existing) {
            log_message('debug', "Skipping fa_attendance_logs for $attendance_id: record does not exist in fa_attendances (Status: $status, Reason: $reason)");
            return;
        }

        $duration = round((microtime(true) - $start_time) * 1000);
        $context = array(
            'employee_code' => $employee_code,
            'reason'        => $reason,
            'request_id'    => $request_id,
            'duration_ms'   => $duration,
            'ip_address'    => $this->ip_address()
        );
        $this->repo->create_attendance_log(array(
            'attendance_id' => $attendance_id,
            'device_id'     => $device_id,
            'event_type'    => $status, // accepted | rejected | duplicate
            'status_before' => null,
            'status_after'  => $status,
            'message'       => $reason ? 'Rejection reason: ' . $reason : 'Attendance processed successfully',
            'context'       => json_encode($context)
        ));
    }

    /**
     * Process bulk attendance submissions.
     * Each item is processed within its own database transaction.
     * Returns statistics (total, accepted, duplicate, rejected) and individual item statuses.
     */
    public function attendances_bulk($header_device_id, $access_raw, $payload, $meta)
    {
        $start = microtime(true);

        // 1. Authorization check
        if (empty($header_device_id) || empty($access_raw)) {
            $this->log_request($meta, $header_device_id, 401, 'UNAUTHORIZED', $start, $payload);
            return array('status' => 401, 'error_code' => 'UNAUTHORIZED');
        }

        // Validate access token
        $val = $this->auth->validate_access_token($access_raw, $header_device_id);
        if (!$val['ok']) {
            $code = ($val['error'] === 'TOKEN_EXPIRED') ? 'TOKEN_EXPIRED' : 'UNAUTHORIZED';
            $this->log_request($meta, $header_device_id, 401, $code, $start, $payload);
            return array('status' => 401, 'error_code' => $code);
        }

        // Verify device exists and is active
        $device = $this->repo->get_device_by_id($header_device_id);
        if (!$device || !isset($device['status']) || $device['status'] !== 'active') {
            $status_code = !$device ? 404 : 403;
            $err_code = !$device ? 'NOT_FOUND' : 'DEVICE_INACTIVE';
            $this->log_request($meta, $header_device_id, $status_code, $err_code, $start, $payload);
            return array('status' => $status_code, 'error_code' => $err_code);
        }

        // 2. Entire body validation (batch validation)
        if (!is_array($payload) || empty($payload['batch_id']) || !isset($payload['items']) || !is_array($payload['items'])) {
            $this->log_request($meta, $header_device_id, 422, 'VALIDATION_ERROR', $start, $payload);
            return array(
                'status' => 422,
                'error_code' => 'VALIDATION_ERROR',
                'errors' => array('body' => array('Invalid bulk request format. batch_id and items array are required.'))
            );
        }

        $batch_id = $payload['batch_id'];
        $items = $payload['items'];
        $total_items = count($items);
        $max_bulk = (int) $this->CI->config->item('fa_max_bulk_attendance', 'face_attendance');

        if ($total_items > $max_bulk) {
            $this->log_request($meta, $header_device_id, 422, 'MAX_LIMIT_EXCEEDED', $start, $payload);
            return array(
                'status' => 422,
                'error_code' => 'MAX_LIMIT_EXCEEDED',
                'errors' => array('items' => array('Bulk items count exceeds maximum limit of ' . $max_bulk))
            );
        }

        if ($total_items === 0) {
            $this->log_request($meta, $header_device_id, 422, 'VALIDATION_ERROR', $start, $payload);
            return array(
                'status' => 422,
                'error_code' => 'VALIDATION_ERROR',
                'errors' => array('items' => array('Items list cannot be empty.'))
            );
        }

        // Process individual items
        $accepted = 0;
        $duplicate = 0;
        $rejected = 0;
        $results = array();

        $allowed_fields = array(
            'attendance_id', 'employee_code', 'device_id', 'attendance_type',
            'attendance_at', 'recognition_confidence', 'liveness_score',
            'face_version', 'photo_base64', 'latitude', 'longitude',
            'source', 'request_id'
        );

        $rules = array(
            'attendance_id'           => 'required|string',
            'employee_code'           => 'required|string',
            'device_id'               => 'required|string',
            'attendance_type'         => 'required|enum:check_in,check_out,break_out,break_in',
            'attendance_at'           => 'required|string',
            'recognition_confidence'  => 'score',
            'liveness_score'          => 'score',
            'face_version'            => 'integer',
            'source'                  => 'string',
            'request_id'              => 'string'
        );

        foreach ($items as $index => $item) {
            $item_start = microtime(true);
            if (!is_array($item)) {
                $rejected++;
                $results[] = array(
                    'index' => $index,
                    'status' => 'rejected',
                    'error_code' => 'INVALID_ITEM',
                    'errors' => array('item' => array('Item must be an object'))
                );
                continue;
            }

            // Filter fields
            $filtered = array();
            foreach ($allowed_fields as $f) {
                if (array_key_exists($f, $item)) {
                    $filtered[$f] = $item[$f];
                }
            }

            // 1. Validation
            $item_errors = $this->validator->validate($filtered, $rules);
            if (!empty($item_errors)) {
                $rejected++;
                $results[] = array(
                    'attendance_id' => isset($filtered['attendance_id']) ? $filtered['attendance_id'] : null,
                    'status' => 'rejected',
                    'error_code' => 'VALIDATION_ERROR',
                    'errors' => $item_errors
                );
                $this->_log_attendance_event(
                    isset($filtered['attendance_id']) ? $filtered['attendance_id'] : null,
                    $header_device_id,
                    isset($filtered['employee_code']) ? $filtered['employee_code'] : null,
                    'rejected', 'VALIDATION_ERROR',
                    isset($filtered['request_id']) ? $filtered['request_id'] : null,
                    $item_start
                );
                continue;
            }

            // 2. device_id mismatch check
            if ($filtered['device_id'] !== $header_device_id) {
                $rejected++;
                $results[] = array(
                    'attendance_id' => $filtered['attendance_id'],
                    'status' => 'rejected',
                    'error_code' => 'DEVICE_MISMATCH',
                    'errors' => array('device_id' => array('device_id must match X-Device-ID header'))
                );
                $this->_log_attendance_event(
                    $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                    'rejected', 'DEVICE_MISMATCH',
                    isset($filtered['request_id']) ? $filtered['request_id'] : null,
                    $item_start
                );
                continue;
            }

            // 3. Idempotency Check: duplicate device_id + request_id
            $item_request_id = isset($filtered['request_id']) ? $filtered['request_id'] : null;
            if (!empty($item_request_id)) {
                $existing_by_req = $this->repo->find_attendance_by_device_request($header_device_id, $item_request_id);
                if ($existing_by_req) {
                    $duplicate++;
                    $results[] = array(
                        'attendance_id' => $filtered['attendance_id'],
                        'status' => 'duplicate',
                        'error_code' => 'IDEMPOTENT_REPLAY',
                        'errors' => null
                    );
                    $this->_log_attendance_event(
                        $existing_by_req['attendance_id'], $header_device_id, $existing_by_req['employee_code'],
                        'duplicate', 'IDEMPOTENT_REPLAY', $item_request_id,
                        $item_start
                    );
                    continue;
                }
            }

            // 4. Duplicate attendance_id Check
            $existing_att = $this->repo->find_attendance_by_id($filtered['attendance_id']);
            if ($existing_att) {
                $duplicate++;
                $results[] = array(
                    'attendance_id' => $filtered['attendance_id'],
                    'status' => 'duplicate',
                    'error_code' => 'DUPLICATE_ATTENDANCE',
                    'errors' => null
                );
                $this->_log_attendance_event(
                    $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                    'duplicate', 'DUPLICATE_ATTENDANCE', $item_request_id,
                    $item_start
                );
                continue;
            }

            // 5. Verify employee exists and is active
            $employee = $this->repo->get_employee_by_code($filtered['employee_code']);
            if (!$employee) {
                $rejected++;
                $results[] = array(
                    'attendance_id' => $filtered['attendance_id'],
                    'status' => 'rejected',
                    'error_code' => 'EMPLOYEE_NOT_FOUND',
                    'errors' => array('employee_code' => array('Employee not found'))
                );
                $this->_log_attendance_event(
                    $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                    'rejected', 'EMPLOYEE_NOT_FOUND', $item_request_id,
                    $item_start
                );
                continue;
            }
            if (!empty($employee['is_deleted']) && (int) $employee['is_deleted'] === 1) {
                $rejected++;
                $results[] = array(
                    'attendance_id' => $filtered['attendance_id'],
                    'status' => 'rejected',
                    'error_code' => 'EMPLOYEE_DELETED',
                    'errors' => array('employee_code' => array('Employee is deleted'))
                );
                $this->_log_attendance_event(
                    $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                    'rejected', 'EMPLOYEE_DELETED', $item_request_id,
                    $item_start
                );
                continue;
            }
            if (!isset($employee['status']) || $employee['status'] !== 'active') {
                $rejected++;
                $results[] = array(
                    'attendance_id' => $filtered['attendance_id'],
                    'status' => 'rejected',
                    'error_code' => 'EMPLOYEE_INACTIVE',
                    'errors' => array('employee_code' => array('Employee is inactive'))
                );
                $this->_log_attendance_event(
                    $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                    'rejected', 'EMPLOYEE_INACTIVE', $item_request_id,
                    $item_start
                );
                continue;
            }

            // 6. Handle optional photo_base64
            $photo_path = null;
            $photo_hash = null;
            if (!empty($filtered['photo_base64'])) {
                $image_data = $filtered['photo_base64'];
                $matches = array();
                if (preg_match('/^data:(image\/(jpeg|png));base64,(.+)$/i', $image_data, $matches)) {
                    $photo_mime = strtolower($matches[1]);
                    $image_binary = base64_decode($matches[3], true);
                    if ($image_binary === false) {
                        $rejected++;
                        $results[] = array(
                            'attendance_id' => $filtered['attendance_id'],
                            'status' => 'rejected',
                            'error_code' => 'INVALID_PHOTO',
                            'errors' => array('photo_base64' => array('Invalid base64 image data'))
                        );
                        $this->_log_attendance_event(
                            $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                            'rejected', 'INVALID_PHOTO', $item_request_id,
                            $item_start
                        );
                        continue;
                    }
                    $photo_size_bytes = strlen($image_binary);
                    $max_size = (int) $this->CI->config->item('fa_max_face_image_size_bytes', 'face_attendance');
                    if ($max_size > 0 && $photo_size_bytes > $max_size) {
                        $rejected++;
                        $results[] = array(
                            'attendance_id' => $filtered['attendance_id'],
                            'status' => 'rejected',
                            'error_code' => 'PHOTO_TOO_LARGE',
                            'errors' => array('photo_base64' => array('Photo exceeds configured size limit'))
                        );
                        $this->_log_attendance_event(
                            $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                            'rejected', 'PHOTO_TOO_LARGE', $item_request_id,
                            $item_start
                        );
                        continue;
                    }
                    // Save photo
                    $upload_root = rtrim($this->CI->config->item('fa_upload_path', 'face_attendance'), '/') . '/attendances/';
                    $att_dir = $upload_root . $filtered['attendance_id'] . '/';
                    if (!is_dir($att_dir)) {
                        if (!mkdir($att_dir, 0755, true) && !is_dir($att_dir)) {
                            $rejected++;
                            $results[] = array(
                                'attendance_id' => $filtered['attendance_id'],
                                'status' => 'rejected',
                                'error_code' => 'INTERNAL_ERROR',
                                'errors' => array('photo_base64' => array('Failed to create upload directory'))
                            );
                            continue;
                        }
                    }
                    $ext = ($photo_mime === 'image/png') ? 'png' : 'jpg';
                    $filename = 'photo_' . time() . '.' . $ext;
                    $full_path = $att_dir . $filename;
                    $relative_dir = 'uploads/face_attendance/attendances/' . $filtered['attendance_id'] . '/';
                    $photo_path = $relative_dir . $filename;
                    $photo_hash = hash('sha256', $image_binary);

                    if (file_put_contents($full_path, $image_binary) === false) {
                        $rejected++;
                        $results[] = array(
                            'attendance_id' => $filtered['attendance_id'],
                            'status' => 'rejected',
                            'error_code' => 'INTERNAL_ERROR',
                            'errors' => array('photo_base64' => array('Failed to write photo file'))
                        );
                        continue;
                    }
                } else {
                    $rejected++;
                    $results[] = array(
                        'attendance_id' => $filtered['attendance_id'],
                        'status' => 'rejected',
                        'error_code' => 'INVALID_PHOTO',
                        'errors' => array('photo_base64' => array('Photo must be a valid data URL'))
                    );
                    $this->_log_attendance_event(
                        $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                        'rejected', 'INVALID_PHOTO', $item_request_id,
                        $item_start
                    );
                    continue;
                }
            }

            // Format nominal device timestamp to standard database DATETIME format
            $dt = date_create($filtered['attendance_at']);
            $attendance_at_db = $dt ? $dt->format('Y-m-d H:i:s') : null;

            // 7. Save to DB in transaction
            $att_row = array(
                'attendance_id'          => $filtered['attendance_id'],
                'device_id'              => $header_device_id,
                'employee_code'          => $filtered['employee_code'],
                'attendance_type'        => $filtered['attendance_type'],
                'attendance_at'          => $attendance_at_db,
                'recorded_at'            => date('Y-m-d H:i:s'),
                'recognition_confidence' => isset($filtered['recognition_confidence']) ? (float) $filtered['recognition_confidence'] : null,
                'liveness_score'         => isset($filtered['liveness_score']) ? (float) $filtered['liveness_score'] : null,
                'face_version'           => isset($filtered['face_version']) ? (int) $filtered['face_version'] : null,
                'photo_path'             => $photo_path,
                'photo_hash'             => $photo_hash,
                'latitude'               => isset($filtered['latitude']) ? (float) $filtered['latitude'] : null,
                'longitude'              => isset($filtered['longitude']) ? (float) $filtered['longitude'] : null,
                'source'                 => isset($filtered['source']) ? $filtered['source'] : null,
                'request_id'             => $item_request_id,
                'batch_id'               => $batch_id,
                'status'                 => 'accepted'
            );

            $this->repo->begin();
            try {
                $db_id = $this->repo->create_attendance($att_row);
                if ($db_id === false || $this->CI->db->trans_status() === FALSE) {
                    throw new Exception('DB insert failed');
                }
                $this->repo->commit();
                $accepted++;
                $results[] = array(
                    'attendance_id' => $filtered['attendance_id'],
                    'status' => 'accepted',
                    'error_code' => null,
                    'errors' => null
                );
                $this->_log_attendance_event(
                    $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                    'accepted', null, $item_request_id,
                    $item_start
                );
            } catch (Exception $e) {
                $this->repo->rollback();
                if ($photo_path && is_file(FCPATH . $photo_path)) {
                    @unlink(FCPATH . $photo_path);
                }
                $rejected++;
                $results[] = array(
                    'attendance_id' => $filtered['attendance_id'],
                    'status' => 'rejected',
                    'error_code' => 'INTERNAL_ERROR',
                    'errors' => array('db' => array($e->getMessage()))
                );
                $this->_log_attendance_event(
                    $filtered['attendance_id'], $header_device_id, $filtered['employee_code'],
                    'rejected', 'DATABASE_ERROR', $item_request_id,
                    $item_start
                );
            }
        }

        // Format Response
        $res_data = array(
            'batch_id' => $batch_id,
            'total' => $total_items,
            'accepted' => $accepted,
            'duplicate' => $duplicate,
            'rejected' => $rejected,
            'items' => $results
        );

        // Sanitize request payload for API log
        $clean_payload = $payload;
        if (isset($clean_payload['items'])) {
            foreach ($clean_payload['items'] as $idx => $item) {
                if (isset($item['photo_base64'])) {
                    $clean_payload['items'][$idx]['photo_base64'] = '[STRIPPED]';
                }
            }
        }
        $clean_response = array(
            'success' => true,
            'message' => 'Bulk attendance processed',
            'data' => $res_data,
            'error_code' => null
        );

        $this->log_request($meta, $header_device_id, 200, null, $start, $clean_payload, $clean_response);

        return array(
            'status' => 200,
            'data' => $res_data
        );
    }

    /**
     * Process bulk system log submissions.
     * Sanitizes contextual data for security and inserts log rows into the DB.
     */
    public function system_logs_bulk($header_device_id, $access_raw, $payload, $meta)
    {
        $start = microtime(true);

        // 1. Authorization check
        if (empty($header_device_id) || empty($access_raw)) {
            $this->log_request($meta, $header_device_id, 401, 'UNAUTHORIZED', $start, $payload);
            return array('status' => 401, 'error_code' => 'UNAUTHORIZED');
        }

        // Validate access token
        $val = $this->auth->validate_access_token($access_raw, $header_device_id);
        if (!$val['ok']) {
            $code = ($val['error'] === 'TOKEN_EXPIRED') ? 'TOKEN_EXPIRED' : 'UNAUTHORIZED';
            $this->log_request($meta, $header_device_id, 401, $code, $start, $payload);
            return array('status' => 401, 'error_code' => $code);
        }

        // Verify device exists and is active
        $device = $this->repo->get_device_by_id($header_device_id);
        if (!$device || !isset($device['status']) || $device['status'] !== 'active') {
            $status_code = !$device ? 404 : 403;
            $err_code = !$device ? 'NOT_FOUND' : 'DEVICE_INACTIVE';
            $this->log_request($meta, $header_device_id, $status_code, $err_code, $start, $payload);
            return array('status' => $status_code, 'error_code' => $err_code);
        }

        // 2. Entire body validation (batch validation)
        if (!is_array($payload) || empty($payload['batch_id']) || !isset($payload['items']) || !is_array($payload['items'])) {
            $this->log_request($meta, $header_device_id, 422, 'VALIDATION_ERROR', $start, $payload);
            return array(
                'status' => 422,
                'error_code' => 'VALIDATION_ERROR',
                'errors' => array('body' => array('Invalid bulk request format. batch_id and items array are required.'))
            );
        }

        $batch_id = $payload['batch_id'];
        $items = $payload['items'];
        $total_items = count($items);
        $max_bulk = (int) $this->CI->config->item('fa_max_bulk_system_logs', 'face_attendance');

        if ($total_items > $max_bulk) {
            $this->log_request($meta, $header_device_id, 422, 'MAX_LIMIT_EXCEEDED', $start, $payload);
            return array(
                'status' => 422,
                'error_code' => 'MAX_LIMIT_EXCEEDED',
                'errors' => array('items' => array('Bulk items count exceeds maximum limit of ' . $max_bulk))
            );
        }

        if ($total_items === 0) {
            $this->log_request($meta, $header_device_id, 422, 'VALIDATION_ERROR', $start, $payload);
            return array(
                'status' => 422,
                'error_code' => 'VALIDATION_ERROR',
                'errors' => array('items' => array('Items list cannot be empty.'))
            );
        }

        // Process individual items
        $accepted = 0;
        $duplicate = 0;
        $rejected = 0;
        $results = array();

        $allowed_fields = array(
            'log_id', 'logged_at', 'level', 'event_type', 'message', 'context', 'request_id'
        );

        $rules = array(
            'log_id'     => 'required|string',
            'logged_at'  => 'required|string',
            'level'      => 'required|enum:DEBUG,INFO,WARNING,ERROR,CRITICAL',
            'event_type' => 'required|string',
            'message'    => 'required|string',
            'request_id' => 'string'
        );

        foreach ($items as $index => $item) {
            if (!is_array($item)) {
                $rejected++;
                $results[] = array(
                    'index' => $index,
                    'status' => 'rejected',
                    'error_code' => 'INVALID_ITEM',
                    'errors' => array('item' => array('Item must be an object'))
                );
                continue;
            }

            // Filter fields
            $filtered = array();
            foreach ($allowed_fields as $f) {
                if (array_key_exists($f, $item)) {
                    $filtered[$f] = $item[$f];
                }
            }

            // 1. Validation
            $item_errors = $this->validator->validate($filtered, $rules);
            if (!empty($item_errors)) {
                $rejected++;
                $results[] = array(
                    'log_id' => isset($filtered['log_id']) ? $filtered['log_id'] : null,
                    'status' => 'rejected',
                    'error_code' => 'VALIDATION_ERROR',
                    'errors' => $item_errors
                );
                continue;
            }

            // 2. Duplicate log_id check
            $existing_log = $this->repo->find_system_log_by_id($filtered['log_id']);
            if ($existing_log) {
                $duplicate++;
                $results[] = array(
                    'log_id' => $filtered['log_id'],
                    'status' => 'duplicate',
                    'error_code' => 'DUPLICATE_LOG',
                    'errors' => null
                );
                continue;
            }

            // 3. Sanitize Context (strip device secret, token, embeddings, images)
            $clean_context = isset($filtered['context']) ? $this->_sanitize_context($filtered['context']) : null;

            // Convert logged_at to DB format
            $dt = date_create($filtered['logged_at']);
            $logged_at_db = $dt ? $dt->format('Y-m-d H:i:s') : null;

            // 4. Save to DB
            $log_row = array(
                'log_id'     => $filtered['log_id'],
                'device_id'  => $header_device_id, // Store device_id from header/token, not payload
                'batch_id'   => $batch_id,
                'logged_at'  => $logged_at_db,
                'level'      => $filtered['level'],
                'event_type' => $filtered['event_type'],
                'message'    => $filtered['message'],
                'context'    => $clean_context ? json_encode($clean_context) : null,
                'request_id' => isset($filtered['request_id']) ? $filtered['request_id'] : null
            );

            $inserted_id = $this->repo->create_system_log($log_row);
            if ($inserted_id) {
                $accepted++;
                $results[] = array(
                    'log_id' => $filtered['log_id'],
                    'status' => 'accepted',
                    'error_code' => null,
                    'errors' => null
                );
            } else {
                $rejected++;
                $results[] = array(
                    'log_id' => $filtered['log_id'],
                    'status' => 'rejected',
                    'error_code' => 'DATABASE_ERROR',
                    'errors' => array('db' => array('Failed to insert system log'))
                );
            }
        }

        // Format Response
        $res_data = array(
            'batch_id' => $batch_id,
            'total' => $total_items,
            'accepted' => $accepted,
            'duplicate' => $duplicate,
            'rejected' => $rejected,
            'items' => $results
        );

        // Clean payload for API log
        $clean_payload = $payload;
        if (isset($clean_payload['items'])) {
            foreach ($clean_payload['items'] as $idx => $item) {
                if (isset($item['context'])) {
                    $clean_payload['items'][$idx]['context'] = $this->_sanitize_context($item['context']);
                }
            }
        }

        $clean_response = array(
            'success' => true,
            'message' => 'Bulk system logs processed',
            'data' => $res_data,
            'error_code' => null
        );

        $this->log_request($meta, $header_device_id, 200, null, $start, $clean_payload, $clean_response);

        return array(
            'status' => 200,
            'data' => $res_data
        );
    }

    /**
     * Recursively sanitizes logs context arrays to prevent saving sensitive fields.
     */
    protected function _sanitize_context($context)
    {
        if (!is_array($context)) {
            return $context;
        }
        $sensitive_keys = array(
            'device_secret',
            'access_token',
            'refresh_token',
            'image_base64',
            'photo_base64',
            'embedding',
            'photo_raw',
            'biometric_payload',
            'payload'
        );
        foreach ($context as $key => $val) {
            if (in_array(strtolower($key), $sensitive_keys, true)) {
                unset($context[$key]);
            } elseif (is_array($val)) {
                $context[$key] = $this->_sanitize_context($val);
            }
        }
        return $context;
    }

}
