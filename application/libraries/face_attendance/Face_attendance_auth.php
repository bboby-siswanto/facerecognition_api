<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Face_attendance_auth
{
    protected $CI;
    protected $repo;

    public function __construct()
    {
        $this->CI =& get_instance();
        $this->CI->config->load('face_attendance', TRUE);
        $this->CI->load->library('face_attendance/Face_attendance_repository');
        $this->repo = $this->CI->face_attendance_repository;
    }

    protected function get_access_ttl()
    {
        return (int) $this->CI->config->item('fa_access_token_ttl', 'face_attendance');
    }

    protected function get_refresh_ttl()
    {
        return (int) $this->CI->config->item('fa_refresh_token_ttl', 'face_attendance');
    }

    public function generate_access_token_raw()
    {
        return bin2hex(random_bytes(32));
    }

    public function generate_refresh_token_raw()
    {
        return bin2hex(random_bytes(48));
    }

    public function create_tokens_for_device($device_id, $meta)
    {
        try {
            $access = $this->generate_access_token_raw();
            $refresh = $this->generate_refresh_token_raw();

            $access_hash = hash('sha256', $access);
            $refresh_hash = hash('sha256', $refresh);

            $now = time();
            $access_expires_at = date('Y-m-d H:i:s', $now + $this->get_access_ttl());
            $refresh_expires_at = date('Y-m-d H:i:s', $now + $this->get_refresh_ttl());

            $token_row = $this->repo->create_device_token($device_id, $access_hash, $refresh_hash, $access_expires_at, $refresh_expires_at, $meta);

            if (!$token_row) {
                return array('error' => 'INTERNAL_ERROR');
            }

            return array(
                'access_token' => $access,
                'refresh_token' => $refresh,
                'access_expires_at' => $access_expires_at,
                'refresh_expires_at' => $refresh_expires_at,
                'token_id' => isset($token_row['id']) ? $token_row['id'] : null
            );
        } catch (Exception $e) {
            log_message('error', 'Token creation failed: ' . $e->getMessage());
            return array('error' => 'INTERNAL_ERROR');
        }
    }

    public function validate_access_token($raw_token, $device_id)
    {
        if (empty($raw_token)) {
            return array('ok' => false, 'error' => 'UNAUTHORIZED');
        }
        $hash = hash('sha256', $raw_token);
        $row = $this->repo->find_token_by_access_hash($hash);
        if (!$row) {
            return array('ok' => false, 'error' => 'UNAUTHORIZED');
        }
        if (!empty($row['revoked_at'])) {
            return array('ok' => false, 'error' => 'UNAUTHORIZED');
        }
        if ($row['device_id'] !== $device_id) {
            return array('ok' => false, 'error' => 'UNAUTHORIZED');
        }
        if (isset($row['access_expires_at']) && strtotime($row['access_expires_at']) < time()) {
            return array('ok' => false, 'error' => 'TOKEN_EXPIRED');
        }

        // update last used
        $this->repo->update_token_last_used($row['id']);

        return array('ok' => true, 'token' => $row);
    }

    public function validate_refresh_token($raw_refresh, $device_id)
    {
        if (empty($raw_refresh)) {
            return array('ok' => false, 'error' => 'UNAUTHORIZED');
        }
        $hash = hash('sha256', $raw_refresh);
        $row = $this->repo->find_token_by_refresh_hash($hash);
        if (!$row) {
            return array('ok' => false, 'error' => 'UNAUTHORIZED');
        }
        if (!empty($row['revoked_at'])) {
            return array('ok' => false, 'error' => 'UNAUTHORIZED');
        }
        if ($row['device_id'] !== $device_id) {
            return array('ok' => false, 'error' => 'UNAUTHORIZED');
        }
        if (isset($row['refresh_expires_at']) && strtotime($row['refresh_expires_at']) < time()) {
            return array('ok' => false, 'error' => 'TOKEN_EXPIRED');
        }

        return array('ok' => true, 'token' => $row);
    }

    public function revoke_token_by_id($token_id)
    {
        try {
            return $this->repo->revoke_token($token_id);
        } catch (Exception $e) {
            log_message('error', 'Failed to revoke token id ' . $token_id . ': ' . $e->getMessage());
            return false;
        }
    }

    public function rotate_refresh_token($old_refresh_raw, $device_id, $meta)
    {
        $val = $this->validate_refresh_token($old_refresh_raw, $device_id);
        if (!$val['ok']) {
            return array('ok' => false, 'error' => $val['error']);
        }

        $old = $val['token'];

        // create new tokens
        $new = $this->create_tokens_for_device($device_id, $meta);
        if (isset($new['error'])) {
            return array('ok' => false, 'error' => 'INTERNAL_ERROR');
        }

        // mark old revoked and set replaced_by
        $this->repo->revoke_token($old['id'], isset($new['token_id']) ? $new['token_id'] : null);

        // set replaced_by on old explicitly
        if (isset($new['token_id'])) {
            $this->repo->set_replaced_by($old['id'], $new['token_id']);
        }

        return array('ok' => true, 'access_token' => $new['access_token'], 'refresh_token' => $new['refresh_token'], 'access_expires_at' => $new['access_expires_at'], 'refresh_expires_at' => $new['refresh_expires_at']);
    }

}
