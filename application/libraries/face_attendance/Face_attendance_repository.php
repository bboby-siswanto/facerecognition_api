<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Face_attendance_repository
{
    protected $CI;
    protected $db;

    public function __construct()
    {
        $this->CI =& get_instance();
        $this->CI->load->database();
        $this->db = $this->CI->db;
    }

    // Helper: begin transaction
    public function begin()
    {
        $this->db->trans_begin();
    }

    public function commit()
    {
        $this->db->trans_commit();
    }

    public function rollback()
    {
        $this->db->trans_rollback();
    }

    // Devices
    public function get_device_by_id_and_code($device_id, $device_code)
    {
        $q = $this->db->get_where('fa_devices', array('device_id' => $device_id, 'device_code' => $device_code));
        return $q->row_array();
    }

    public function get_device_by_id($device_id)
    {
        $q = $this->db->get_where('fa_devices', array('device_id' => $device_id));
        return $q->row_array();
    }

    public function update_device_login_info($device_id, $data)
    {
        if (isset($data['ip'])) {
            $data['ip_address'] = $data['ip'];
            unset($data['ip']);
        }
        return $this->db->where('device_id', $device_id)->update('fa_devices', $data);
    }

    // Device tokens
    public function create_device_token($device_id, $access_token_hash, $refresh_token_hash, $access_expires_at, $refresh_expires_at, $meta)
    {
        $row = array(
            'device_id'            => $device_id,
            'access_token_hash'    => $access_token_hash,
            'refresh_token_hash'   => $refresh_token_hash,
            'access_expires_at'    => $access_expires_at,
            'refresh_expires_at'   => $refresh_expires_at,
            'issued_ip_address'    => isset($meta['ip']) ? $meta['ip'] : null,
            'last_used_ip_address' => isset($meta['ip']) ? $meta['ip'] : null,
            'last_used_at'         => null,
            'revoked_at'           => null,
            'replaced_by_token_id' => null,
            'created_at'           => date('Y-m-d H:i:s'),
            'updated_at'           => date('Y-m-d H:i:s')
        );
        $this->db->insert('fa_device_tokens', $row);
        $id = $this->db->insert_id();
        if ($id) {
            return $this->find_token_by_id($id);
        }
        return null;
    }

    public function find_token_by_id($id)
    {
        $q = $this->db->get_where('fa_device_tokens', array('id' => $id));
        return $q->row_array();
    }

    public function find_token_by_access_hash($access_hash)
    {
        $q = $this->db->get_where('fa_device_tokens', array('access_token_hash' => $access_hash));
        return $q->row_array();
    }

    public function find_token_by_refresh_hash($refresh_hash)
    {
        $q = $this->db->get_where('fa_device_tokens', array('refresh_token_hash' => $refresh_hash));
        return $q->row_array();
    }

    public function update_token_last_used($token_id)
    {
        return $this->db->where('id', $token_id)->update('fa_device_tokens', array('last_used_at' => date('Y-m-d H:i:s')));
    }

    public function revoke_token($token_id, $replaced_by_token_id = null)
    {
        $data = array('revoked_at' => date('Y-m-d H:i:s'), 'updated_at' => date('Y-m-d H:i:s'));
        if ($replaced_by_token_id !== null) {
            $data['replaced_by_token_id'] = $replaced_by_token_id;
        }
        return $this->db->where('id', $token_id)->update('fa_device_tokens', $data);
    }

    public function set_replaced_by($token_id, $replaced_by_token_id)
    {
        return $this->db->where('id', $token_id)->update('fa_device_tokens', array('replaced_by_token_id' => $replaced_by_token_id));
    }

    // Device sessions
    public function create_device_session($device_id, $data)
    {
        $meta = isset($data['meta']) ? json_decode($data['meta'], true) : array();
        $row = array(
            'device_id'    => $device_id,
            'session_type' => isset($data['type']) ? $data['type'] : 'login',
            'ip_address'   => isset($data['ip']) ? $data['ip'] : (isset($data['ip_address']) ? $data['ip_address'] : null),
            'app_version'  => isset($meta['app_version']) ? $meta['app_version'] : null,
            'platform'     => isset($meta['platform']) ? $meta['platform'] : null,
            'message'      => isset($meta['note']) ? $meta['note'] : null,
            'created_at'   => date('Y-m-d H:i:s')
        );
        $this->db->insert('fa_device_sessions', $row);
        return $this->db->insert_id();
    }

    // Device config
    public function get_device_config($device_id)
    {
        $this->db->order_by('id', 'DESC');
        $this->db->limit(1);
        $q = $this->db->get_where('fa_device_configs', array('device_id' => $device_id));
        return $q->row_array();
    }

    // Heartbeats
    public function create_device_heartbeat($device_id, $data)
    {
        $row = $data;
        $row['device_id'] = $device_id;
        $row['created_at'] = date('Y-m-d H:i:s');
        $this->db->insert('fa_device_heartbeats', $row);
        return $this->db->insert_id();
    }

    public function update_device_heartbeat_status($device_id, $data)
    {
        return $this->db->where('device_id', $device_id)->update('fa_devices', $data);
    }

    // Employee syncs
    public function create_employee_sync($device_id, $data)
    {
        $row = $data;
        $row['device_id'] = $device_id;
        $row['created_at'] = date('Y-m-d H:i:s');
        $this->db->insert('fa_employee_syncs', $row);
        return $this->db->insert_id();
    }

    public function get_employee_sync($sync_id)
    {
        $q = $this->db->get_where('fa_employee_syncs', array('sync_id' => $sync_id));
        return $q->row_array();
    }

    public function get_employee_sync_by_id_and_device($sync_id, $device_id)
    {
        $q = $this->db->get_where('fa_employee_syncs', array('sync_id' => $sync_id, 'device_id' => $device_id));
        return $q->row_array();
    }

    public function update_employee_sync($sync_id, $data)
    {
        return $this->db->where('sync_id', $sync_id)->update('fa_employee_syncs', $data);
    }

    public function create_employee_sync_item($sync_id, $data)
    {
        $row = $data;
        $row['sync_id'] = $sync_id;
        $row['created_at'] = date('Y-m-d H:i:s');
        $this->db->insert('fa_employee_sync_items', $row);
        return $this->db->insert_id();
    }

    public function update_employee_sync_item($sync_id, $employee_code, $data)
    {
        $this->db->where('sync_id', $sync_id);
        $this->db->where('employee_code', $employee_code);
        return $this->db->update('fa_employee_sync_items', $data);
    }

    public function get_active_employees($since = null)
    {
        $this->db->from('fa_employees');
        if ($since !== null) {
            $this->db->group_start();
            $this->db->where('updated_at >=', $since);
            $this->db->or_where('deleted_at >=', $since);
            $this->db->group_end();
        }
        $this->db->where('is_deleted', 0);
        $this->db->order_by('updated_at', 'ASC');
        $q = $this->db->get();
        return $q->result_array();
    }

    public function get_deleted_employees($since = null)
    {
        $this->db->from('fa_employees');
        if ($since !== null) {
            $this->db->where('deleted_at >=', $since);
        }
        $this->db->where('is_deleted', 1);
        $this->db->order_by('deleted_at', 'ASC');
        $q = $this->db->get();
        return $q->result_array();
    }

    public function get_employee_faces($employee_id)
    {
        $this->db->where('employee_id', $employee_id);
        $this->db->order_by('id', 'ASC');
        $q = $this->db->get('fa_employee_faces');
        return $q->result_array();
    }

    public function get_employee_by_code($employee_code)
    {
        $q = $this->db->get_where('fa_employees', array('employee_code' => $employee_code));
        return $q->row_array();
    }

    public function create_employee($data)
    {
        $row = $data;
        $row['created_at'] = date('Y-m-d H:i:s');
        $row['updated_at'] = date('Y-m-d H:i:s');
        $this->db->insert('fa_employees', $row);
        return $this->db->insert_id();
    }

    public function update_employee($employee_id, $data)
    {
        $data['updated_at'] = date('Y-m-d H:i:s');
        return $this->db->where('id', $employee_id)->update('fa_employees', $data);
    }

    public function get_face_by_id($face_id)
    {
        $q = $this->db->get_where('fa_employee_faces', array('face_id' => $face_id));
        return $q->row_array();
    }

    public function create_face($data)
    {
        $row = $data;
        $row['created_at'] = date('Y-m-d H:i:s');
        $row['updated_at'] = date('Y-m-d H:i:s');
        $this->db->insert('fa_employee_faces', $row);
        return $this->db->insert_id();
    }

    public function clear_primary_face($employee_id)
    {
        return $this->db->where('employee_id', $employee_id)->where('is_primary', 1)->update('fa_employee_faces', array('is_primary' => 0));
    }

    // API request logs (audit)
    public function log_api_request($data)
    {
        $row = array(
            'request_id'       => isset($data['request_id']) ? $data['request_id'] : null,
            'device_id'        => isset($data['device_id']) ? $data['device_id'] : null,
            'endpoint'         => isset($data['endpoint']) ? $data['endpoint'] : null,
            'http_method'      => isset($data['http_method']) ? $data['http_method'] : (isset($data['method']) ? $data['method'] : null),
            'http_status'      => isset($data['http_status']) ? (int)$data['http_status'] : 200,
            'error_code'       => isset($data['error_code']) ? $data['error_code'] : null,
            'ip_address'       => isset($data['ip_address']) ? $data['ip_address'] : (isset($data['ip']) ? $data['ip'] : null),
            'request_payload'  => isset($data['request_payload']) ? $data['request_payload'] : null,
            'response_payload' => isset($data['response_payload']) ? $data['response_payload'] : null,
            'duration_ms'      => isset($data['duration_ms']) ? (int)$data['duration_ms'] : null,
            'created_at'       => date('Y-m-d H:i:s')
        );
        $this->db->insert('fa_api_request_logs', $row);
        return $this->db->insert_id();
    }

    // Placeholders for attendance and employee
    public function find_employee_by_code($code)
    {
        return null;
    }

    public function save_attendance($data)
    {
        return false;
    }

    // ---------------------------------------------------------------------------
    // Attendances
    // ---------------------------------------------------------------------------

    /**
     * Find an attendance record by its unique attendance_id string.
     */
    public function find_attendance_by_id($attendance_id)
    {
        $q = $this->db->get_where('fa_attendances', array('attendance_id' => $attendance_id));
        return $q->row_array();
    }

    /**
     * Find an attendance record by the combination of device_id + request_id.
     * Used for idempotency: if the same device submits the same request_id twice,
     * we return the existing record instead of creating a new one.
     */
    public function find_attendance_by_device_request($device_id, $request_id)
    {
        if (empty($request_id)) {
            return null;
        }
        $q = $this->db->get_where('fa_attendances', array(
            'device_id'  => $device_id,
            'request_id' => $request_id
        ));
        return $q->row_array();
    }

    /**
     * Insert a new attendance record into fa_attendances.
     * Returns the auto-increment id on success, or FALSE on failure.
     */
    public function create_attendance($data)
    {
        $row = $data;
        $row['created_at'] = date('Y-m-d H:i:s');
        $row['updated_at'] = date('Y-m-d H:i:s');
        $this->db->insert('fa_attendances', $row);
        if ($this->db->affected_rows() < 1) {
            return false;
        }
        return $this->db->insert_id();
    }

    /**
     * Insert a row into fa_attendance_logs.
     * status values: 'accepted', 'rejected', 'duplicate'
     * Does NOT contain photo_base64 or token values.
     */
    public function create_attendance_log($data)
    {
        $row = $data;
        $row['created_at'] = date('Y-m-d H:i:s');
        $this->db->insert('fa_attendance_logs', $row);
        return $this->db->insert_id();
    }

    // ---------------------------------------------------------------------------
    // System Logs
    // ---------------------------------------------------------------------------

    /**
     * Find a system log by log_id.
     */
    public function find_system_log_by_id($log_id)
    {
        $q = $this->db->get_where('fa_system_logs', array('log_id' => $log_id));
        return $q->row_array();
    }

    /**
     * Insert a new system log.
     */
    public function create_system_log($data)
    {
        $row = $data;
        $row['received_at'] = date('Y-m-d H:i:s');
        $row['created_at'] = date('Y-m-d H:i:s');
        $this->db->insert('fa_system_logs', $row);
        if ($this->db->affected_rows() < 1) {
            return false;
        }
        return $this->db->insert_id();
    }

}
