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
        return $this->db->where('device_id', $device_id)->update('fa_devices', $data);
    }

    // Device tokens
    public function create_device_token($device_id, $access_token_hash, $refresh_token_hash, $access_expires_at, $refresh_expires_at, $meta)
    {
        $row = array(
            'device_id' => $device_id,
            'access_token_hash' => $access_token_hash,
            'refresh_token_hash' => $refresh_token_hash,
            'expires_at' => $access_expires_at,
            'refresh_expires_at' => $refresh_expires_at,
            'revoked' => 0,
            'replaced_by_token_id' => null,
            'last_used_at' => null,
            'created_at' => date('Y-m-d H:i:s'),
            'meta' => json_encode($meta)
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
        $data = array('revoked' => 1, 'revoked_at' => date('Y-m-d H:i:s'));
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
        $row = $data;
        $row['device_id'] = $device_id;
        $row['created_at'] = date('Y-m-d H:i:s');
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
        $row = $data;
        $row['created_at'] = date('Y-m-d H:i:s');
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

}
