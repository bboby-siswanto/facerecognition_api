<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Face_attendance extends MY_API_Controller {

    public function __construct()
    {
        parent::__construct();

        // Load face attendance config and libraries
        $this->config->load('face_attendance', TRUE);
        $this->load->library('face_attendance/Face_attendance_response');
        $this->load->library('face_attendance/Face_attendance_validator');
        $this->load->library('face_attendance/Face_attendance_repository');
        $this->load->library('face_attendance/Face_attendance_auth');
        $this->load->library('face_attendance/Face_attendance_service');
        $this->service = $this->face_attendance_service;
        $this->fa_response = $this->face_attendance_response;
    }

    // GET /api/v1/face-attendance/health
    public function health()
    {
        $this->require_method('GET');

        // Check DB connection
        $db_connected = false;
        try {
            if (isset($this->db) && $this->db->conn_id) {
                $db_connected = true;
            }
        } catch (Exception $e) {
            log_message('error', 'DB health check failed: ' . $e->getMessage());
            $db_connected = false;
        }

        $data = array(
            'status' => 'ok',
            'server_time' => (new DateTime('now'))->format(DATE_ATOM),
            'request_id' => $this->request_id,
            'db_connected' => $db_connected
        );

        $this->respond_success('API is healthy', $data, 200);
    }

    // POST /api/v1/auth/device/login
    public function auth_device_login()
    {
        $this->require_method('POST');
        $body = $this->input_json();

        $meta = array('request_id' => $this->request_id, 'endpoint' => 'auth/device/login', 'method' => 'POST');
        $res = $this->service->device_login($body, $meta);

        if (isset($res['status']) && $res['status'] === 200) {
            $this->respond_success('Login successful', $res['data'], 200);
            return;
        }

        if (isset($res['status']) && $res['status'] === 422) {
            $this->respond_error('Validation failed', 422, 'VALIDATION_ERROR', $res['errors']);
            return;
        }

        $code = isset($res['error_code']) ? $res['error_code'] : 'INTERNAL_ERROR';
        $status = isset($res['status']) ? $res['status'] : 500;
        $this->respond_error('Authentication failed', $status, $code);
    }

    // POST /api/v1/auth/device/refresh
    public function auth_device_refresh()
    {
        $this->require_method('POST');
        $body = $this->input_json();
        $meta = array('request_id' => $this->request_id, 'endpoint' => 'auth/device/refresh', 'method' => 'POST');
        $res = $this->service->device_refresh($body, $meta);

        if (isset($res['status']) && $res['status'] === 200) {
            $this->respond_success('Token refreshed', $res['data'], 200);
            return;
        }

        if (isset($res['status']) && $res['status'] === 422) {
            $this->respond_error('Validation failed', 422, 'VALIDATION_ERROR', $res['errors']);
            return;
        }

        $code = isset($res['error_code']) ? $res['error_code'] : 'INTERNAL_ERROR';
        $status = isset($res['status']) ? $res['status'] : 500;
        $this->respond_error('Refresh failed', $status, $code);
    }

    // POST /api/v1/auth/device/logout
    public function auth_device_logout()
    {
        $this->require_method('POST');
        $device_id = $this->request_header('X-Device-ID');
        $auth = $this->request_header('Authorization');
        $raw = null;
        if ($auth && preg_match('/Bearer\s+(.*)$/i', $auth, $m)) {
            $raw = $m[1];
        }
        $meta = array('request_id' => $this->request_id, 'endpoint' => 'auth/device/logout', 'method' => 'POST');
        $res = $this->service->device_logout($device_id, $raw, $meta);

        if (isset($res['status']) && $res['status'] === 200) {
            $this->respond_success('Logged out', $res['data'], 200);
            return;
        }

        $code = isset($res['error_code']) ? $res['error_code'] : 'INTERNAL_ERROR';
        $status = isset($res['status']) ? $res['status'] : 500;
        $this->respond_error('Logout failed', $status, $code);
    }

    // GET /api/v1/auth/device/profile
    public function auth_device_profile()
    {
        $this->require_method('GET');
        $device_id = $this->request_header('X-Device-ID');
        $auth = $this->request_header('Authorization');
        $raw = null;
        if ($auth && preg_match('/Bearer\s+(.*)$/i', $auth, $m)) {
            $raw = $m[1];
        }
        $meta = array('request_id' => $this->request_id, 'endpoint' => 'auth/device/profile', 'method' => 'GET');
        $res = $this->service->device_profile($device_id, $raw, $meta);

        if (isset($res['status']) && $res['status'] === 200) {
            $this->respond_success('Device profile', $res['data'], 200);
            return;
        }

        $code = isset($res['error_code']) ? $res['error_code'] : 'INTERNAL_ERROR';
        $status = isset($res['status']) ? $res['status'] : 500;
        $this->respond_error('Profile failed', $status, $code);
    }

    // GET /api/v1/devices/{device_id}/config
    public function device_config($device_id)
    {
        $this->require_method('GET');
        $header_device_id = $this->request_header('X-Device-ID');
        $auth = $this->request_header('Authorization');
        $raw = null;
        if ($auth && preg_match('/Bearer\s+(.*)$/i', $auth, $m)) {
            $raw = $m[1];
        }
        $meta = array('request_id' => $this->request_id, 'endpoint' => 'devices/config', 'method' => 'GET');
        $res = $this->service->device_config($device_id, $raw, $header_device_id, $meta);

        if (isset($res['status']) && $res['status'] === 200) {
            $this->respond_success('Device config', $res['data'], 200);
            return;
        }

        $code = isset($res['error_code']) ? $res['error_code'] : 'INTERNAL_ERROR';
        $status = isset($res['status']) ? $res['status'] : 500;
        $this->respond_error('Config failed', $status, $code);
    }

    // POST /api/v1/devices/{device_id}/heartbeat
    public function device_heartbeat($device_id)
    {
        $this->require_method('POST');
        $header_device_id = $this->request_header('X-Device-ID');
        $auth = $this->request_header('Authorization');
        $raw = null;
        if ($auth && preg_match('/Bearer\s+(.*)$/i', $auth, $m)) {
            $raw = $m[1];
        }
        $body = $this->input_json();
        $meta = array('request_id' => $this->request_id, 'endpoint' => 'devices/heartbeat', 'method' => 'POST');
        $res = $this->service->device_heartbeat($device_id, $raw, $header_device_id, $body, $meta);

        if (isset($res['status']) && $res['status'] === 200) {
            $this->respond_success('Heartbeat recorded', $res['data'], 200);
            return;
        }

        if (isset($res['status']) && $res['status'] === 422) {
            $this->respond_error('Validation failed', 422, 'VALIDATION_ERROR', $res['errors']);
            return;
        }

        $code = isset($res['error_code']) ? $res['error_code'] : 'INTERNAL_ERROR';
        $status = isset($res['status']) ? $res['status'] : 500;
        $this->respond_error('Heartbeat failed', $status, $code);
    }

    // POST /api/v1/employees
    public function employees_create()
    {
        $this->require_method('POST');
        $device_id = $this->request_header('X-Device-ID');
        $auth = $this->request_header('Authorization');
        $raw = null;
        if ($auth && preg_match('/Bearer\s+(.*)$/i', $auth, $m)) {
            $raw = $m[1];
        }
        $body = $this->input_json();
        $meta = array('request_id' => $this->request_id, 'endpoint' => 'employees', 'method' => 'POST');
        $res = $this->service->employees_create($device_id, $raw, $device_id, $body, $meta);

        if (isset($res['status']) && $res['status'] === 200) {
            $this->respond_success('Employee created', $res['data'], 200);
            return;
        }

        if (isset($res['status']) && $res['status'] === 422) {
            $this->respond_error('Validation failed', 422, 'VALIDATION_ERROR', $res['errors']);
            return;
        }

        if (isset($res['status']) && $res['status'] === 409) {
            $this->respond_error('Duplicate employee', 409, 'DUPLICATE_EMPLOYEE');
            return;
        }

        $code = isset($res['error_code']) ? $res['error_code'] : 'INTERNAL_ERROR';
        $status = isset($res['status']) ? $res['status'] : 500;
        $this->respond_error('Employee create failed', $status, $code);
    }

    // POST /api/v1/employees/{employee_code}/faces
    public function employee_faces_create($employee_code)
    {
        $this->require_method('POST');
        $device_id = $this->request_header('X-Device-ID');
        $auth = $this->request_header('Authorization');
        $raw = null;
        if ($auth && preg_match('/Bearer\s+(.*)$/i', $auth, $m)) {
            $raw = $m[1];
        }
        $body = $this->input_json();
        $meta = array('request_id' => $this->request_id, 'endpoint' => 'employees/faces', 'method' => 'POST');
        $res = $this->service->employee_faces_create($employee_code, $device_id, $raw, $device_id, $body, $meta);

        if (isset($res['status']) && $res['status'] === 200) {
            $this->respond_success('Face created', $res['data'], 200);
            return;
        }

        if (isset($res['status']) && $res['status'] === 422) {
            $this->respond_error('Validation failed', 422, 'VALIDATION_ERROR', $res['errors']);
            return;
        }

        if (isset($res['status']) && $res['status'] === 409) {
            $this->respond_error('Duplicate face', 409, 'DUPLICATE_FACE');
            return;
        }

        $code = isset($res['error_code']) ? $res['error_code'] : 'INTERNAL_ERROR';
        $status = isset($res['status']) ? $res['status'] : 500;
        $this->respond_error('Face create failed', $status, $code);
    }

    // GET /api/v1/employees/sync
    public function employees_sync()
    {
        $this->require_method('GET');
        $device_id = $this->query('device_id');
        $header_device_id = $this->request_header('X-Device-ID');
        $auth = $this->request_header('Authorization');
        $raw = null;
        if ($auth && preg_match('/Bearer\s+(.*)$/i', $auth, $m)) {
            $raw = $m[1];
        }
        $query = array('last_sync_at' => $this->query('last_sync_at'));
        $meta = array('request_id' => $this->request_id, 'endpoint' => 'employees/sync', 'method' => 'GET');
        $res = $this->service->employees_sync($device_id, $raw, $header_device_id, $query, $meta);

        if (isset($res['status']) && $res['status'] === 200) {
            $this->respond_success('Employee sync generated', $res['data'], 200);
            return;
        }

        $code = isset($res['error_code']) ? $res['error_code'] : 'INTERNAL_ERROR';
        $status = isset($res['status']) ? $res['status'] : 500;
        $this->respond_error('Employee sync failed', $status, $code);
    }

    // POST /api/v1/employees/sync/acknowledge
    public function employees_sync_acknowledge()
    {
        $this->require_method('POST');
        $body = $this->input_json();
        $meta = array('request_id' => $this->request_id, 'endpoint' => 'employees/sync/acknowledge', 'method' => 'POST');
        $res = $this->service->employees_sync_acknowledge($body, $meta);

        if (isset($res['status']) && $res['status'] === 200) {
            $this->respond_success('Employee sync acknowledged', $res['data'], 200);
            return;
        }

        if (isset($res['status']) && $res['status'] === 422) {
            $this->respond_error('Validation failed', 422, 'VALIDATION_ERROR', $res['errors']);
            return;
        }

        $code = isset($res['error_code']) ? $res['error_code'] : 'INTERNAL_ERROR';
        $status = isset($res['status']) ? $res['status'] : 500;
        $this->respond_error('Employee sync acknowledge failed', $status, $code);
    }

    // POST /api/v1/attendances
    public function attendances_create()
    {
        $this->require_method('POST');

        $device_id = $this->request_header('X-Device-ID');
        $auth      = $this->request_header('Authorization');
        $raw       = null;
        if ($auth && preg_match('/Bearer\s+(.*)$/i', $auth, $m)) {
            $raw = $m[1];
        }

        $body = $this->input_json();
        $meta = array(
            'request_id' => $this->request_id,
            'endpoint'   => 'attendances',
            'method'     => 'POST'
        );

        $res = $this->service->attendances_create($device_id, $raw, $body, $meta);

        if (isset($res['status']) && $res['status'] === 200) {
            $this->respond_success('Attendance recorded', $res['data'], 200);
            return;
        }

        if (isset($res['status']) && $res['status'] === 422) {
            $errors = isset($res['errors']) ? $res['errors'] : null;
            $code   = isset($res['error_code']) ? $res['error_code'] : 'VALIDATION_ERROR';
            $this->respond_error('Validation failed', 422, $code, $errors);
            return;
        }

        if (isset($res['status']) && $res['status'] === 409) {
            $this->respond_error('Duplicate attendance', 409, 'DUPLICATE_ATTENDANCE');
            return;
        }

        $code   = isset($res['error_code']) ? $res['error_code'] : 'INTERNAL_ERROR';
        $status = isset($res['status'])     ? $res['status']     : 500;
        $this->respond_error('Attendance failed', $status, $code);
    }

    // GET /api/v1/attendances/{attendance_id}
    public function attendances_detail($attendance_id)
    {
        $this->require_method('GET');

        $device_id = $this->request_header('X-Device-ID');
        $auth      = $this->request_header('Authorization');
        $raw       = null;
        if ($auth && preg_match('/Bearer\s+(.*)$/i', $auth, $m)) {
            $raw = $m[1];
        }

        $meta = array(
            'request_id' => $this->request_id,
            'endpoint'   => 'attendances/detail',
            'method'     => 'GET'
        );

        $res = $this->service->attendances_detail($attendance_id, $device_id, $raw, $meta);

        if (isset($res['status']) && $res['status'] === 200) {
            $this->respond_success('Attendance detail', $res['data'], 200);
            return;
        }

        $code   = isset($res['error_code']) ? $res['error_code'] : 'INTERNAL_ERROR';
        $status = isset($res['status'])     ? $res['status']     : 500;
        $this->respond_error('Attendance detail failed', $status, $code);
    }

}

