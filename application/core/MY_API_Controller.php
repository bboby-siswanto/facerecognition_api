<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class MY_API_Controller extends CI_Controller {

    protected $request_id;

    public function __construct()
    {
        parent::__construct();

        // Set timezone
        date_default_timezone_set('Asia/Jakarta');

        // Load helpers
        $this->load->helper('url');

        // Ensure database is available if needed
        $this->load->database();

        // Initialize request id
        $this->request_id = $this->get_request_id();

        // Default headers
        header('Content-Type: application/json; charset=utf-8');
    }

    protected function get_request_id()
    {
        $rid = $this->input->get_request_header('X-Request-ID', TRUE);
        if ($rid && $this->is_valid_uuid($rid)) {
            return $rid;
        }

        // generate UUID v4
        return $this->generate_uuid_v4();
    }

    protected function generate_uuid_v4()
    {
        try {
            $data = random_bytes(16);
        } catch (Exception $e) {
            // fallback to mt_rand
            $data = '';
            for ($i = 0; $i < 16; $i++) {
                $data .= chr(mt_rand(0, 255));
            }
        }

        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data),4));
    }

    protected function is_valid_uuid($uuid)
    {
        return (bool) preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $uuid);
    }

    protected function parse_json_body()
    {
        $raw = file_get_contents('php://input');
        if (empty($raw)) {
            return null;
        }

        $data = json_decode($raw, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return null;
        }
        return $data;
    }

    protected function input_json($key = null, $default = null)
    {
        static $body = null;
        if ($body === null) {
            $body = $this->parse_json_body();
            if ($body === null) {
                $body = array();
            }
        }

        if ($key === null) {
            return $body;
        }

        return isset($body[$key]) ? $body[$key] : $default;
    }

    protected function request_header($name, $default = null)
    {
        $v = $this->input->get_request_header($name, TRUE);
        return ($v === NULL) ? $default : $v;
    }

    protected function query($key = null, $default = null)
    {
        if ($key === null) {
            return $this->input->get();
        }
        return $this->input->get($key) !== NULL ? $this->input->get($key) : $default;
    }

    protected function require_method($method)
    {
        $current = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $expected = strtoupper($method);
        if ($current !== $expected) {
            $this->send_response(array(
                'success' => false,
                'message' => 'Method not allowed',
                'data' => null,
                'error_code' => 'METHOD_NOT_ALLOWED',
                'errors' => null,
                'meta' => $this->meta(false)
            ), 405);
            exit;
        }
    }

    protected function meta($retryable = false, $retry_after_seconds = null)
    {
        $dt = new DateTime('now');
        return array(
            'request_id' => $this->request_id,
            'server_time' => $dt->format(DATE_ATOM),
            'retryable' => $retryable,
            'retry_after_seconds' => $retry_after_seconds
        );
    }

    protected function send_response($body, $http_code = 200)
    {
        // Ensure no sensitive info in production responses
        $this->output->set_status_header($http_code)
            ->set_content_type('application/json', 'utf-8')
            ->set_output(json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    protected function respond_success($message = 'Request processed successfully', $data = array(), $http_code = 200, $error_code = null)
    {
        $body = array(
            'success' => true,
            'message' => $message,
            'data' => $data,
            'error_code' => $error_code,
            'meta' => array(
                'request_id' => $this->request_id,
                'server_time' => (new DateTime('now'))->format(DATE_ATOM)
            )
        );
        $this->send_response($body, $http_code);
    }

    protected function respond_error($message = 'An error occurred', $http_code = 500, $error_code = 'SERVER_ERROR', $errors = null, $retryable = false, $retry_after_seconds = null)
    {
        // Log the error server-side
        log_message('error', sprintf('[%s] %s', $this->request_id, $message));

        $body = array(
            'success' => false,
            'message' => $message,
            'data' => null,
            'error_code' => $error_code,
            'errors' => $errors,
            'meta' => array(
                'request_id' => $this->request_id,
                'server_time' => (new DateTime('now'))->format(DATE_ATOM),
                'retryable' => $retryable,
                'retry_after_seconds' => $retry_after_seconds
            )
        );

        $this->send_response($body, $http_code);
    }

}
