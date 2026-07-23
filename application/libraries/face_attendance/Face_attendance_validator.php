<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Face_attendance_validator
{
    protected $CI;

    public function __construct()
    {
        $this->CI =& get_instance();
    }

    public function validate($data, $rules)
    {
        $errors = array();

        foreach ($rules as $field => $rlist) {
            $field = strtolower($field);
            $value = isset($data[$field]) ? $data[$field] : null;
            $rulesArray = is_array($rlist) ? $rlist : explode('|', $rlist);

            foreach ($rulesArray as $rule) {
                $param = null;
                if (strpos($rule, ':') !== false) {
                    list($rule, $param) = explode(':', $rule, 2);
                }

                $method = 'validate_' . $rule;
                if (method_exists($this, $method)) {
                    $ok = $this->$method($value, $param);
                    if (!$ok) {
                        $errors[$field][] = $this->message_for($rule, $field, $param);
                    }
                } else {
                    // unknown rule - skip
                }
            }
        }

        return $errors;
    }

    protected function message_for($rule, $field, $param = null)
    {
        $messages = array(
            'required' => 'Field is required',
            'string' => 'Must be a string',
            'integer' => 'Must be an integer',
            'numeric' => 'Must be numeric',
            'boolean' => 'Must be boolean',
            'array' => 'Must be an array',
            'enum' => 'Invalid value',
            'iso8601' => 'Must be a ISO-8601 datetime',
            'uuid' => 'Must be a valid UUID',
            'employee_code' => 'Invalid employee code',
            'device_id' => 'Invalid device id',
            'attendance_id' => 'Invalid attendance id',
            'score' => 'Must be a numeric score between 0 and 1',
            'base64_image' => 'Must be a base64 encoded image within allowed size'
        );

        return isset($messages[$rule]) ? $messages[$rule] : 'Invalid value';
    }

    protected function validate_required($value, $param)
    {
        return !is_null($value) && $value !== '';
    }

    protected function validate_string($value, $param)
    {
        return is_string($value);
    }

    protected function validate_integer($value, $param)
    {
        if (is_int($value)) return true;
        return (string) (int) $value === (string) $value;
    }

    protected function validate_numeric($value, $param)
    {
        return is_numeric($value);
    }

    protected function validate_boolean($value, $param)
    {
        if (is_bool($value)) return true;
        $v = strtolower((string) $value);
        return in_array($v, array('0','1','true','false','yes','no'), true);
    }

    protected function validate_array($value, $param)
    {
        return is_array($value);
    }

    protected function validate_enum($value, $param)
    {
        $allowed = explode(',', $param);
        return in_array($value, $allowed, true);
    }

    protected function validate_iso8601($value, $param)
    {
        if (!is_string($value)) return false;
        $d = DateTime::createFromFormat(DateTime::ATOM, $value);
        if ($d !== false) return true;
        $d2 = date_create($value);
        return ($d2 !== false);
    }

    protected function validate_uuid($value, $param)
    {
        if (!is_string($value)) return false;
        return (bool) preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $value);
    }

    protected function validate_employee_code($value, $param)
    {
        // simple rule: alphanumeric, 3-32 chars
        return (is_string($value) && preg_match('/^[A-Za-z0-9\-\_]{3,32}$/', $value));
    }

    protected function validate_device_id($value, $param)
    {
        // allow alphanumeric and dashes/underscores, 3-64 chars
        return (is_string($value) && preg_match('/^[A-Za-z0-9\-\_]{3,64}$/', $value));
    }

    protected function validate_attendance_id($value, $param)
    {
        // assume UUID or numeric id
        if ($this->validate_uuid($value, $param)) return true;
        return $this->validate_integer($value, $param);
    }

    protected function validate_score($value, $param)
    {
        if (!is_numeric($value)) return false;
        $f = (float) $value;
        return ($f >= 0 && $f <= 1);
    }

    protected function validate_base64_image($value, $param)
    {
        if (!is_string($value)) return false;
        $decoded = base64_decode($value, true);
        if ($decoded === false) return false;
        $size = strlen($decoded);
        $max = (int) $param;
        if ($max > 0 && $size > $max) return false;
        // minimal check for image by checking starting bytes of common formats
        if (substr($decoded, 0, 4) === "\xFF\xD8\xFF\xE0" || substr($decoded, 0, 4) === "\xFF\xD8\xFF\xE1") return true; // jpeg
        if (substr($decoded, 0, 8) === "\x89PNG\x0D\x0A\x1A\x0A") return true; // png
        if (substr($decoded, 0, 6) === "GIF87a" || substr($decoded, 0, 6) === "GIF89a") return true; // gif
        return true; // allow if base64 valid and size ok
    }

}
