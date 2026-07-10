<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Face_attendance_response
{
    public function success($message = 'Request processed successfully', $data = array())
    {
        return array('body' => array(
            'success' => true,
            'message' => $message,
            'data' => $data,
            'error_code' => null,
            'meta' => array()
        ), 'http_code' => 200);
    }

    public function created($message = 'Resource created', $data = array())
    {
        return array('body' => array(
            'success' => true,
            'message' => $message,
            'data' => $data,
            'error_code' => null,
            'meta' => array()
        ), 'http_code' => 201);
    }

    public function bad_request($message = 'Bad request', $errors = null)
    {
        return array('body' => array(
            'success' => false,
            'message' => $message,
            'data' => null,
            'error_code' => 'BAD_REQUEST',
            'errors' => $errors,
            'meta' => array()
        ), 'http_code' => 400);
    }

    public function unauthorized($message = 'Unauthorized')
    {
        return array('body' => array(
            'success' => false,
            'message' => $message,
            'data' => null,
            'error_code' => 'UNAUTHORIZED',
            'errors' => null,
            'meta' => array()
        ), 'http_code' => 401);
    }

    public function forbidden($message = 'Forbidden')
    {
        return array('body' => array(
            'success' => false,
            'message' => $message,
            'data' => null,
            'error_code' => 'FORBIDDEN',
            'errors' => null,
            'meta' => array()
        ), 'http_code' => 403);
    }

    public function not_found($message = 'Not found')
    {
        return array('body' => array(
            'success' => false,
            'message' => $message,
            'data' => null,
            'error_code' => 'NOT_FOUND',
            'errors' => null,
            'meta' => array()
        ), 'http_code' => 404);
    }

    public function conflict($message = 'Conflict')
    {
        return array('body' => array(
            'success' => false,
            'message' => $message,
            'data' => null,
            'error_code' => 'CONFLICT',
            'errors' => null,
            'meta' => array()
        ), 'http_code' => 409);
    }

    public function validation_error($errors = array(), $message = 'Validation failed')
    {
        return array('body' => array(
            'success' => false,
            'message' => $message,
            'data' => null,
            'error_code' => 'VALIDATION_ERROR',
            'errors' => $errors,
            'meta' => array()
        ), 'http_code' => 422);
    }

    public function rate_limited($retry_after_seconds = null, $message = 'Rate limit exceeded')
    {
        return array('body' => array(
            'success' => false,
            'message' => $message,
            'data' => null,
            'error_code' => 'RATE_LIMITED',
            'errors' => null,
            'meta' => array('retry_after_seconds' => $retry_after_seconds)
        ), 'http_code' => 429);
    }

    public function server_error($message = 'Internal server error')
    {
        return array('body' => array(
            'success' => false,
            'message' => $message,
            'data' => null,
            'error_code' => 'SERVER_ERROR',
            'errors' => null,
            'meta' => array()
        ), 'http_code' => 500);
    }

    public function method_not_allowed($message = 'Method not allowed')
    {
        return array('body' => array(
            'success' => false,
            'message' => $message,
            'data' => null,
            'error_code' => 'METHOD_NOT_ALLOWED',
            'errors' => null,
            'meta' => array()
        ), 'http_code' => 405);
    }

}
