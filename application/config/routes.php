<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/*
| -------------------------------------------------------------------------
| URI ROUTING
| -------------------------------------------------------------------------
| This file lets you re-map URI requests to specific controller functions.
|
| Typically there is a one-to-one relationship between a URL string
| and its corresponding controller class/method. The segments in a
| URL normally follow this pattern:
|
|	example.com/class/method/id/
|
| In some instances, however, you may want to remap this relationship
| so that a different class/function is called than the one
| corresponding to the URL.
|
| Please see the user guide for complete details:
|
|	https://codeigniter.com/userguide3/general/routing.html
|
| -------------------------------------------------------------------------
| RESERVED ROUTES
| -------------------------------------------------------------------------
|
| There are three reserved routes:
|
|	$route['default_controller'] = 'welcome';
|
| This route indicates which controller class should be loaded if the
| URI contains no data. In the above example, the "welcome" class
| would be loaded.
|
|	$route['404_override'] = 'errors/page_missing';
|
| This route will tell the Router which controller/method to use if those
| provided in the URL cannot be matched to a valid route.
|
|	$route['translate_uri_dashes'] = FALSE;
|
| This is not exactly a route, but allows you to automatically route
| controller and method names that contain dashes. '-' isn't a valid
| class or method name character, so it requires translation.
| When you set this option to TRUE, it will replace ALL dashes in the
| controller and method URI segments.
|
| Examples:	my-controller/index	-> my_controller/index
|		my-controller/my-method	-> my_controller/my_method
*/
$route['default_controller'] = 'welcome';
$route['404_override'] = '';
$route['translate_uri_dashes'] = FALSE;

// Face Attendance API v1
$route['api/v1/face-attendance/health'] = 'api/v1/Face_attendance/health';
// Auth routes
$route['api/v1/auth/device/login'] = 'api/v1/Face_attendance/auth_device_login';
$route['api/v1/auth/device/refresh'] = 'api/v1/Face_attendance/auth_device_refresh';
$route['api/v1/auth/device/logout'] = 'api/v1/Face_attendance/auth_device_logout';
$route['api/v1/auth/device/profile'] = 'api/v1/Face_attendance/auth_device_profile';

// Device config and heartbeat routes
$route['api/v1/devices/(:any)/config'] = 'api/v1/Face_attendance/device_config/$1';
$route['api/v1/devices/(:any)/heartbeat'] = 'api/v1/Face_attendance/device_heartbeat/$1';

// Employee CRUD and sync routes
$route['api/v1/employees'] = 'api/v1/Face_attendance/employees_create';
$route['api/v1/employees/(:any)/faces'] = 'api/v1/Face_attendance/employee_faces_create/$1';
$route['api/v1/employees/sync'] = 'api/v1/Face_attendance/employees_sync';
$route['api/v1/employees/sync/acknowledge'] = 'api/v1/Face_attendance/employees_sync_acknowledge';
