<?php

class Passport extends Admin_Controller {

    protected $options;
    protected $cache;
    protected $returnType;
    protected $brokerId;

    public function __construct() {
        self::$session_domain = 'sess_domain_admin';
        log_message('DEBUG', json_encode($_SERVER));
        parent::__construct();
        log_message('DEBUG', 'passport load');
        $this->load->model('user_model');
        $this->load->config('redis');
        $redisCache = $this->config->item('RedisCache');

        if (class_exists('Redis')) {
            try {
                $this->cache = new Redis();
                 $this->cache->connect($redisCache['host'], $redisCache['port']);
            } catch (RedisException $e){
                log_message('error', $e->getMessage());
            }
        }
    }
    public function attach()
    {
        $this->detectReturnType();
        if (empty($_REQUEST['broker'])) return $this->fail("No broker specified", 400);
        if (empty($_REQUEST['token'])) return $this->fail("No token specified", 400);

        if (!$this->returnType) return $this->fail("No return url specified", 400);
        $checksum = $this->generateAttachChecksum($_REQUEST['broker'], $_REQUEST['token']);
        if (empty($_REQUEST['checksum']) || $checksum != $_REQUEST['checksum']) {
            return $this->fail("Invalid checksum$checksum", 400);
        }
        $this->startUserSession();
        $sid = $this->generateSessionId($_REQUEST['broker'], $_REQUEST['token']);
        $this->cache->set($sid, $this->getSessionData('id'));
        $this->outputAttachSuccess();
    }

    protected function detectReturnType() {
        if (!empty($_GET['return_url'])) {
            $this->returnType = 'redirect';
        } elseif (!empty($_GET['callback'])) {
            $this->returnType = 'jsonp';
        } elseif (strpos($_SERVER['HTTP_ACCEPT'], 'image/') !== false) {
            $this->returnType = 'image';
        } elseif (strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false) {
            $this->returnType = 'json';
        }
    }

    public function login() {
        log_message('DEBUG','passport/login-->'. json_encode($_SERVER));
        $this->startBrokerSession();
        if (empty($_POST['userName'])) $this->fail("No username specified", 400);
        if (empty($_POST['password'])) $this->fail("No password specified", 400);

        if (strlen($_POST['password']) < 6) {
            $this->r(101, "用户名或密码错误");
        }
        $this->user = $this->user_model->getUserByUserName($this->input->post('userName'));
        if ($this->user == null || !password_verify($this->input->post('password'), $this->user->password)) {
            $this->r(101, "用户名或密码错误");
        }
        $this->session->set_userdata(array('sso_userId' => $this->user->userId));
        log_message('DEBUG','passport/login-->'. $this->session->userdata('sso_userId'));
        header('Content-type: application/json; charset=UTF-8');
        echo json_encode($this->user);
    }

    public function startBrokerSession() {
        if (isset($this->brokerId)) return;
        if (!isset($_GET['sso_session'])) {
            return $this->fail("Broker didn't send a session key", 400);
        }
        $sid = $_GET['sso_session'];

        $linkedId = $this->cache->get($sid);
        if (!$linkedId) {
            return $this->fail("The broker session id isn't attached to a user session$sid", 403);
        }
        if (session_status() === PHP_SESSION_ACTIVE) {
            log_message('DEBUG', 'passport/startsession-->' . $sid.'--'.$linkedId . '--' . session_id());
            log_message('DEBUG', 'passport/startsession-->' . json_encode($_SERVER));
            if ($linkedId !== session_id()) throw new \Exception(" Session has already started", 400);
            return;
        }
        session_id($linkedId);
        session_start();
        $this->brokerId = $this->validateBrokerSessionId($sid);
    }

    protected function validateBrokerSessionId($sid) {
        $matches = null;
        if (!preg_match('/^SSO-(\w*+)-(\w*+)-([a-z0-9]*+)$/', $_GET['sso_session'], $matches)) {
            return $this->fail("Invalid session id");
        }
        $brokerId = $matches[1];
        $token = $matches[2];
        if ($this->generateSessionId($brokerId, $token) != $sid) {
            return $this->fail("Checksum failed: Client IP address may have changed", 403);
        }

        return $brokerId;
    }

    protected function startUserSession() {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    }

    protected function generateSessionId($brokerId, $token) {
        $broker = $this->getBrokerInfo($brokerId);
        if (!isset($broker)) return null;
        return "SSO-{$brokerId}-{$token}-" . hash('sha256', 'session' . $token . $broker['secret']);
    }

    protected function generateAttachChecksum($brokerId, $token) {
        $broker = $this->getBrokerInfo($brokerId);
        if (!isset($broker)) return null;
        return hash('sha256', $token . $broker['secret']);
    }

    protected function outputAttachSuccess() {
        if ($this->returnType === 'image') {
            $this->outputImage();
        }
        if ($this->returnType === 'json') {
            header('Content-type: application/json; charset=UTF-8');
            echo json_encode(['success' => 'attached']);
            die();
        }
        if ($this->returnType === 'jsonp') {
            $data = json_encode(['success' => 'attached']);
            echo $_REQUEST['callback'] . "($data, 200);";
        }
        if ($this->returnType === 'redirect') {
            $url = $_REQUEST['return_url'];
            header("Location: $url", true, 307);
            echo "You're being redirected to <a href='{$url}'>$url</a>";
        }
    }

    protected function outputImage() {
        header('Content-Type: image/png');
        echo base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQ'
            . 'MAAAAl21bKAAAAA1BMVEUAAACnej3aAAAAAXRSTlMAQObYZg'
            . 'AAAApJREFUCNdjYAAAAAIAAeIhvDMAAAAASUVORK5CYII=');
    }

    public function logout() {
        $this->startBrokerSession();
        $this->session->set_userdata(array('sso_userId', null));
        header('Content-type: application/json; charset=UTF-8');
        http_response_code(204);
    }

    public function setSessionData($key, $value) {
        if (!isset($value)) {
           unset($_SESSION[$key]);
           return;
        }
        $_SESSION[$key] = $value;
    }

    public function getSessionData($key) {
        if ($key === 'id') return session_id();
        return isset($_SESSION[$key]) ? $_SESSION[$key] : null;
    }

    protected function fail($message, $http_status = 500) {
        if (!empty($this->options['fail_exception'])) {
            throw new Exception($message, $http_status);
        }

        if ($http_status === 500) trigger_error($message, E_USER_WARNING);
        if ($this->returnType === 'jsonp') {
            echo $_REQUEST['callback'] . "(" . json_encode(['error' => $message]) . ", $http_status);";
            exit();
        }
        if ($this->returnType === 'redirect') {
            $url = $_REQUEST['return_url'] . '?sso_error=' . $message;
            header("Location: $url", true, 307);
            echo "You're being redirected to <a href='{$url}'>$url</a>";
            exit();
        }
        http_response_code($http_status);
        header('Content-type: application/json; charset=UTF-8');
        echo json_encode(['error' => $message]);
        exit();
    }

    protected function getBrokerInfo($brokerId) {
        $this->load->config('secrets');
        $brokers = $this->config->item('sso');
        return isset($brokers[$brokerId]) ? $brokers[$brokerId] : null;
    }

    public function userInfo() {
        $this->startBrokerSession();
        $userId = $this->session->userdata('sso_userId');
        log_message('DEBUG', 'passport/userinfo-userid->' .$userId);
        if ($userId) {
            $this->user = $this->getUserInfo($userId);
            if (!$this->user) return $this->fail("User not found", 500);
        }
        header('Content-type: application/json; charset=UTF-8');
        echo json_encode($this->user);
    }

    protected function getUserInfo($userId) {
        if($this->user){
            return $this->user;
        }
        $this->user = $this->user_model->getUserById($userId);
        unset($this->user->password);
    }
}
