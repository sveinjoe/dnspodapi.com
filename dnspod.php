<?php
/*
 * DNSPod API PHP Web 示例
 * http://www.likexian.com/
 *
 * Copyright 2011-2014, Kexian Li
 * Released under the Apache License, Version 2.0
 *
 */

class dnspod {
    public $grade_list = array(
        'D_Free' => '免费套餐',
        'D_Plus' => '豪华 VIP套餐',
        'D_Extra' => '企业I VIP套餐',
        'D_Expert' => '企业II VIP套餐',
        'D_Ultra' => '企业III VIP套餐',
        'DP_Free' => '新免费套餐',
        'DP_Plus' => '个人专业版',
        'DP_Extra' => '企业创业版',
        'DP_Expert' => '企业标准版',
        'DP_Ultra' => '企业旗舰版',
    );

    public $status_list = array(
        'enable' => '启用',
        'pause' => '暂停',
        'spam' => '封禁',
        'lock' => '锁定',
    );

    public function api_call($api, $data) {
        if ($api == '' || !is_array($data)) {
            $this->message('danger', '内部错误：参数错误', '');
        }

        $api = 'https://dnsapi.cn/' . $api;
        $data = array_merge($data, array('login_email' => $_SESSION['login_email'],
            'login_password' => $_SESSION['login_password'], 'login_code' => $_SESSION['login_code'],
            'format' => 'json', 'lang' => 'cn', 'error_on_empty' => 'no'));

        $result = $this->post_data($api, $data, $_SESSION['cookies']);
        if (!$result) {
            $this->message('danger', '内部错误：调用失败', '');
        }

        $result = explode("\r\n\r\n", $result);
        if (preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $result[0], $cookies)) {
            $_SESSION['login_code'] = '';
            foreach ($cookies[1] as $key => $value) {
                if (substr($value, 0, 1) == 't') {
                    $_SESSION['cookies'] = $value;
                }
            }
        }

        $results = @json_decode($result[1], 1);
        if (!is_array($results)) {
            $this->message('danger', '内部错误：返回异常', '');
        }
        
        if ($results['status']['code'] != 1 && $results['status']['code'] != 50) {
            $this->message('danger', $results['status']['message'], -1);
        }
        
        return $results;
    }

    public function get_template($template) {
        $text = file_get_contents('./template/' . $template . '.html');
        $master = file_get_contents('./template/index.html');
        $master = str_replace('{{content}}', $text, $master);
        return $master;
    }

    public function message($status, $message, $url=-1) {
        $text = $this->get_template('message');
        $text = str_replace('{{title}}', $status == 'success' ? '操作成功' : '操作失败', $text);
        $text = str_replace('{{status}}', $status, $text);
        $text = str_replace('{{message}}', $message, $text);
        $text = str_replace('{{url}}', $url, $text);
        exit($text);
    }

    private function post_data($url, $data, $cookie='') {
        if ($url == '' || !is_array($data)) {
            $this->message('danger', '内部错误：参数错误', '');
        }

        $ch = @curl_init();
        if (!$ch) {
            $this->message('danger', '内部错误：服务器不支持CURL', '');
        }

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_HEADER, 1);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_SSLVERSION, 1);
        curl_setopt($ch, CURLOPT_COOKIE, $cookie);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($ch, CURLOPT_USERAGENT, 'DNSPod API PHP Web Client/1.0.0 (i@likexian.com)');
        $result = curl_exec($ch);
        curl_close($ch);

        return $result;
    }
}
