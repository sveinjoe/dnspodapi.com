<?php
/*
 * DNSPod API PHP Web 示例
 * http://www.likexian.com/
 *
 * Copyright 2011-2014, Kexian Li
 * Released under the Apache License, Version 2.0
 *
 */

error_reporting(0);
header('Content-type:text/html; charset=utf-8');

require './dnspod.php';
$dnspod = new dnspod();
@session_start();

if ($_GET['action'] == 'domainlist') {
    if ($_POST['login_code'] == '') {
        if ($_POST['login_email'] == '') {
            if ($_SESSION['login_email'] == '') {
                $dnspod->message('danger', '请输入登录账号。', -1);
            }
        } else {
            $_SESSION['login_email'] = $_POST['login_email'];
        }

        if ($_POST['login_password'] == '') {
            if ($_SESSION['login_password'] == '') {
                $dnspod->message('danger', '请输入登录密码。', -1);
            }
        } else {
            $_SESSION['login_password'] = $_POST['login_password'];
        }

        $_SESSION['login_code'] = '';
    } else {
        $_SESSION['login_code'] = $_POST['login_code'];
    }

    $response = $dnspod->api_call('Domain.List', array());
    if ($response['status']['code'] == 50) {
        header('Location: ?action=logind');
        exit();
    }
    $list = '';
    $domain_sub = file_get_contents('./template/domain_sub.html');
    foreach ($response['domains'] as $id => $domain) {
    		if(!empty($_GET["cache"]) && $_GET["cache"] == "yes")
    		{
    			file_put_contents("cache/".trim($domain['name']) . ".txt", $domain['id']);
    		}
        $list_sub = str_replace('{{id}}', $domain['id'], $domain_sub);
        $list_sub = str_replace('{{domain}}', $domain['name'], $list_sub);
        $list_sub = str_replace('{{grade}}', $dnspod->grade_list[$domain['grade']], $list_sub);
        $list_sub = str_replace('{{status}}', $dnspod->status_list[$domain['status']], $list_sub);
        $list_sub = str_replace('{{status_new}}', $domain['status'] == 'pause' ? 'enable' : 'disable', $list_sub);
        $list_sub = str_replace('{{status_text}}', $domain['status'] == 'pause' ? '启用' : '暂停', $list_sub);
        $list_sub = str_replace('{{records}}', $domain['records'], $list_sub);
        $list_sub = str_replace('{{updated_on}}', $domain['updated_on'], $list_sub);
        $list .= $list_sub;
    }
		if(!empty($_GET["cache"]) && $_GET["cache"] == "yes")
		{
			$dnspod->message('success', '缓存成功。', '?action=domainlist');
			die();
		}
    $text = $dnspod->get_template('domain');
    $text = str_replace('{{title}}', '域名列表(共' . $response["info"]["domain_total"] . '个域名)<a href="/?action=domainlist&cache=yes">刷新缓存</a>', $text);
    $text = str_replace('{{list}}', $list, $text);
} elseif ($_GET['action'] == 'domaincreate') {
    if ($_POST['domain'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }

    $response = $dnspod->api_call('Domain.Create', array('domain' => $_POST['domain']));

    $dnspod->message('success', '添加成功。', '?action=domainlist');
} elseif ($_GET['action'] == 'domainstatus') {
    if ($_GET['domain_id'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }
    if ($_GET['status'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }

    $_SESSION['login_code'] = $_POST['login_code'];
    $response = $dnspod->api_call('Domain.Status', array('domain_id' => $_GET['domain_id'], 'status' => $_GET['status']));
    if ($response['status']['code'] == 50) {
        header('Location: ?action=domainstatusd&domain_id=' . $_GET['domain_id'] . '&status=' . $_GET['status']);
        exit();
    }

    $dnspod->message('success', ($_GET['status'] == 'enable' ? '启用' : '暂停') . '成功。', '?action=domainlist');
} elseif ($_GET['action'] == 'domainremove') {
    if ($_GET['domain_id'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }

    $_SESSION['login_code'] = $_POST['login_code'];
    $response = $dnspod->api_call('Domain.Remove', array('domain_id' => $_GET['domain_id']));
    if ($response['status']['code'] == 50) {
        header('Location: ?action=domainremoved&domain_id=' . $_GET['domain_id']);
        exit();
    }

    $dnspod->message('success', '删除成功。', '?action=domainlist');
} elseif ($_GET['action'] == 'batchsetrecordf') {
	$text = $dnspod->get_template('batchsetrecordf');
	$text = str_replace('{{title}}', "批量修改记录", $text);
	$text = str_replace('{{action}}', "batchsetrecord", $text);
} elseif ($_GET['action'] == 'batchsetrecord') {
	if(!empty($_POST["domainandips"]))
	{
		file_put_contents("domainandips.log", $_POST["domainandips"]);
	}
	if(file_exists("domainandips.log"))
	{
		//进度标记
		if(empty($_GET["count"]))
		{
			$count == 1;
		}
		else
		{
			$count = $_GET["count"];
		}
		$domainandips = file_get_contents("domainandips.log");
		$arrdomainandips = explode("\n", $domainandips);
		$currentcount = 0;
		//如果已经执行完毕，就删除domainandips.log并跳转到提示成功的页面
		if($count > count($arrdomainandips))
		{
			unlink("domainandips.log");
			$dnspod->message('success', '执行成功{$count}条修改或添加域名记录的命令', '?action=domainlist');
		}
		foreach($arrdomainandips as $domainandip)
		{
			//跳过已经执行的
			$currentcount++;
			if($currentcount < $count)
			{
				continue;
			}else
			{
				$count++;
			}
			if(strlen($domainandip) > 15)
			{
				$arr = explode("\t", $domainandip);
				$domain = trim($arr[0]);
				$ip = trim($arr[1]);
				$domainid = file_get_contents("cache/" . $domain . ".txt");
				if(!file_exists("cache/" . $domain . ".txt") || empty($domainid)) //如果域名id不存在，则退出
				{
					//1秒后跳转到下一步
					echo "<meta http-equiv=\"refresh\" content=\"1;url=/?action=batchsetrecord&count=" . $count . "\">";
					$errormsg = "域名{$domain}不存在，或者没有该域名的权限，请检查\n";
					file_put_contents("error.log", $errormsg, FILE_APPEND);
					die($errormsg);
				}
				//获取记录id
				$response = $dnspod->api_call('Record.List', array('domain_id' => $domainid));
				//遍历记录，如果找到"www"和"@"则记录ID，如果找不到则id为0
				$wwwid = 0;
				$atid = 0;
				foreach($response["records"] as $arrrecord)
				{
					if($arrrecord["type"] == "A")
					{
						if($arrrecord["name"] == "@")
						{
							$atid = $arrrecord["id"];
						}elseif($arrrecord["name"] == "www")
						{
							$wwwid = $arrrecord["id"];
						}
					}
				}
				//修改或者新增www记录
				if($wwwid == 0)
				{
					//新增记录
			    $response = $dnspod->api_call('Record.Create',
			        array('domain_id' => $domainid,
			            'sub_domain' => "www",
			            'record_type' => "A",
			            'record_line' => "默认",
			            'value' => $ip,
			            'mx' => 0,
			            'ttl' => 600,
			        )
			    );
			    echo "为域名{$domain}新增www记录值{$ip}"."<br>";
				}
				else
				{
					//修改记录
					$response = $dnspod->api_call('Record.Modify',
			        array('domain_id' => $domainid,
			            'record_id' => $wwwid,
			            'sub_domain' => "www",
			            'record_type' => "A",
			            'record_line' => "默认",
			            'value' => $ip,
			            'mx' => 0,
			            'ttl' => 600,
			        )
			    );
			    echo "为域名{$domain}修改www记录值{$ip}"."<br>";
				}
				//修改或者新增@记录
				if($atid == 0)
				{
					//新增记录
			    $response = $dnspod->api_call('Record.Create',
			        array('domain_id' => $domainid,
			            'sub_domain' => "@",
			            'record_type' => "A",
			            'record_line' => "默认",
			            'value' => $ip,
			            'mx' => 0,
			            'ttl' => 600,
			        )
			    );
			    echo "为域名{$domain}新增·记录值{$ip}"."<br>";
				}
				else
				{
					//修改记录
					$response = $dnspod->api_call('Record.Modify',
			        array('domain_id' => $domainid,
			            'record_id' => $atid,
			            'sub_domain' => "@",
			            'record_type' => "A",
			            'record_line' => "默认",
			            'value' => $ip,
			            'mx' => 0,
			            'ttl' => 600,
			        )
			    );
			    echo "为域名{$domain}修改@记录值{$ip}"."<br>";
				}
				//记录当前操作的域名
				
			}
			//1秒后跳转到下一步
			echo "<meta http-equiv=\"refresh\" content=\"1;url=/?action=batchsetrecord&count=" . $count . "\">";
			die();
		}
	}
	else
	{
		$dnspod->message('success', '没有找到需要执行的任务列表', '?action=domainlist');
	}
} elseif ($_GET['action'] == 'recordlist') {
    if ($_GET['domain_id'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }

    $response = $dnspod->api_call('Record.List', array('domain_id' => $_GET['domain_id']));
    $list = '';
    $record_sub = file_get_contents('./template/record_sub.html');
    foreach ($response['records'] as $id => $record) {
        $list_sub = str_replace('{{domain_id}}', $_GET['domain_id'], $record_sub);
        $list_sub = str_replace('{{id}}', $record['id'], $list_sub);
        $list_sub = str_replace('{{name}}', $record['name'], $list_sub);
        $list_sub = str_replace('{{value}}', $record['value'], $list_sub);
        $list_sub = str_replace('{{type}}', $record['type'], $list_sub);
        $list_sub = str_replace('{{line}}', $record['line'], $list_sub);
        $list_sub = str_replace('{{enabled}}', $record['enabled'] ? '启用' : '暂停', $list_sub);
        $list_sub = str_replace('{{status_new}}', $record['enabled'] ? 'disable' : 'enable', $list_sub);
        $list_sub = str_replace('{{status_text}}', $record['enabled'] ? '暂停' : '启用', $list_sub);
        $list_sub = str_replace('{{mx}}', $record['mx'] ? $record['mx'] : '-', $list_sub);
        $list_sub = str_replace('{{ttl}}', $record['ttl'], $list_sub);
        $list .= $list_sub;
    }

    $text = $dnspod->get_template('record');
    $text = str_replace('{{title}}', '记录列表 - ' . $response['domain']['name'], $text);
    $text = str_replace('{{list}}', $list, $text);
    $text = str_replace('{{domain_id}}', $response['domain']['id'], $text);
    $text = str_replace('{{grade}}', $response['domain']['grade'], $text);
} elseif ($_GET['action'] == 'recordcreatef') {
    if ($_GET['domain_id'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }

    if (!$_SESSION['type_' . $_GET['grade']]) {
        $response = $dnspod->api_call('Record.Type', array('domain_grade' => $_GET['grade']));
        $_SESSION['type_' . $_GET['grade']] = $response['types'];
    }

    if (!$_SESSION['line_' . $_GET['grade']]) {
        $response = $dnspod->api_call('Record.Line', array('domain_grade' => $_GET['grade']));
        $_SESSION['line_' . $_GET['grade']] = $response['lines'];
    }

    $type_list = '';
    foreach ($_SESSION['type_' . $_GET['grade']] as $key => $value) {
        $type_list .= '<option value="' . $value . '">' . $value . '</option>';
    }

    $line_list = '';
    foreach ($_SESSION['line_' . $_GET['grade']] as $key => $value) {
        $line_list .= '<option value="' . $value . '">' . $value . '</option>';
    }

    $text = $dnspod->get_template('recordcreatef');
    $text = str_replace('{{title}}', '添加记录', $text);
    $text = str_replace('{{action}}', 'recordcreate', $text);
    $text = str_replace('{{domain_id}}', $_GET['domain_id'], $text);
    $text = str_replace('{{record_id}}', $_GET['record_id'], $text);
    $text = str_replace('{{type_list}}', $type_list, $text);
    $text = str_replace('{{line_list}}', $line_list, $text);
    $text = str_replace('{{sub_domain}}', '', $text);
    $text = str_replace('{{value}}', '', $text);
    $text = str_replace('{{mx}}', '10', $text);
    $text = str_replace('{{ttl}}', '600', $text);
} elseif ($_GET['action'] == 'recordcreate') {
    if ($_GET['domain_id'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }

    if (!$_POST['sub_domain']) {
        $_POST['sub_domain'] = '@';
    }

    if (!$_POST['value']) {
        $dnspod->message('danger', '请输入记录值。', -1);
    }

    if ($_POST['type'] == 'MX' && !$_POST['mx']) {
        $_POST['mx'] = 10;
    }

    if (!$_POST['ttl']) {
        $_POST['ttl'] = 600;
    }
echo $_POST['mx'];die();
    $response = $dnspod->api_call('Record.Create',
        array('domain_id' => $_GET['domain_id'],
            'sub_domain' => $_POST['sub_domain'],
            'record_type' => $_POST['type'],
            'record_line' => $_POST['line'],
            'value' => $_POST['value'],
            'mx' => $_POST['mx'],
            'ttl' => $_POST['ttl'],
        )
    );

    $dnspod->message('success', '添加成功。', '?action=recordlist&domain_id=' . $_GET['domain_id']);
} elseif ($_GET['action'] == 'recordeditf') {
    if ($_GET['domain_id'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }
    if ($_GET['record_id'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }

    $response = $dnspod->api_call('Record.Info', array('domain_id' => $_GET['domain_id'], 'record_id' => $_GET['record_id']));
    $record = $response['record'];

    if (!$_SESSION['type_' . $_GET['grade']]) {
        $response = $dnspod->api_call('Record.Type', array('domain_grade' => $_GET['grade']));
        $_SESSION['type_' . $_GET['grade']] = $response['types'];
    }

    if (!$_SESSION['line_' . $_GET['grade']]) {
        $response = $dnspod->api_call('Record.Line', array('domain_grade' => $_GET['grade']));
        $_SESSION['line_' . $_GET['grade']] = $response['lines'];
    }

    $type_list = '';
    foreach ($_SESSION['type_' . $_GET['grade']] as $key => $value) {
        $type_list .= '<option value="' . $value . '" ' . ($record['record_type'] == $value ? 'selected="selected"' : '') . '>' . $value . '</option>';
    }

    $line_list = '';
    foreach ($_SESSION['line_' . $_GET['grade']] as $key => $value) {
        $line_list .= '<option value="' . $value . '" ' . ($record['record_line'] == $value ? 'selected="selected"' : '') . '>' . $value . '</option>';
    }

    $text = $dnspod->get_template('recordcreatef');
    $text = str_replace('{{title}}', '修改记录', $text);
    $text = str_replace('{{action}}', 'recordedit', $text);
    $text = str_replace('{{domain_id}}', $_GET['domain_id'], $text);
    $text = str_replace('{{record_id}}', $_GET['record_id'], $text);
    $text = str_replace('{{type_list}}', $type_list, $text);
    $text = str_replace('{{line_list}}', $line_list, $text);
    $text = str_replace('{{sub_domain}}', $record['sub_domain'], $text);
    $text = str_replace('{{value}}', $record['value'], $text);
    $text = str_replace('{{mx}}', $record['mx'], $text);
    $text = str_replace('{{ttl}}', $record['ttl'], $text);
} elseif ($_GET['action'] == 'recordedit') {
    if ($_GET['domain_id'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }
    if ($_GET['record_id'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }

    if (!$_POST['sub_domain']) {
        $_POST['sub_domain'] = '@';
    }

    if (!$_POST['value']) {
        $dnspod->message('danger', '请输入记录值。', -1);
    }

    if ($_POST['type'] == 'MX' && !$_POST['mx']) {
        $_POST['mx'] = 10;
    }

    if (!$_POST['ttl']) {
        $_POST['ttl'] = 600;
    }

    $response = $dnspod->api_call('Record.Modify',
        array('domain_id' => $_GET['domain_id'],
            'record_id' => $_GET['record_id'],
            'sub_domain' => $_POST['sub_domain'],
            'record_type' => $_POST['type'],
            'record_line' => $_POST['line'],
            'value' => $_POST['value'],
            'mx' => $_POST['mx'],
            'ttl' => $_POST['ttl'],
        )
    );

    $dnspod->message('success', '修改成功。', '?action=recordlist&domain_id=' . $_GET['domain_id']);
} elseif ($_GET['action'] == 'recordremove') {
    if ($_GET['domain_id'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }
    if ($_GET['record_id'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }

    $response = $dnspod->api_call('Record.Remove',
        array('domain_id' => $_GET['domain_id'],
            'record_id' => $_GET['record_id'],
        )
    );

    $dnspod->message('success', '删除成功。', '?action=recordlist&domain_id=' . $_GET['domain_id']);
} elseif ($_GET['action'] == 'recordstatus') {
    if ($_GET['domain_id'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }
    if ($_GET['record_id'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }
    if ($_GET['status'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }

    $response = $dnspod->api_call('Record.Status',
        array('domain_id' => $_GET['domain_id'],
            'record_id' => $_GET['record_id'],
            'status' => $_GET['status'],
        )
    );

    $dnspod->message('success', ($_GET['status'] == 'enable' ? '启用' : '暂停') . '成功。', '?action=recordlist&domain_id=' . $_GET['domain_id']);
} elseif ($_GET['action'] == 'domainstatusd') {
    if ($_GET['domain_id'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }
    if ($_GET['status'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }
    $text = $dnspod->get_template('logind');
    $text = str_replace('{{title}}', '域名' . ($_GET['status'] == 'enable' ? '启用' : '暂停'), $text);
    $text = str_replace('{{action}}', 'domainstatus&domain_id=' . $_GET['domain_id'] . '&status=' . $_GET['status'], $text);
} elseif ($_GET['action'] == 'domainremoved') {
    if ($_GET['domain_id'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }
    $text = $dnspod->get_template('logind');
    $text = str_replace('{{title}}', '域名删除', $text);
    $text = str_replace('{{action}}', 'domainremove&domain_id=' . $_GET['domain_id'], $text);
} elseif ($_GET['action'] == 'logind') {
    if ($_SESSION['login_email'] == '' || $_SESSION['login_password'] == '') {
        $dnspod->message('danger', '参数错误。', -1);
    }
    $text = $dnspod->get_template('logind');
    $text = str_replace('{{title}}', '用户登录', $text);
    $text = str_replace('{{action}}', 'domainlist', $text);
} else {
    $text = $dnspod->get_template('login');
    $text = str_replace('{{title}}', '用户登录', $text);
}

echo $text;
