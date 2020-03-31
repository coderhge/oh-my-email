#!/bin/sh

# 合并所有upgradenew,目前支持所有wios的产品


#日志记录
logger_to_logread()
{
log_message=$1
if [ -n "${log_message}" ];then
    if [ "${debug_flag}" = "0" ];then
        logger -t "${main_logger_key}" "${log_message}"
    else
        logger -s -t "${main_logger_key}" "${log_message}"
    fi
fi
}

# 在线时间
get_uptime()
{
for i in $(seq 1 6)
do
    main_uptime=$(cat /proc/uptime|awk '{print $1}'|awk -F '.' '{print $1}'|head -1)
    if [ -n "${main_uptime}" ];then
        break
    fi
    sleep 1
done
if [ ! -n "${main_uptime}" ];then
    main_uptime=0
fi
}

# 版本号
get_version()
{
if [ ! -f "/etc/robin_version" ];then
    main_version="no_robin_file"
else
    for i in $(seq 1 6)
    do
        main_version=$(cat /etc/robin_version|head -1)
        if [ -n "${main_version}" ];then
            break
        fi
        sleep 1
    done
fi
}

# 设备mac
get_mac()
{
for i in $(seq 1 6)
do
    main_mac_uci=$(mtdconfig get mac|tr '[a-z]' '[A-Z]'|head -1)
    if [ -n "${main_mac_uci}" ];then
        break
    fi
    sleep 1
done
}

# 产品名称
get_product()
{
for i in $(seq 1 6)
do
    main_product_uci=$(mtdconfig get product|head -1)
    if [ -n "${main_product_uci}" ];then
        break
    fi
    sleep 1
done
}

# 获取tmp的剩余内存
get_tmp_memory()
{
for i in $(seq 1 6)
do
    main_tmp_memory=$(df|grep "/tmp"|awk '{print $4}'|head -1)
    if [ -n "${main_tmp_memory}" ];then
        break
    fi
    sleep 1
done
}

# 获取设备运行模式,#1是路由,0是桥,2是网监旁路,3是portal旁路,4是网监旁路
get_mode()
{
for i in $(seq 1 6)
do
    main_mode_id=$(uci get system.basic.mode|head -1)
    if [ -n "${main_mode_id}" ];then
        break
    fi
    sleep 1
done

#1是路由,0是桥,2,4是网监旁路,3是portal旁路
if [ "${main_mode_id}" = "1" ];then
	main_mode_proto=$(uci get network.wan.proto)
	main_mode_en="router"
elif [ "${main_mode_id}" = "0" ];then
	main_mode_proto=$(uci get network.lan.proto)
	main_mode_en="bridge"
elif [ "${main_mode_id}" = "2" ];then
	main_mode_proto=$(uci get network.wan.proto)
	main_mode_en="panggua_wj_double"
elif [ "${main_mode_id}" = "3" ];then
	main_mode_proto=$(uci get network.lan.proto)
	main_mode_en="panggua_portal"
elif [ "${main_mode_id}" = "4" ];then
	main_mode_proto=$(uci get network.lan.proto)
	main_mode_en="panggua_wj_single"
else
	main_mode_proto="not_support"
	main_mode_en="not_support_$main_mode_id"
fi
}

# 获取update服务器地址
get_update_url()
{
for i in $(seq 1 6)
do
    main_update_server=$(uci get system.update.server|head -1)
    if [ -n "${main_update_server}" ];then
        break
    fi
    sleep 1
done
}

# 日志上传到固定服务器基础脚本,可以追加
post_curl_message()
{
post_curl_port=$1
# 日志类型 Error , Info
log_level=$2
# 错误类型
check_result=$3
# 错误详情
check_detail=$4
get_uptime
main_post_message_json="{\"loggerKey\":\"${main_logger_key}\",\"mac\":\"${main_mac_uci}\",\"product\":\"${main_product_uci}\",\"version\":\"${main_version}\",\"mode\":\"${main_mode_en}\",\"runDuration\":\"${main_uptime}\",\"scriptVersion\":\"${script_version}\",\"logLevel\":\"${log_level}\",\"checkResult\":\"${check_result}\",\"checkDetail\":\"${check_detail}\",\"port\":\"${post_curl_port}\"}"
logger_to_logread "run post_curl start,port=${post_curl_port},main_post_message_json=${main_post_message_json}"

post_curl_file="/tmp/${main_logger_key}"
post_is_ok=0
for i in $(seq 1 6)
do
    if [ -f "${post_curl_file}" ];then
        rm ${post_curl_file}
    fi
    post_http_code=$(curl -4 --connect-timeout 30 --speed-time 30 --speed-limit 1 -m 30 -w %{http_code} -d "${main_post_message_json}" http://123.206.65.61:${post_curl_port} -o ${post_curl_file})
    post_curl_code=$?
    logger_to_logread "try_num=${i},port=${post_curl_port},post_http_code=${post_http_code},post_curl_code=${post_curl_code}"
    if [ "${post_http_code}" = "200" ]&&[ "${post_curl_code}" = "0" ];then
        post_is_ok=$(cat ${post_curl_file}|head -1|grep "^ok"|wc -l)
        if [ "$post_is_ok" = "1" ];then
            break
        fi
    fi
    sleep 2
done
logger_to_logread "run post_curl end,port=${post_curl_port}"
}

#从服务器下载文件用,从wios开始
download_curl_file_wios()
{
tmp_suffix=$1
local_file=$2
num_max=$3
if [ ! -n "$num_max" ];then
    num_max=6
fi
remote_file="https://upgrade.wiwide.com/wios/${tmp_suffix}"
logger_to_logread "run download start,file=${local_file},remote_file=${remote_file}"
download_success=0
for i in $(seq 1 $num_max)
do
    if [ -f "${local_file}" ];then
        rm ${local_file}
    fi
    download_http_code=$(curl -4 --insecure --connect-timeout 60 --speed-time 30 --speed-limit 1 -w %{http_code} "${remote_file}" -o ${local_file})
    download_curl_code=$?
    logger_to_logread "try_num=${i},tmp_suffix=${tmp_suffix},download_http_code=${download_http_code},download_curl_code=${download_curl_code}"
    if [ "${download_http_code}" = "200" ]&&[ "${download_curl_code}" = "0" ];then
        download_success=1
        break
    fi
    sleep 5
done
logger_to_logread "run download end,file=${local_file},remote_file=${remote_file}"
}

# 脚本加权限
check_chmod_and_run()
{
script_file=$1
if_back=$2
for i in $(seq 1 6)
do
    logger_to_logread "chmod $script_file"
    chmod 777 $script_file
    chmod_num=$(ls -l ${script_file}|awk '{print $1}'|grep -o x|wc -l)
    if [ "${chmod_num}" = "3" ];then
        break
    fi
    sleep 1

done
if [ "${if_back}" = "1" ];then
    $script_file
    run_ret=$?
    file_num=$(cat ${script_file}|wc -l)
    logger_to_logread "run $script_file code=${run_ret},file_num=${file_num}"
else
    $script_file &
    logger_to_logread "run ${script_file} to back"
fi

}

####################以上是通用函数与device_detection一致####################

####################以下是通用功能####################

# 检测网监是否是最新插件
get_wj_update()
{
if [ "$main_product_uci" = "W1210" ]||[ "$main_product_uci" = "W1211" ];then
    wj_up_version="v2.2.14"
elif [ "$main_product_uci" = "W1240" ];then
    wj_up_version="v2.2.14"
elif [ "$main_product_uci" = "W3022" ];then
    wj_up_version="v2.2.14"
elif [ "$main_product_uci" = "W3023" ];then
    wj_up_version="v2.2.14"
elif [ "$main_product_uci" = "W3024" ]||[ "$main_product_uci" = "W3060" ];then
    wj_up_version="v2.2.14"
elif [ "$main_product_uci" = "W3420" ]||[ "$main_product_uci" = "W3520" ];then
    wj_up_version="v2.2.14"
fi

logger_to_logread "run wj update start $wj_up_version"
wj_tar="wiwide_${main_product_uci}.tar.bz2"
wiwide_file="/tmp/plugin/wiwide/wiwide.sh"
if [ "${main_wj_enable}" = "1" ]&&[ "${main_wj_type}" = "6" ]&&[ "${main_uptime}" -ge "3000" ];then
    wj_path="/tmp/plugin/wiwide"
    if [ "$main_product_uci" = "W1211" ]||[ "$main_product_uci" = "W1210" ]||[ "$main_product_uci" = "W1240" ];then
        if [ "$main_mode_id" = "0" ];then
            logger_to_logread "ap bridge not use wj"
            return 1
        fi
    fi
    
    if [ ! -f "$wiwide_file" ];then
        wj_old_version="0"
    else
        wj_old_version=$(cat $wiwide_file|grep "wiwide.version"|awk -F '=' '{print $2}'|head -1)
        last_old=$(echo $wj_old_version|awk -F '.' '{print $3}')
        last_now=$(echo $wj_up_version|awk -F '.' '{print $3}')
        if [ "${last_old}" -lt "${last_now}" ];then
            logger_to_logread "wiwide plugin lt now"
            return 1
        fi
    fi
        
	if [ "${wj_old_version}" = "${wj_up_version}" ];then
        ps_wj=$(ps|grep wjwatchdog|grep -v grep|wc -l)
        if [ "$ps_wj" = "0" ];then
            $wj_path/wiwide.sh load
            post_curl_message "60001" "P1" "wj_not_load" "wiwide plugin already but not run,so run it"
            logger_to_logread "wiwide plugin already but not run,so run it"
        else
            logger_to_logread "wiwide plugin already the latest"
        fi
		return 1
	fi

    tmp_tar="/tmp/$wj_tar"
    download_curl_file_wios "${main_product_uci}/plugin/${wj_tar}" "$tmp_tar"
    if [ "$download_success" != "1" ];then
        logger_to_logread "wj download fail"
        post_curl_message "60001" "P0" "wj_download_fail" "wj download fail"
        return 1
    fi

    if [ ! -d "$wj_path" ];then
        logger_to_logread "wj path not found"
        post_curl_message "60001" "P1" "wj_path_not_found" "wj path not found"
    else
        if [ -f "$wj_path/wiwide.sh" ];then
            $wj_path/wiwide.sh unload
            if [ -d "$wj_path" ];then
                logger_to_logread "wj unload fail"
                post_curl_message "60001" "P0" "wj_unload_fail" "wj unload fail"
                return 1
            fi
        fi
    fi
    mkdir $wj_path
    tar -jxf "${tmp_tar}" -C "${wj_path}/"
    $wj_path/wiwide.sh load
	wj_now_version=$(cat $wiwide_file|grep "wiwide.version"|awk -F '=' '{print $2}'|head -1)
	if [ "${wj_now_version}" = "${wj_up_version}" ];then
		logger_to_logread "wiwide plugin upgrade success"
	else
		logger_to_logread "wiwide plugin upgrade failed"
        post_curl_message "60001" "P0" "wj_upgrade_fail" "wiwide plugin upgrade failed"
	fi
fi
logger_to_logread "run wj update end"

}

# 数据上报到上海的wdc平台用于进行网监校准,并上报到我们自己的平台,60100端口
upload_to_wdc()
{
logger_to_logread "run upload to wdc start"
audit_url=$(uci get system.netmonitor.url)
audit_port=$(uci get system.netmonitor.port)
sniffer_enable=$(uci get system.sniffer.enable)
sniffer_server=$(uci get system.sniffer.server)
sniffer_port=$(uci get system.sniffer.port)
sniffer_path=$(uci get system.sniffer.path)
ns_version=""
if [ -f "/tmp/plugin/wiwide/wiwide.sh" ];then
    ns_version=$(cat /tmp/plugin/wiwide/wiwide.sh|grep "wiwide.version"|awk -F '=' '{print $2}'|head -1)
fi
if [ -f "$main_tmp_logread_file" ];then
    last_login=$(cat $main_tmp_logread_file|grep Login|tail -1|awk -F '}' '{print $1}'|awk -F '{' '{print $2}')
else
    last_login=""
fi
post_to_wdc="{\"mac\":\"${main_mac_uci}\",\"version\":\"${main_version}\",\"product\":\"${main_product_uci}\",\"mode\":\"${main_mode_id}\",\"audit_enable\":\"${main_wj_enable}\",\"audit_type\":\"${main_wj_type}\",\"audit_url\":\"${audit_url}\",\"audit_port\":\"${audit_port}\",\"sniffer_enable\":\"${sniffer_enable}\",\"sniffer_server\":\"${sniffer_server}\",\"sniffer_port\":\"${sniffer_port}\",\"sniffer_path\":\"${sniffer_path}\",\"ns_version\":\"${ns_version}\",\"last_login\":\"${last_login}\"}"
logger_to_logread "post wdc value = $post_to_wdc"

wj_http_code=$(curl -4 --connect-timeout 30 --speed-time 30 --speed-limit 1 -m 50 -w %{http_code} -H "Content-type: application/json" -X POST -d "${post_to_wdc}" http://wdc.wiwide.com:8071/ns/status  -o /dev/null)
wj_curl_code=$?
logger_to_logread "run wj_http_code=${wj_http_code},wj_curl_code=${wj_curl_code},upload to wdc end"
post_to_send="wj_http_code=${wj_http_code},wj_curl_code=${wj_curl_code},mode=${main_mode_id},audit_enable=${main_wj_enable},audit_type=${main_wj_type},audit_url=${audit_url},audit_port=${audit_port},sniffer_enable=${sniffer_enable},sniffer_server=${sniffer_server},sniffer_port=${sniffer_port},sniffer_path=${sniffer_path},ns_version=${ns_version},last_login=${last_login}"
post_curl_message "60100" "Info" "upload_t_wdc" "$post_to_send"
}

# 版本号比大小
check_version_lt()
{
no_use_version=$1
logger_to_logread "run check version lt ${no_use_version}"
if_v=$(echo "${main_version}"|grep v|wc -l)
if [ "${if_v}" = "0" ];then
    return 0
fi
main_version_1=$(echo ${main_version}|awk -F 'v' '{print $2}'|awk -F '.' '{print $1}')
no_use_version_1=$(echo ${no_use_version}|awk -F 'v' '{print $2}'|awk -F '.' '{print $1}')
main_version_2=$(echo ${main_version}|awk -F 'v' '{print $2}'|awk -F '.' '{print $2}'|awk '{printf("%05d",$0)}')
no_use_version_2=$(echo ${no_use_version}|awk -F 'v' '{print $2}'|awk -F '.' '{print $2}'|awk '{printf("%05d",$0)}')
main_version_3=$(echo ${main_version}|awk -F 'v' '{print $2}'|awk -F '.' '{print $3}'|awk -F '_' '{print $1}'|awk -F '-' '{print $1}'|awk -F 'T' '{print $1}'|awk '{printf("%05d",$0)}')
no_use_version_3=$(echo ${no_use_version}|awk -F 'v' '{print $2}'|awk -F '.' '{print $3}'|awk -F '_' '{print $1}'|awk -F '-' '{print $1}'|awk -F 'T' '{print $1}'|awk '{printf("%05d",$0)}')
main_version_4=$(echo ${main_version}|awk -F 'T' '{print $2}'|awk -F '_' '{print $1}')
no_use_version_4=$(echo ${no_use_version}|awk -F 'T' '{print $2}'|awk -F '_' '{print $1}')
verison_1=$main_version_1$main_version_2$main_version_3
verison_2=$no_use_version_1$no_use_version_2$no_use_version_3
lt_num=0

if [ "${verison_1}" -lt "${verison_2}" ];then
    logger_to_logread "main_version ${main_version} -lt no_use_version ${no_use_version}"
    lt_num=1

elif [ "${verison_1}" -eq "${verison_2}" ];then
    if [ -n "${main_version_4}" ] && [ -n "${upgrade_version_4}" ];then
        if [ "${main_version_4}" -lt "${upgrade_version_4}" ];then
            logger_to_logread "all have T,main_version ${main_version} -lt upgrade_version ${upgrade_version}"
            lt_num=1
        fi
    fi
fi
return $lt_num

}

#下载upgrade.sh并执行
download_upgrade_sh()
{
logger_to_logread "run download_upgrade_sh"
upgrade_sh_file="/tmp/upgrade.sh"
download_curl_file_wios "${main_product_uci}/upgrade.sh" "$upgrade_sh_file"
if [ "${download_success}" = "1" ];then
	check_chmod_and_run "$upgrade_sh_file" "1"
#else
#    post_curl_message "60001" "download_upgrade_sh_fail,http_code=${download_http_code}"
#	if [ "${download_curl_code}" = "0" ];then
#		logger_to_logread "download upgrade.sh ok,but https code not 200,is ${download_http_code}"
#	else
#		logger_to_logread "download upgrade.sh fail"
#	fi
fi
}


####################以上是通用功能####################

####################以下设备检查自身并上报服务器历史8086的函数####################

#上报8086日志的二次封装
post_curl_to_8086()
{
log_level=$1
check_result=$2
check_detail=$3
curl_port=8086
logger_to_logread "run post_curl_to_8086 $check_detail"
if [ "$main_product_uci" = "W1210" ]||[ "$main_product_uci" = "W1211" ];then
	result_key="wios-W3_"
elif [ "$main_product_uci" = "W1240" ]||[ "$main_product_uci" = "W1241" ];then
	result_key="wios-W3s_"
elif [ "$main_product_uci" = "W1242" ]||[ "$main_product_uci" = "W1243" ];then
	result_key="wios-WP_"
elif [ "$main_product_uci" = "W3022" ];then
	result_key="wios-WMM_"
elif [ "$main_product_uci" = "W3023" ];then
	result_key="wios-WMT_"
elif [ "$main_product_uci" = "W3024" ]||[ "$main_product_uci" = "W3060" ];then
	result_key="wios-WMXP_"
elif [ "$main_product_uci" = "W3061" ];then
	result_key="wios-WMD_"
elif [ "$main_product_uci" = "W3420" ]||[ "$main_product_uci" = "W3520" ];then
	result_key="wios-WMMW_"
else
	result_key="wios-nosupport_"
fi
main_post8086_message_json="{\"loggerKey\":\"8086log\",\"mac\":\"${main_mac_uci}\",\"product\":\"${main_product_uci}\",\"version\":\"${main_version}\",\"mode\":\"${main_mode_en}\",\"runDuration\":\"${main_uptime}\",\"scriptVersion\":\"${script_version}\",\"logLevel\":\"${log_level}\",\"checkResult\":\"${check_result}\",\"checkDetail\":\"${check_detail}\",\"port\":\"8086\"}"
logger_to_logread "run post_curl,MAC=${main_mac_uci},port=${curl_port},main_post8086_message_json=${main_post8086_message_json}"

result_post_http_code=$(curl -4 --connect-timeout 30 --speed-time 30 --speed-limit 1 -w %{http_code} -d "${main_post8086_message_json}" http://123.206.65.61:8086 -o /dev/null)
result_post_curl_code=$?
logger_to_logread "result_post_http_code=${result_post_http_code},result_post_curl_code=$result_post_curl_code"

}

#通过检查logread对应文件,匹配次数
check_logread_file_num_to_8086()
{
up_value=$1
check_key1=$2
check_key2=$3
if [ -f "$main_tmp_logread_file" ];then
    if [ -n "$check_key2" ];then
        keyword_num=$(cat $main_tmp_logread_file|grep "${main_date_last_hours}"|grep -v "$main_logger_key"|grep "$check_key1"|grep "$check_key2"|wc -l)
    else
        keyword_num=$(cat $main_tmp_logread_file|grep "${main_date_last_hours}"|grep -v "$main_logger_key"|grep "$check_key1"|wc -l)
    fi

    if [ "$keyword_num" != "0" ];then
        post_curl_to_8086 "P2" "${up_value}" "${up_value}=${keyword_num}"
    fi
fi
}

#全产品用的8086检查项
check_all_product_8086_log()
{
logger_to_logread "run check_up_to_8086"

#判断mtd中的产品mac
logger_to_logread "check mac_mtd"
get_mac_mtd=$(mtdconfig get mac|tr '[a-z]' '[A-Z]'|head -1)
if [ "$get_mac_mtd" != "$main_mac_uci" ];then
	post_curl_to_8086 "P2" "mtd_mac_error" "mtd_mac_error=${get_mac_mtd}"
fi


###Check memery leak###
logger_to_logread "check memery leak"
if [ -f "$main_tmp_logread_file" ];then
    memleak=$(cat $main_tmp_logread_file|grep "Call Trace"|grep -v "$main_logger_key"|wc -l)
    kick_times=$(cat $main_tmp_logread_file|grep "kick out msg fail"|grep -v "$main_logger_key"|wc -l)
    if [ "${memleak}" != "0" ] && [ "${kick_times}" = "0" ];then
        top_num=$(top -bn 1|grep COMMAND|grep " CPU"|wc -l)
        if [ "$top_num" = "0" ];then
            topm=$(top -bn 1|awk '{print $5,$8}'|sed '1,4d'|grep -v "top"|sort -r -n -k 1 -t ' '|head -5|tr '\n' ','|tr ' ' '_')
        else
            topm=$(top -bn 1|awk '{print $5,$9}'|sed '1,4d'|grep -v "top"|sort -r -n -k 1 -t ' '|head -5|tr '\n' ','|tr ' ' '_')
        fi
        post_curl_to_8086 "P2" "memery_leak" "memery_leak=${memleak}_${topm}"
    fi
fi

###check the most high process mem is higher than 80%###
logger_to_logread "check top mem"
top1_mem=$(top -bn 1|awk '{print $6}'|sed '1,4d'|sort -r -n|head -1|sed 's/%//g'|awk -F '.' '{print $1}')
if [ ${top1_mem} -gt "80" ];then
	top_num=$(top -bn 1|grep COMMAND|grep " CPU"|wc -l)
	if [ "$top_num" = "0" ];then
		top3_processs=$(top -bn 1|awk '{print $6,$8}'|sed '1,4d'|grep -v "top"|grep -v "bn"|sort -n -r|head -3|tr '\n' ','|tr ' ' '_')
	else
		top3_processs=$(top -bn 1|awk '{print $6,$9}'|sed '1,4d'|grep -v "top"|grep -v "bn"|sort -n -r|head -3|tr '\n' ','|tr ' ' '_')
	fi
	post_curl_to_8086 "P2" "process_mem_high" "process_mem_high=${top3_processs}"
fi

###check segfault###
logger_to_logread "check segfault"
check_logread_file_num_to_8086 "segfault" "segfault"

###check No username found in login request repeat reboot###
logger_to_logread "check No username found"
check_logread_file_num_to_8086 "no_username_found_in_login_request" "No username found in login request"

###check wiportal repeat reboot###
logger_to_logread "check wiportal"
check_logread_file_num_to_8086 "repeat_reboot_process_wiportal" "checkprocess" "wiportal"

###check wimonitor repeat reboot###
logger_to_logread "check wimonitor"
check_logread_file_num_to_8086 "repeat_reboot_process_wimonitor" "checkprocess" "wimonitor"

###check wiupdate repeat reboot###
logger_to_logread "check wiupdate"
check_logread_file_num_to_8086 "repeat_reboot_process_wiupdate" "checkprocess" "wiupdate"

###check udpclient repeat reboot###
logger_to_logread "check udpclient"
check_logread_file_num_to_8086 "repeat_reboot_process_udpclient" "checkprocess" "udpclient"

###check dnsmasq repeat reboot###
logger_to_logread "check dnsmasq"
check_logread_file_num_to_8086 "repeat_reboot_process_dnsmasq" "checkprocess" "dnsmasq"

###check dnslearn repeat reboot###
logger_to_logread "check dnslearn"
check_logread_file_num_to_8086 "repeat_reboot_process_dnslearn" "checkprocess" "dnslearn"

###check fcgi repeat reboot###
logger_to_logread "check fcgi"
check_logread_file_num_to_8086 "repeat_reboot_process_fcgi" "checkprocess" "fcgi"

###check capwap repeat reboot###
logger_to_logread "check capwap"
check_logread_file_num_to_8086 "repeat_reboot_process_capwap" "checkprocess" "capwap"

###device repeat reboot###
logger_to_logread "check device repeat reboot num"
syslog_nowsec=$(echo ${main_now_sec}|awk '{print strftime ("%b\t%e",$0)}')
repeatreboot=$(cat /data/log/syslog|grep "boot"|grep "Device"|grep "${syslog_nowsec}"|wc -l)
if [ "${repeatreboot}" -gt "8" ];then
	post_curl_to_8086 "P0" "device_repeat_reboot" "device_repeat_reboot=${repeatreboot}"
fi

###check data mount###
logger_to_logread "check data mount"
data_exist=$(ls -l /data/*|wc -l)
if [ "$data_exist" = "0" ];then
	post_curl_to_8086 "P1" "data_mount_fail" "data_mount_fail"
fi
###check etc mount###
logger_to_logread "check etc mount"
etc_config_exist=$(ls -l /etc/config/*|wc -l)
if [ "$etc_config_exist" = "0" ];then
	post_curl_to_8086 "P1" "etc_config_mount_fail" "etc_config_mount_fail"
fi

###检查是否可以读写
logger_to_logread "check data rw"
data_rw=$(mount|grep "/data"|awk '{print $6}'|awk -F '(' '{print $2}'|awk -F ',' '{print $1}')
if [ ! "$data_rw" = "rw" ];then
	post_curl_to_8086 "P1" "data_not_rw" "data_not_rw"
fi

###检查是否可以读写
logger_to_logread "check etc rw"
etc_config_rw=$(mount|grep "etc"|grep "config"|awk '{print $6}'|awk -F '(' '{print $2}'|awk -F ',' '{print $1}')
if [ ! "$etc_config_rw" = "rw" ];then
	post_curl_to_8086 "P1" "etc_config_not_rw" "etc_config_not_rw"
fi

### 检查s99###
check_s99widone_num=$(ps |grep S99widone|grep -v grep|wc -l)
sys_uptime=$(cat /proc/uptime|awk '{split($0,a,".");print a[1]}')
date_time=$(date |awk '{print $4}'|awk -F ':' '{print $1}')
if [ "$check_s99widone_num" -gt "0" ]&&[ "$sys_uptime" -ge "1200" ];then
    post_curl_to_8086 "P2" "device_have_s99widone" "device_have_s99widone"
    if [ "$sys_uptime" -ge "36000" ]&&[ "$date_time" -le "3" ];then
        killall -9 watchdog
    fi
else
    ### 检查mt7601Usta
    check_mt7601_num=$(ps|grep "mt7601Usta.ko"|grep "D"|grep -v grep|wc -l)
    if [ "$check_mt7601_num" -gt "0" ]&&[ "$sys_uptime" -ge "1200" ];then
        post_curl_to_8086 "Info" "device_have_mt7601Usta" "device_have_mt7601Usta"
        if [ "$sys_uptime" -ge "36000" ]&&[ "$date_time" -le "3" ];then
            killall -9 watchdog
        fi
    fi
fi
}

#上传到服务器8086的日志中
check_up_to_8086()
{
###全产品支持的8086检查项
check_all_product_8086_log

###部分产品支持的8086检查项
if [ "$main_product_uci" = "W1211" ]||[ "$main_product_uci" = "W1210" ]||[ "$main_product_uci" = "W1240" ];then
	###check 5g crash
	if [ "$main_product_uci" = "W1211" ]||[ "$main_product_uci" = "W1210" ];then
	###5G init failed###
	logger_to_logread "check 5G init"
	check_logread_file_num_to_8086 "asic_not_ready" "AsicNotReady"

	###ip dst more 15000
	logger_to_logread "check ip dst"
	ip_dst_more=$(cat /proc/slabinfo|grep "ip_dst"|awk '{print $2}')
		if [ "$ip_dst_more" -ge "15000" ];then
			post_curl_to_8086 "P2" "ip_dst_more" "ip_dst_more=${ip_dst_more}"
		fi
	fi
fi

if [ "$main_product_uci" = "W1211" ]||[ "$main_product_uci" = "W1210" ]||[ "$main_product_uci" = "W1240" ]||[ "$main_product_uci" = "W1241" ]||[ "$main_product_uci" = "W1242" ]||[ "$main_product_uci" = "W1243" ];then
	###check wireless attack###
	logger_to_logread "check wireless attack"
	check_logread_file_num_to_8086 "wireless_attack" "Phishing Attack"
fi
}

####################以上设备检查自身并上报服务器历史8086的函数####################

####################以下设备打补丁对应函数####################

#函数名以产品型号开头,全产品则是all,方便后续维护

# 设备system配置
check_config_file()
{
logger_to_logread "run check_config_file"
    get_config_file()
    {
    file_name=$1
    check_file="/etc/config/${file_name}"
    if [ ! -f "${check_file}" ];then
        post_curl_message "60001" "P1" "config_lost_file" "${file_name}_not_exist"
    else
        num_line=$(cat $check_file|wc -l)
        if [ "${num_line}" = "0" ];then
            post_curl_message "60001" "P1" "config_lost_file" "${file_name}_no_line"
        fi
    fi
    }
get_config_file "system"
get_config_file "luci"
get_config_file "firewall"
get_config_file "network"
get_config_file "portal"

}

# 确认dmesg中是否有catch异常
path_all_dmesg_error()
{
tmp_error_file="/tmp/test_dmesg_error"
error_num=$(dmesg|grep "SQUASHFS error"|wc -l)
clean_num=0
if [ ! -f "${tmp_error_file}" ]&&[ "${error_num}" != "0" ];then
    clean_num=1
elif [ -f "${tmp_error_file}" ]&&[ "${error_num}" != "0" ];then
    old_error_num=$(cat ${tmp_error_file}|head -1)
    if [ "${old_error_num}" -gt "${error_num}" ];then
        clean_num=1
    fi 
fi
if [ "${error_num}" != "0" ];then
    echo "${error_num}" > ${tmp_error_file}
fi

if [ "${clean_num}" = "1" ];then
    post_curl_message "60001" "P1" "SQUASHFS_Error" "SQUASHFS_error_${error_num}"
    sync;echo 1 > /proc/sys/vm/drop_caches
fi
}

#修改pppoe的mtu
patch_all_ppp_mtu()
{
logger_to_logread "run all_ppp_mtu"
#改mtu
pppup=$(ifconfig|grep "pppoe-wan"|wc -l)
if [ "${pppup}" = "1" ];then
	mtunow=$(ifconfig pppoe-wan|grep "MTU"|awk '{print $6}'|awk -F ':' '{print $2}')
	if [ "${mtunow}" -gt "1454" ];then
		ifconfig pppoe-wan mtu 1454
	fi
fi
}

#W1211,W1210 fix sniffer restart bug##
patch_w1211_sniffer_restart_bug()
{
logger_to_logread "run w1211_sniffer_restart_bug"
if [ ! -f /tmp/flag_fix_sniffer_restart ];then
	ifconfig mon0 down
	rmmod /lib/modules/3.10.14/mt7601Usta.ko
	/etc/init.d/Wisniffer restart
	touch /tmp/flag_fix_sniffer_restart
fi
}

# W1211,W1210,W3022的uboot等待时间,设置为不等待
patch_w1211_w3022_uboot_delay()
{
logger_to_logread "run w1210_w3022_uboot_delay"
uboot_delay_num=$(nvram show uboot|grep "bootdelay"|cut -d '=' -f 2)
if [ "$uboot_delay_num" != "0" ];then
    nvram set uboot bootdelay 0
    nvram commit
fi
}

# 关闭uboot
patch_w1240_uboot_uart()
{
logger_to_logread "run w1240_uboot_uart"
uboot_uart_num=$(nvram show|grep config_uart_en|awk -F '=' '{print $2}')
if [ "$uboot_uart_num" != "0" ];then
    nvram set config_uart_en=0
    nvram commit
fi
}

# 3S,升级miniwios
patch_w1240_miniwios()
{
logger_to_logread "run w1240_miniwios"
get_mtd=$(md5sum /dev/mtdblock6|awk '{print $1}')
match_md5="82f7381460f9053fd99ddc603be10b88"
local_file="/tmp/MiniWIOS_v1.0.5.bin"
if [ -f "$local_file" ];then
    rm $local_file
fi
if [ "${get_mtd}" != "${match_md5}" ];then
	download_curl_file_wios "W1240/MiniWIOS_v1.0.5.bin" $local_file
	if [ "$download_http_code" = "200" ]&&[ "$download_curl_code" = "0" ];then
		logger_to_logread "download MiniWIOS ok"
        character='\377'
        block_size=4096
        block_counts=`expr 4194304 / $block_size`
        tr '\000' $character < /dev/zero | dd of=/dev/mtdblock6 bs=$block_size count=$block_counts
		cat $local_file > /dev/mtdblock6
		get_mtd=$(md5sum /dev/mtdblock6|awk '{print $1}')
		if [ "${get_mtd}" != "${match_md5}" ];then
			logger_to_logread "write MiniWIOS fail"
            post_curl_message "60001" "P0" "write_MiniWIOS_fail" "write MiniWIOS fail"
        else
            post_curl_message "60001" "Info" "write_MiniWIOS_ok" "write_MiniWIOS_ok"
		fi
	else
		logger_to_logread "download MiniWIOS fail"
        post_curl_message "60001" "P0" "download_MiniWIOS_fail" "http_${download_http_code}_curl_${download_curl_code}"
	fi
fi
}

# w1240修复探针timed-task异常的问题
patch_w1240_sniffer_timedtask()
{
logger_to_logread "run w1240_sniffer_timedtask"
sniffersw=$(uci get system.sniffer.enable)
if [ "${sniffersw}" = "1" ];then
	uptimenow=$(cat /proc/uptime|awk '{print $1}'|awk -F '.' '{print $1}'|head -1)
	if [ "${uptimenow}" -gt 300 ];then
		timedtask_sniffer=$(timed-task show |grep update-sniffer|wc -l)
		if [ "${timedtask_sniffer}" = "0" ];then
			timed-task add /usr/sbin/update-sniffer.sh 30 -1
		fi
	fi
fi
}

#w1240,dnsmasq fix bug
patch_w1240_dnsmasq()
{
logger_to_logread "run w1240_dnsmasq"
check_version=$(echo $main_version|grep "v5.1.4"|wc -l)
dnsmasq_file="/etc/dnsmasq.conf"
if [ "${check_version}" = "1" ];then
	dns_improve=$(cat $dnsmasq_file|grep "no-dns-improve"|wc -l)
	if [ "${dns_improve}" = "0" ];then
		echo "no-dns-improve" >> $dnsmasq_file
        /etc/init.d/dnsmasq restart
	fi
fi
}

# 旧版本的bug,这个进程卡在这里,导致logger占用cpu
patch_w1240_sysinit()
{
logger_to_logread "check logger -s -p 6 -t sysinit"
logger_init=$(ps|grep "logger -s -p 6 -t sysinit"|grep -v grep|wc -l)
if [ "$logger_init" != "0" ];then
    kill_num=$(ps|grep "logger -s -p 6 -t sysinit"|awk '{print $1}'|head -1)
    kill -9 $kill_num
    post_curl_message "60001" "Info" "logger_have_sysinit_kill" "logger_have_sysinit_kill"
fi
}

# 监测是否有配置不对的
patch_w3420_multwan()
{
logger_to_logread "check multwan"
lte_ifname=$(uci get network.lte.ifname)
wan_ifname=$(uci get network.wan.ifname)
if [ "$lte_ifname" = "usb0" ]&&[ "$wan_ifname" = "eth0.2" ];then
    mult_config=$(uci get multiwan.config.enabled)
    if [ "$mult_config" = "0" ];then
        post_curl_message "60001" "P1" "mult_config" "mult_config=${mult_config}"
    fi

fi
}

# 读取wifi数量
check_w1240_wifi()
{
wifi_num=$(iwconfig |grep ESSID|grep ath|grep -v "\"\""|wc -l)
if [ "${wifi_num}" = "0" ];then
    post_curl_message "60001" "Info" "wifi_num" "wifi_num=${wifi_num}"
    wifi
    sleep 5
fi
}

# 读取设备接口
get_w1240_interface()
{
ifname=$(uci get network.lan.ifname)

post_curl_message "60061" "Info" "getDevice" "ifname=${ifname},main_mode_id=$main_mode_id"
}

# 监测探针是否读到
get_w1240_7601()
{
lsusb_num=$(lsusb|grep 7601|wc -l)
if [ "$lsusb_num" = "0" ];then
    post_curl_message "60061" "Info" "lsusb_num" "lsusb_num=${lsusb_num}"
fi
}

# vap监测并在v5.2上关闭,此vap
check_w1240_w1211_vapcheck()
{
logger_to_logread "run w1240_w1211 vap"
if_v52_num=$(echo $main_version|grep v5.2|wc -l)
if [ "$if_v52_num" = "1" ];then
    if_wifi_reboot=0
    vap_value=$(uci get wireless.basic.5g_ssidext)
    if [ -n "$vap_value" ]&&[ "$vap_value" != "0" ];then
        uci set wireless.basic.5g_ssidext=0
        uci commit
        post_curl_message "60001" "Info" "vap_value_ssid" "vap_value_ssid=${vap_value}"
        if_wifi_reboot=1
    fi

    vap_value=$(uci get wireless.@wifi-iface[11].vap_enable)
    if [ -n "$vap_value" ]&&[ "$vap_value" != "0" ];then
        uci set wireless.@wifi-iface[11].vap_enable=0
        uci commit
        post_curl_message "60001" "Info" "vap_value11" "vap_value11=${vap_value}"
        if_wifi_reboot=1
    fi
    vap_value=$(uci get wireless.@wifi-iface[10].vap_enable)
    if [ -n "$vap_value" ]&&[ "$vap_value" != "0" ];then
        uci set wireless.@wifi-iface[10].vap_enable=0
        uci commit
        post_curl_message "60001" "Info" "vap_value10" "vap_value10=${vap_value}"
        if_wifi_reboot=1
    fi
    vap_value=$(uci get wireless.@wifi-iface[12].vap_enable)
    if [ -n "$vap_value" ]&&[ "$vap_value" != "0" ];then
        uci set wireless.@wifi-iface[12].vap_enable=0
        uci commit
        post_curl_message "60001" "Info" "vap_value12" "vap_value12=${vap_value}"
        if_wifi_reboot=1
    fi
    vap_value=$(uci get wireless.@wifi-iface[13].vap_enable)
    if [ -n "$vap_value" ]&&[ "$vap_value" != "0" ];then
        uci set wireless.@wifi-iface[13].vap_enable=0
        uci commit
        post_curl_message "60001" "Info" "vap_value13" "vap_value13=${vap_value}"
        if_wifi_reboot=1
    fi
    if [ "$if_wifi_reboot" = "1" ];then
        wifi 
    fi
fi
}

# 监测设备是否有oop的报错
check_handle_kernel()
{

check_kernel=$(dmesg|grep "to handle kernel paging"|wc -l)
if [ "$check_kernel" != "0" ];then
    post_curl_message "60001" "P2" "kernel" "kernel=${check_kernel}"
fi
}


# 测试10M文件下载.确认当前网络是否OK
download_test_file()
{
if [ "$test_flag" = "1" ];then
    test_tmp="/tmp/test_download"
    file_name="10M"
    local_file="/tmp/test_file_10"
    download_flag=0
    if [ ! -f "$test_tmp" ];then
        download_flag=1
        download_num=1
    else
        download_num=$(cat $test_tmp|head -1)
        if [ "$download_num" != "0" ]||[ "$download_num" -le "2" ];then
            download_flag=1
        fi
    fi
    if [ "$download_flag" = "1" ];then
        download_curl_file_wios "$file_name" "$local_file" 2
        if [ "$download_http_code" = "200" ]&&[ "$download_curl_code" = "0" ];then
            echo 0 > $test_tmp
            post_curl_message "60003" "Info" "download_ok" "download_ok"
        else
            post_curl_message "60003" "P2" "download_fail" "download_fail_$download_num"
            tmp_num=$(expr $download_num + 1)
            echo $tmp_num > $test_tmp
        fi
    fi

    if [ -f "$local_file" ];then
        rm $local_file
    fi
fi
}

# 监测dnsmasq配置个数
check_dnsmasq_config()
{

dnsmasq_num=$(uci show |grep dhcp|grep dnsmasq|grep "]="|wc -l)
if [ "$dnsmasq_num" -ge 2 ];then
    post_curl_message "60001" "Info" "dnsmasq_num" "dnsmasq_num=$dnsmasq_num"
fi
}

####################以上设备打补丁对应函数####################

# 大部分的主入口这里有检测3000秒以上才跑一次
run_hour()
{
now_time=$(date +%s)
tmp_time_file="/tmp/tmp_upgradenew.txt"
expr_num=3000
if [ -f "$tmp_time_file" ]&&[ "$debug_flag" = "0" ];then
    script_tmp_version=$(cat $tmp_time_file|awk -F '_' '{print $2}'|head -1)
    if [ "${script_tmp_version}" = "${script_version}" ];then
        last_time=$(cat $tmp_time_file|awk -F '_' '{print $1}'|head -1)
        expr_time=$(expr $now_time - $last_time)
        if [ -n "$expr_time" ];then
            if [ "$expr_time" -lt "$expr_num" ];then
                logger_to_logread "now_time=${now_time},last_time=$last_time,expr_time=$expr_time,script_version=${script_version},not run upgradenew"
                return 
            fi
        fi
    fi
fi
echo "${now_time}_${script_version}" > $tmp_time_file

#进行常规上报
config_num=$(cat $(ls /etc/config|grep -v "dhcp"|awk -v dir='/etc/config' '{print dir"/"$0}')|wc -l)
local_portal=$(uci get wiwide.basic.localportal)
users_num=0
for i in $(seq 0 3)
do
    tmp_num=$(monitor show -i ${i}|wc -l)
    if [ "${tmp_num}" != "0" ];then
        users_num=$(expr ${users_num} + ${tmp_num})
    fi
done

get_tmp_memory
ps_update_num=$(ps|grep wiupdate|grep -v "grep"|awk '{print $1}'|head -1)
if [ -n "$ps_update_num" ];then
    dir_value="/proc/${ps_update_num}/fd/"
    if [ -d "$dir_value" ];then
        num_0=$(ls -l /proc/${ps_update_num}/fd/0|awk -F '->' '{print $2}'|sed 's/ //g')
        num_1=$(ls -l /proc/${ps_update_num}/fd/1|awk -F '->' '{print $2}'|sed 's/ //g')
        num_2=$(ls -l /proc/${ps_update_num}/fd/2|awk -F '->' '{print $2}'|sed 's/ //g')
    fi
fi
if [ -n "${main_update_server}" ];then
    widash_code=$(curl -4 --insecure --connect-timeout 60 --speed-time 30 --speed-limit 1 -w %{http_code} "${main_update_server}" -o /dev/null)
else
    widash_code=-1
fi
reboot_num=$(cat /data/log/syslog|grep "device detection reboot"|wc -l)
update_md5=$(md5sum /usr/sbin/wiupdate|awk '{print $1}'|head -1)
mtd6=$(md5sum /dev/mtdblock6|awk '{print $1}')
sniffer_fail=$(cat $main_tmp_logread_file|grep "fail"|grep "sniffer"|wc -l)
post_to_60000="config_num=${config_num},local_portal=${local_portal},widash_code=${widash_code},total_users=${users_num},df_num=$(df|wc -l),free=$(free|grep "Mem"|awk '{print $4}'|head -1),tmp_mem=${main_tmp_memory},num_0=${num_0},num_1=${num_1},num_2=${num_2},reboot_num=${reboot_num},update_md5=${update_md5},mtd6=${mtd6},sniffer_fail=${sniffer_fail}"
post_curl_message "60000" "Info" "patch_config" "$post_to_60000"

#调用upgrade.sh确认是否要升级
download_upgrade_sh

if [ "$if_cn" = "1" ];then
    return
fi

# 不区分版本处理的内容
path_all_dmesg_error
check_config_file
check_handle_kernel
check_dnsmasq_config

if [ "$main_product_uci" = "W1210" ]||[ "$main_product_uci" = "W1211" ];then
    patch_w1211_w3022_uboot_delay
    check_w1240_w1211_vapcheck
    download_test_file
    echo ""
elif [ "$main_product_uci" = "W1240" ];then
    patch_w1240_miniwios
    patch_w1240_uboot_uart
    check_w1240_wifi
    get_w1240_interface
    get_w1240_7601
    check_w1240_w1211_vapcheck
    download_test_file
    echo ""
elif [ "$main_product_uci" = "W3022" ];then
    patch_w1211_w3022_uboot_delay
    download_test_file
    echo ""
elif [ "$main_product_uci" = "W3023" ];then
    download_test_file
    echo ""
elif [ "$main_product_uci" = "W3024" ]||[ "$main_product_uci" = "W3060" ];then
    download_test_file
    echo ""
elif [ "$main_product_uci" = "W3420" ];then
    patch_w3420_multwan
    echo ""
elif [ "$main_product_uci" = "W3520" ];then
    patch_w3420_multwan
    echo ""
fi

#打补丁,或监测,区分产品
check_version_lt "v5.2.10"
return_code=$?
if [ "$return_code" = "1" ];then
    patch_all_ppp_mtu
    if [ "$main_product_uci" = "W1210" ]||[ "$main_product_uci" = "W1211" ];then
        patch_w1211_sniffer_restart_bug
    elif [ "$main_product_uci" = "W1240" ];then
        patch_w1240_sniffer_timedtask
        patch_w1240_dnsmasq
        patch_w1240_sysinit
    elif [ "$main_product_uci" = "W3022" ];then
        echo ""
    elif [ "$main_product_uci" = "W3023" ];then
        echo ""
    elif [ "$main_product_uci" = "W3024" ]||[ "$main_product_uci" = "W3060" ];then
        echo ""
    elif [ "$main_product_uci" = "W3420" ]||[ "$main_product_uci" = "W3520" ];then
        echo ""
    fi
fi

# 给会龙的
upload_to_wdc

#进程8086检查
check_up_to_8086


}

# 主函数
run_main()
{
get_version
get_mac
get_product
get_uptime
get_mode
get_update_url
if_cn="$(echo ${main_update_server}|grep wiwide.cn|wc -l)"
if_cn=0

device_detection_bash_num=$(ps | grep device_detection | grep -v 'grep' | wc -l)
if [ "$device_detection_bash_num" = 1 ]; then
    killall -9 device_detection.sh
fi

if [ "$main_product_uci" != "W1210" ]&&[ "$main_product_uci" != "W1211" ]&&[ "$main_product_uci" != "W1240" ]&&[ "$main_product_uci" != "W3022" ]&&[ "$main_product_uci" != "W3023" ]&&[ "$main_product_uci" != "W3024" ]&&[ "$main_product_uci" != "W3060" ]&&[ "$main_product_uci" != "W3420" ]&&[ "$main_product_uci" != "W3520" ];then
    killall -9 device_detection.sh
    #exit
fi
# 网监开关
main_wj_enable=$(uci get system.netmonitor.enable)
# 网监类型
main_wj_type=$(uci get system.netmonitor.type)
#获取当前时间
main_now_sec=$(date +%s)
logger_to_logread "product is ${main_product_uci}"
#新版本此时会有2个文件一个是logread.log,一个是logread.1.log
tmp_new_logread_file="/tmp/log/logread.*"

if [ -f "/tmp/log/logread.log" ]||[ -f "/tmp/log/logread.1.log" ];then
	main_tmp_logread_file=$tmp_new_logread_file
    logger_to_logread "use logread file is $main_tmp_logread_file"
else
    main_tmp_logread_file="0"
    #如果是旧版本则删除读取出来的logread
    if [ -f "/tmp/logread_upgradenew_tmp.log" ];then
        rm /tmp/logread_upgradenew_tmp.log
    fi
fi
run_hour
# 检查是否要更新网监
get_wj_update

}


# 开始的地方
script_version="191232"
main_logger_key="test_wios_upgradenew"
if [ "$1" = "1" ];then
    debug_flag=1
else
    debug_flag=0
    exec >/dev/null 2>&1
    exec >/dev/null 1>&1
fi
#获取上一个小时
main_now_sec=$(date +%s)
let date_last_sec=${main_now_sec}-3600
main_date_last_hours=$(echo ${date_last_sec}|awk '{print strftime ("%b %e %H",$0)}')
test_flag=0

logger_to_logread "run upgradenew start"
run_main
logger_to_logread "run upgradenew end"
