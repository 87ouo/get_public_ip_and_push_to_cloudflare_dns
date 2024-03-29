import datetime
import json
import logging
import os
import re
import subprocess
from time import sleep

import requests

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
now = datetime.datetime.now()
formatted_time = now.strftime("%Y%m%d_%H%M%S.%f")[:-3]
exe_path = os.path.split(os.path.realpath(__file__))[0]
log_file_path = os.path.join(exe_path, 'logs')
if not os.path.exists(log_file_path):
    os.makedirs(log_file_path)
log_file_path = os.path.join(log_file_path, "UTC+8 " + formatted_time + '.log')
handler = logging.FileHandler(log_file_path)
handler.setLevel(logging.DEBUG)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
console.setFormatter(formatter)
logger.addHandler(handler)
logger.addHandler(console)


def is_valid_domain(domain: str) -> bool:
    pattern = re.compile(
        r'^((([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
        r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3}))$'
    )
    return True if pattern.match(domain) else False


def load_cfg_json():
    exe_path = os.path.split(os.path.realpath(__file__))[0]
    cfg_file_path = os.path.join(exe_path, 'config.cfgjson')
    is_ok_flag = "OK"

    try:
        if not os.path.exists(cfg_file_path):
            with open(cfg_file_path, 'w') as fw:
                cfg_file_content_original = "{\"api_key\":\"\",\"zone_id\":\"\",\"target_url_v4\":\"\",\"target_url_v6\":\"\",\"v4_use_cloudflare_proxy\":false,\"v6_use_cloudflare_proxy\":false,\"sleep_time_in_ms\":600000}"
                fw.write(cfg_file_content_original)
                fw.close()
    except Exception as e:
        logger.warning('Creating Default Config File Failed --- ' + str(e))
        is_ok_flag = "Creating Default Config File Failed"

    try:
        with open(cfg_file_path, 'r') as fr:
            cfg_file_content = fr.read()
            if cfg_file_content == "":
                try:
                    with open(cfg_file_path, 'w') as fw:
                        cfg_file_content_original = "{\"api_key\":\"\",\"zone_id\":\"\",\"target_url_v4\":\"\",\"target_url_v6\":\"\",\"v4_use_cloudflare_proxy\":false,\"v6_use_cloudflare_proxy\":false,\"sleep_time_in_ms\":600000}"
                        fw.write(cfg_file_content_original)
                        fw.close()
                except Exception as e:
                    logger.warning('Writing Default Config Content Failed --- ' + str(e))
                    is_ok_flag = "Writing Default Config Content Failed"
            fr.close()
    except Exception as e:
        logger.warning('Read Config File Failed --- ' + str(e))
        is_ok_flag = "Read Config File Failed"

    api_key, target_url_v4, zone_id, v4_use_cloudflare_proxy, v6_use_cloudflare_proxy, sleep_time_in_ms = "", "", "", False, False, 0

    try:
        with (open(cfg_file_path, 'r') as fr):
            cfg_file_content = fr.read()
            cfg_json_item = json.loads(cfg_file_content)

            api_key = cfg_json_item['api_key']
            zone_id = cfg_json_item['zone_id']
            target_url_v4 = cfg_json_item['target_url_v4']
            target_url_v6 = cfg_json_item['target_url_v6']

            v4_use_cloudflare_proxy = (
                cfg_json_item['v4_use_cloudflare_proxy'] if cfg_json_item['v4_use_cloudflare_proxy'] != None else False)
            v6_use_cloudflare_proxy = (
                cfg_json_item['v6_use_cloudflare_proxy'] if cfg_json_item['v6_use_cloudflare_proxy'] != None else False)

            sleep_time_in_ms = cfg_json_item['sleep_time_in_ms']

            if api_key == "":
                is_ok_flag = "Read Config File Failed - No API key"
                logger.warning(is_ok_flag)

            elif zone_id == "":
                is_ok_flag = "Read Config File Failed - No zone id"
                logger.warning(is_ok_flag)

            elif target_url_v4 == "":
                # is_ok_flag = "Read Config File Failed - No IPv4 target url"
                # logger.warning(is_ok_flag)
                pass
            elif is_valid_domain(target_url_v4) == False:
                is_ok_flag = "Read Config File Failed - IPv4 Target URL Not Valid"
                logger.warning(is_ok_flag)

            elif target_url_v6 == "":
                # is_ok_flag = "Read Config File Failed - No IPv6 target url"
                # logger.info("No IPv6 target url, Skip IPv6......")
                pass
            elif is_valid_domain(target_url_v6) == False:
                is_ok_flag = "Read Config File Failed - IPv6 Target URL Not Valid"
                logger.warning(is_ok_flag)

    except Exception as e:
        logger.warning('Read Config File Failed --- ' + str(e))
        is_ok_flag = "Read Config File Failed"

    return is_ok_flag, api_key, zone_id, target_url_v4, target_url_v6, v4_use_cloudflare_proxy, v6_use_cloudflare_proxy, sleep_time_in_ms


def save_cfg_json():
    exe_path = os.path.split(os.path.realpath(__file__))[0]
    cfg_file_path = os.path.join(exe_path, 'config.cfgjson')
    cfg_json_item = json.loads("{}")
    is_ok_flag = "OK"

    try:
        with open(cfg_file_path, 'r') as fr:
            cfg_file_content = fr.read()
            cfg_json_item = json.loads(cfg_file_content)
            fr.close()
    except Exception as e:
        logger.warning('Read Config File Failed --- ' + str(e))
        is_ok_flag = "Read Config File Failed"

    try:
        with open(cfg_file_path, 'w') as fw:
            cfg_file_content = json.dumps(cfg_json_item)
            fw.write(cfg_file_content)
            fw.close()
    except Exception as e:
        logger.warning('Write Config File Failed --- ' + str(e))
        is_ok_flag = "Write Config File Failed"

    return is_ok_flag


def curl_func(url: str):
    curl_command = 'curl -sS ' + url
    output = subprocess.check_output(curl_command, shell=True)
    output = output.decode('utf-8')
    return output.replace('\n', '').replace(' ', '')


def get_public_ip_from_ipsb(ipv4_or_ipv6: int):
    if ipv4_or_ipv6 == 4:
        return curl_func("ipv4.ip.sb")
    elif ipv4_or_ipv6 == 6:
        return curl_func("ipv6.ip.sb")


def get_dns_record_list_from_cloudflare(zone_id: str, api_key: str):
    url = "https://api.cloudflare.com/client/v4/zones/" + zone_id + "/dns_records"
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + api_key
    }
    response = requests.request("GET", url, headers=headers)
    res_json_item = json.loads(response.text)

    logger.info(response.text)

    return res_json_item


def check_domain_is_same(res_json_item, domain_in_cfg: str) -> bool:
    if len(res_json_item['result']) > 0:
        domain_in_res_json_item = res_json_item['result'][0]['zone_name']
        domain_in_cfg_to_check = domain_in_cfg[(len(domain_in_res_json_item) * -1):]
        if domain_in_cfg_to_check == domain_in_res_json_item:
            return True
        else:
            return False


def check_is_need_create_or_update_in_clodflare_dns_record(target_url_v4: str, now_ipv4_address: str,
                                                           v4_use_cloudflare_proxy: bool,
                                                           target_url_v6: str, now_ipv6_address: str,
                                                           v6_use_cloudflare_proxy: bool,
                                                           res_json_item):
    is_v4_target_url_existed = False
    is_ipv4_need_update = False
    ipv4_dns_record_id = ""

    is_v6_target_url_existed = False
    is_ipv6_need_update = False
    ipv6_dns_record_id = ""

    for i in res_json_item['result']:
        if target_url_v4 != "" and now_ipv4_address != "":
            if i['name'] == target_url_v4:
                is_v4_target_url_existed = True
                if i['type'] == "A":
                    if i['content'] != now_ipv4_address:
                        is_ipv4_need_update = True
                        ipv4_dns_record_id = i['id']
                    if i['proxied'] != v4_use_cloudflare_proxy:
                        is_ipv4_need_update = True
                        ipv4_dns_record_id = i['id']

        if target_url_v6 != "" and now_ipv6_address != "":
            if i['name'] == target_url_v6:
                is_v6_target_url_existed = True
                if i['type'] == "AAAA":
                    if i['content'] != now_ipv6_address:
                        is_ipv6_need_update = True
                        ipv6_dns_record_id = i['id']
                    if i['proxied'] != v6_use_cloudflare_proxy:
                        is_ipv6_need_update = True
                        ipv6_dns_record_id = i['id']

    return is_v4_target_url_existed, is_ipv4_need_update, ipv4_dns_record_id, is_v6_target_url_existed, is_ipv6_need_update, ipv6_dns_record_id


def create_dns_record_for_cloudflare(ipv4_or_ipv6: int, target_url: str, now_address: str, use_cloudflare_proxy: bool,
                                     api_key: str, zone_id: str):
    is_ok_flag = "OK"

    url = "https://api.cloudflare.com/client/v4/zones/" + zone_id + "/dns_records"
    payload = {}
    if ipv4_or_ipv6 == 4:
        payload = {
            "content": now_address,
            "name": target_url,
            "proxied": use_cloudflare_proxy,
            "type": "A",
            "comment": "",
            "tags": [],
            "ttl": 1
        }
    elif ipv4_or_ipv6 == 6:
        payload = {
            "content": now_address,
            "name": target_url,
            "proxied": use_cloudflare_proxy,
            "type": "AAAA",
            "comment": "",
            "tags": [],
            "ttl": 1
        }
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + api_key
    }

    try:
        response = requests.request("POST", url, json=payload, headers=headers)
        logger.info(response.text)
    except Exception as e:
        logger.warning('Create DNS Record Failed --- ' + str(e))
        is_ok_flag = "Create DNS Record Failed"

    return is_ok_flag


def update_dns_record_for_cloudflare(ipv4_or_ipv6: int, target_url: str, target_dns_record_id: str, now_address: str,
                                     use_cloudflare_proxy: bool, api_key: str, zone_id: str):
    is_ok_flag = "OK"

    url = "https://api.cloudflare.com/client/v4/zones/" + zone_id + "/dns_records/" + target_dns_record_id

    payload = {}

    if ipv4_or_ipv6 == 4:
        payload = {
            "content": now_address,
            "name": target_url,
            "proxied": use_cloudflare_proxy,
            "type": "A",
            "comment": "",
            "tags": [],
            "ttl": 1
        }
    elif ipv4_or_ipv6 == 6:
        payload = {
            "content": now_address,
            "name": target_url,
            "proxied": use_cloudflare_proxy,
            "type": "AAAA",
            "comment": "",
            "tags": [],
            "ttl": 1
        }
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + api_key
    }

    try:
        response = requests.request("PATCH", url, json=payload, headers=headers)
        logger.info(response.text)
    except Exception as e:
        logger.warning('Update DNS Record Failed --- ' + str(e))
        is_ok_flag = "Update DNS Record Failed"

    return is_ok_flag


if __name__ == '__main__':
    is_ok_flag, api_key, zone_id, target_url_v4, target_url_v6, v4_use_cloudflare_proxy, v6_use_cloudflare_proxy, sleep_time_in_ms = load_cfg_json()

    debug_enable = 0

    is_loop = True
    loop_cnt = 0

    if is_ok_flag != "OK":
        logger.info(is_ok_flag)
        is_loop = False

    if debug_enable == 1:
        is_loop = False
        if is_ok_flag == "OK":
            get_dns_record_list_from_cloudflare(zone_id, api_key)

    while is_loop:
        loop_cnt += 1
        logger.info("Start Local DDNS Checking Operation ====== Loop " + str(loop_cnt) + " ======")

        if loop_cnt != 1:
            is_ok_flag, api_key, zone_id, target_url_v4, target_url_v6, v4_use_cloudflare_proxy, v6_use_cloudflare_proxy, sleep_time_in_ms = load_cfg_json()
            if is_ok_flag != "OK":
                logger.info(is_ok_flag)
                is_loop = False
                break

        res_json_item = get_dns_record_list_from_cloudflare(zone_id, api_key)

        if (target_url_v4 != "") and (
                check_domain_is_same(res_json_item=res_json_item, domain_in_cfg=target_url_v4) is False):
            logger.info(
                "The IPv4 Target URL`s Domain in config.cfgjson IS NOT same with Cloudflare`s return information's Domain.")
            is_loop = False
            break
        if (target_url_v6 != "") and (
                check_domain_is_same(res_json_item=res_json_item, domain_in_cfg=target_url_v6) is False):
            logger.info(
                "The IPv6 Target URL`s Domain in config.cfgjson IS NOT same with Cloudflare`s return information's Domain.")
            is_loop = False
            break

        now_ipv4_address = get_public_ip_from_ipsb(4)
        now_ipv6_address = get_public_ip_from_ipsb(6)

        logger.info("Now IPv4 Address: " + now_ipv4_address)
        logger.info("Now IPv6 Address: " + now_ipv6_address)

        is_v4_target_url_existed, is_ipv4_need_update, ipv4_dns_record_id, is_v6_target_url_existed, is_ipv6_need_update, ipv6_dns_record_id = \
            check_is_need_create_or_update_in_clodflare_dns_record(target_url_v4=target_url_v4,
                                                                   now_ipv4_address=now_ipv4_address,
                                                                   v4_use_cloudflare_proxy=v4_use_cloudflare_proxy,
                                                                   target_url_v6=target_url_v6,
                                                                   now_ipv6_address=now_ipv6_address,
                                                                   v6_use_cloudflare_proxy=v6_use_cloudflare_proxy,
                                                                   res_json_item=res_json_item)

        if target_url_v4 != "":
            if is_v4_target_url_existed:
                if is_ipv4_need_update:
                    logger.info("Public IPv4 Changed, Update......")
                    update_dns_record_for_cloudflare(ipv4_or_ipv6=4,
                                                     target_url=target_url_v4,
                                                     target_dns_record_id=ipv4_dns_record_id,
                                                     now_address=now_ipv4_address,
                                                     use_cloudflare_proxy=v4_use_cloudflare_proxy,
                                                     api_key=api_key,
                                                     zone_id=zone_id)
                else:
                    logger.info("Public IPv4 NOT Change, Pass......")
            else:
                logger.info("IPv4 DNS Record NOT Existed, Create......")
                create_dns_record_for_cloudflare(ipv4_or_ipv6=4,
                                                 target_url=target_url_v4,
                                                 now_address=now_ipv4_address,
                                                 use_cloudflare_proxy=v4_use_cloudflare_proxy,
                                                 api_key=api_key,
                                                 zone_id=zone_id)
        else:
            logger.info("No IPv4 target url, Skip IPv4......")

        if target_url_v6 != "":
            if is_v6_target_url_existed:
                if is_ipv6_need_update:
                    logger.info("Public IPv6 Changed, Update......")
                    update_dns_record_for_cloudflare(ipv4_or_ipv6=6,
                                                     target_url=target_url_v6,
                                                     target_dns_record_id=ipv6_dns_record_id,
                                                     now_address=now_ipv6_address,
                                                     use_cloudflare_proxy=v6_use_cloudflare_proxy,
                                                     api_key=api_key,
                                                     zone_id=zone_id)
                else:
                    logger.info("Public IPv6 NOT Change, Pass......")
            else:
                logger.info("IPv6 DNS Record NOT Existed, Create......")
                create_dns_record_for_cloudflare(ipv4_or_ipv6=6,
                                                 target_url=target_url_v6,
                                                 now_address=now_ipv6_address,
                                                 use_cloudflare_proxy=v6_use_cloudflare_proxy,
                                                 api_key=api_key,
                                                 zone_id=zone_id)
        else:
            logger.info("No IPv6 target url, Skip IPv6......")

        # save_cfg_json()

        sleep_time_in_ms = max(sleep_time_in_ms, (1 * 60 * 1000))  # 最小loop时间间隔1分钟
        logger.info("Operation Finished. Sleep " + str(sleep_time_in_ms / 1000) + " Sec......\n\n")
        sleep(sleep_time_in_ms / 1000)
