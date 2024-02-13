import json
import os
import re
import subprocess

import requests


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
                cfg_file_content_original = "{\"api_key\":\"\",\"zone_id\":\"\",\"target_url_v4\":\"\",\"target_url_v6\":\"\",\"now_ipv4_address\":\"\",\"now_ipv6_address\":\"\",\"sleep_time_in_ms\":600000}"
                fw.write(cfg_file_content_original)
                fw.close()
    except Exception as e:
        print(e)
        is_ok_flag = "Creating Default Config File Failed"

    try:
        with open(cfg_file_path, 'r') as fr:
            cfg_file_content = fr.read()
            if cfg_file_content == "":
                try:
                    with open(cfg_file_path, 'w') as fw:
                        cfg_file_content_original = "{\"api_key\":\"\",\"zone_id\":\"\",\"target_url_v4\":\"\",\"target_url_v6\":\"\",\"now_ipv4_address\":\"\",\"now_ipv6_address\":\"\",\"sleep_time_in_ms\":600000}"
                        fw.write(cfg_file_content_original)
                        fw.close()
                except Exception as e:
                    print(e)
                    is_ok_flag = "Writing Default Config Content Failed"
            fr.close()
    except Exception as e:
        print(e)
        is_ok_flag = "Read Config File Failed"

    api_key, target_url_v4, zone_id, now_ipv4_address, now_ipv6_address, sleep_time_in_ms = "", "", "", "", "", 0

    try:
        with (open(cfg_file_path, 'r') as fr):
            cfg_file_content = fr.read()
            cfg_json_item = json.loads(cfg_file_content)

            api_key = cfg_json_item['api_key']
            zone_id = cfg_json_item['zone_id']
            target_url_v4 = cfg_json_item['target_url_v4']
            target_url_v6 = cfg_json_item['target_url_v6']
            now_ipv4_address = cfg_json_item['now_ipv4_address']
            now_ipv6_address = cfg_json_item['now_ipv6_address']
            sleep_time_in_ms = cfg_json_item['sleep_time_in_ms']

            if api_key == "":
                is_ok_flag = "Read Config File Failed - No API key"
                print(is_ok_flag)
            elif zone_id == "":
                is_ok_flag = "Read Config File Failed - No zone id"
                print(is_ok_flag)
            elif target_url_v4 == "":
                is_ok_flag = "Read Config File Failed - No IPv4 target url"
                print(is_ok_flag)
            elif is_valid_domain(target_url_v4) == False:
                is_ok_flag = "Read Config File Failed - IPv4 Target URL Not Valid"
                print(is_ok_flag)
            elif target_url_v6 == "":
                is_ok_flag = "Read Config File Failed - No IPv6 target url"
                print(is_ok_flag)
            elif is_valid_domain(target_url_v6) == False:
                is_ok_flag = "Read Config File Failed - IPv6 Target URL Not Valid"
                print(is_ok_flag)
    except Exception as e:
        print(e)
        is_ok_flag = "Read Config File Failed"

    return is_ok_flag, api_key, zone_id, target_url_v4, target_url_v6, now_ipv4_address, now_ipv6_address, sleep_time_in_ms


def save_cfg_json(new_ipv4: str, new_ipv6: str):
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
        print(e)
        is_ok_flag = "Read Config File Failed"

    cfg_json_item['now_ipv4_address'] = new_ipv4
    cfg_json_item['now_ipv6_address'] = new_ipv6

    try:
        with open(cfg_file_path, 'w') as fw:
            cfg_file_content = cfg_json_item.dumps()
            fw.write(cfg_file_content)
            fw.close()
    except Exception as e:
        print(e)
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
    return res_json_item


def check_is_need_create_or_update_in_clodflare_dns_record(target_url_v4: str, now_ipv4_address: str,
                                                           target_url_v6: str, now_ipv6_address: str,
                                                           res_json_item):
    is_v4_target_url_existed = False
    is_ipv4_need_update = False
    is_v6_target_url_existed = False
    is_ipv6_need_update = False

    for i in res_json_item['result']:
        if i['name'] == target_url_v4:
            is_v4_target_url_existed = True
            if i['type'] == "A":
                if i['content'] != now_ipv4_address:
                    is_ipv4_need_update = True

        elif i['name'] == target_url_v6:
            is_v6_target_url_existed = True
            if i['type'] == "AAAA":
                if i['content'] != now_ipv6_address:
                    is_ipv6_need_update = True

    return is_v4_target_url_existed, is_ipv4_need_update, is_v6_target_url_existed, is_ipv6_need_update


if __name__ == '__main__':
    print(get_public_ip_from_ipsb(4))
    print(get_public_ip_from_ipsb(6))

    # get_dns_record_list_from_cloudflare(zone_id="f8c97397f790aa4d0dd1c4046b4c1e25",
    #                                     api_key="vRIfnKqi6Mla_G9cPwrCak3dniGR0G9tKvxQJvd4")
