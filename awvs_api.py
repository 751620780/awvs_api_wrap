#coding=utf-8
from datetime import datetime
import os
import random
import re
import requests
import urllib3
import traceback
import json
import time
import html
import logging
from logging.handlers import RotatingFileHandler



def init_log(logfile):
    '''初始化日志，返回日志对象'''
    global logger
    logfile = os.path.abspath(logfile)
    if not os.path.exists(os.path.dirname(logfile)):
        os.makedirs(os.path.dirname(logfile))
    logger = logging.getLogger()
    hdlr = RotatingFileHandler(logfile,
                               maxBytes=128 * 1024 * 1024,
                               backupCount=3)
    FORMAT = "%(asctime)s.%(msecs)03d %(levelname)s %(filename)s:%(lineno)d - %(message)s"
    formatter = logging.Formatter(FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.DEBUG)
    return logger

logger = init_log(os.path.join("/var/log/celery"), "awvs_api.log")

cve_info = {}
try:
    cve_info_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_info.json")
    with open(cve_info_file, "r", encoding="utf-8") as f:
        cve_info = json.loads(f.read())
except Exception as e:
    err = " ".join([s.strip() for s in traceback.format_exc().split('\n') if s])
    logger.error("load cve_info failed, exception:{}".format(err))

class AwvsApi:
    '''
        访问AWVS的api的类

        使用流程：
        1. 创建taget
        2. 设置target的相关配置
        3. 创建扫描任务
        4. 等待、暂停或结束扫描任务
        5. 获取扫描的漏洞结果
    '''

    def __init__(self, ip_port, api_key):
        '''
            ``ip``: awvs服务器的IP地址和端口号，举例："127.0.0.1:3443"

            ``api_key``: awvs访问api时使用的X-Auth key，可以从awvs的管理页面右上角的 用户->profile 中获得
        '''
        urllib3.disable_warnings()
        self.ip_port = ip_port
        self.api_key = api_key
        self.api_url = 'https://{}/api/v1'.format(ip_port)
        self.req_header = {
            'Accept': 'application/json',
            'X-Auth': api_key,
        }

        if self._test_server() == False:
            logger.error("connect to AWVS api server={} failed!".format(ip_port))
        self.scan_profiles = self.get_scan_profiles()

    def get_profile_id(self,profile_name):
        '''根据扫描模式的名字，获得扫描模式的id，失败返回“”'''
        profile_name = profile_name.strip()
        for profile in self.scan_profiles:
            if profile["name"].strip() == profile_name:
                profile_id = profile["profile_id"]
                break
        if profile_id == "" :
            self.scan_profiles = self.get_scan_profiles()
            for profile in self.scan_profiles:
                if profile["name"].strip() == profile_name:
                    profile_id = profile["profile_id"]
                    break
        return profile_id

    def do_get(self,
               request_uri,
               req_header={},
               req_params=None,
               request_body=None):
        '''发送get请求'''
        url = "{}/{}".format(self.api_url, request_uri.strip("/\\"))
        req_header.update(self.req_header)
        return requests.get(url=url,
                            headers=req_header,
                            params=req_params,
                            data=request_body,
                            verify=False)

    def do_post(self, request_uri, request_body=None, req_header={}):
        '''发送post请求'''
        url = "{}/{}".format(self.api_url, request_uri.strip("/\\"))
        req_header.update(self.req_header)
        return requests.post(url=url,
                             data=json.dumps(request_body),
                             headers=req_header,
                             verify=False)

    def do_patch(self,
                 request_uri,
                 req_header={},
                 req_params=None,
                 request_body=None):
        '''发送patch请求'''
        url = "{}/{}".format(self.api_url, request_uri.strip("/\\"))
        req_header.update(self.req_header)
        return requests.patch(url=url,
                              headers=req_header,
                              params=req_params,
                              data=json.dumps(request_body),
                              verify=False)

    def do_delete(self,
                 request_uri,
                 req_header={},
                 req_params=None,
                 request_body=None):
        '''发送patch请求'''
        url = "{}/{}".format(self.api_url, request_uri.strip("/\\"))
        req_header.update(self.req_header)
        return requests.delete(url=url,
                              headers=req_header,
                              params=req_params,
                              data=json.dumps(request_body),
                              verify=False)

    def _test_server(self):
        '''判断AWVS api是否可用,外部请勿调用'''
        rsp = self.do_get("users")
        if rsp.status_code != 200:
            return False
        data = rsp.json()
        if 'users' not in data or 'pagination' not in data:
            return False
        return True

    def get_scan_profiles(self):
        '''获得已配置的扫描策略,返回策略列表'''
        rsp = self.do_get("scanning_profiles")
        if rsp.status_code != 200:
            return []
        return rsp.json()['scanning_profiles']

    def get_target_list(self, query_str):
        '''
            获取已设置的扫描目标列表
            
            ``query_str``是查询的过滤关键字，可以是target的域名字符串或描述信息中的部分字符串

            最多返回50个
        '''
        rsp = self.do_get('targets',
                          req_params={
                              "l": 50,
                              'q': "text_search:*{}".format(query_str)
                          })
        if rsp.status_code != 200:
            return []
        return rsp.json()['targets']

    def add_target(self, address, description, criticality=30):
        '''
            增加一个扫描目标,返回增加成功后的target_id，失败返回空字符串

            ``address``：ip地址、域名、具体的网站或网站url

            ``description``：目标的描述信息

            ``criticality``：目标的优先级，取值为0，10，20，30之一，分值越大，优先级越高
        '''
        if criticality not in [0, 10, 20, 30]:
            logger.error(
                """add_target failed, address={},description="{}",criticality={}"""
                .format(address, description, criticality))
            return ""
        rsp = self.do_post('targets',
                           req_header={'Content-Type': 'application/json'},
                           request_body={
                               'address': address,
                               "description": description,
                               'criticality': 30,
                               "type": "default",
                           })
        if rsp.status_code != 201:
            logger.error("""add_target failed, rsp data={}""".format(rsp.text))
            return ""
        return rsp.json()['target_id']

    def get_target_config(self, target_id):
        '''
            查询扫描目标的全局配置信息，返回词典
        '''
        rsp = self.do_get("targets/{}/configuration".format(target_id.strip()))
        if rsp.status_code != 200:
            logger.error("""get_target_config failed, rsp data={}""".format(
                rsp.text))
            return {}
        return rsp.json()

    def set_target_config(self, target_id,params={}):
        '''为扫描目标更新默认扫描配置,仅供内部调用'''
        configure_template = {
            "description": "",
            "limit_crawler_scope": True,
            "login": {          # 取值为 {"kind":"none"} 表示无登录验证，如果
                "kind": "none"
            },
            "sensor": False,
            "ssh_credentials": {
                "kind": "none"
            },
            "proxy": {
                "enabled": False
            },
            "authentication": {
                "enabled": False
            },
            "client_certificate_password": "",
            "scan_speed":"fast",  # 扫描速度，取值只能是 fast、moderate、slow、sequential 之一
            "default_scanning_profile_id":"11111111-1111-1111-1111-111111111111",  # 扫描策略，需提供正确的扫描策略
            "case_sensitive": "auto",
            "technologies": [],
            "custom_headers": [],
            "custom_cookies": [],
            "excluded_paths": [],
            "user_agent": "",  # 设置浏览器的user_agent
            "debug": False
        }
        bad_config = {}
        config={}
        for key in params:
            if key not in configure_template:
                bad_config[key]=params[key]
            else:
                config[key] = params[key]

        if len(bad_config) != 0:
            logger.error("set_target_config faield, found bad params={}".format(json.dumps(bad_config)))
            return False
        if len(config) == 0:
            logger.error("set_target_config faield, found no params set")
            return False

        rsp = self.do_patch(
            "targets/{}/configuration".format(target_id),
            req_header={"Content-Type": "application/json"},
            request_body=config,
        )
        if rsp.status_code != 204:
            logger.error(
                "set_target_config failed, status code={},server response={}".format(
                    rsp.status_code,
                    rsp.text
                ))
        return rsp.status_code == 204

    def set_target_config_scan_spped(self, target_id, scan_speed="fast"):
        '''
            为扫描目标更新默认扫描配置之扫描速度

            ``scan_speed``取值只能是"fast","moderate","slow","sequential"之一
        '''
        scan_speed = scan_speed.lower()
        if scan_speed not in ["fast", "moderate", "slow", "sequential"]:
            logger.error(
                "set_target_config_scan_spped failed with bad speed value, speed=%s",
                scan_speed)
            return False
        return self.set_target_config(target_id,{"scan_speed":scan_speed})

    def set_target_config_exclusions(self,target_id,add=[],remove=[]):
        '''
            设置扫描目标的跳过目录

            ``add``:增加需要跳过目录列表

            ``remove``:删除已经设置过的需要跳过的目录列表

            如果需要查询请通过``get_target_config``查看
        '''   
        rsp = self.do_post(
            "targets/{}/configuration/exclusions".format(target_id),
            req_header={"Content-Type": "application/json"},
            request_body={
                "add": {
                    "excluded_paths": add
                },
                "delete": {
                    "excluded_paths": remove
                }
        })
        if rsp.status_code != 204:
            logger.error(
                "set_target_config_exclusions failed, status code={},server response={}".format(
                    rsp.status_code,
                    rsp.text
                ))
            return False
        return rsp.status_code == 204

    def set_target_config_cookies(self,target_id,cookies={}):
        '''
            设置扫描目标的cookie

            ``cookies``:设置的cookie列表，例如``[{url: "http://example.com", cookie: "a=b;c=d;"}]``
        '''   
        return self.set_target_config(target_id=target_id,params={"custom_cookies":cookies})

    def set_target_config_profiles(self,target_id,profile_name="Full Scan"):
        '''
            设置扫描目标的默认扫描策略

            ``profile_name``:扫描策略的名字，一般情况下有取值：
                Full Scan、High Risk、High / Medium Risk、Cross-site Scripting、
                SQL Injection、Weak Passwords、Crawl Only、
                Network Scan (Full and fast)、Malware Scan、quick_profile_2、quick_profile_1
            
            如果需要查看设置后的扫描策略，请通过``get_target_config``查看
        '''
        profile_id = self.get_profile_id(profile_name=profile_name)
        if profile_id == "":
            logger.error("set_target_config_profiles failed, invalid profile_name={}".format(profile_name))
            return False
        return self.set_target_config(target_id=target_id,params={"default_scanning_profile_id":profile_id})

    def set_target_config_request_header(self,target_id,headers=[]):
        '''
            设置扫描目标访问扫描时额外提供请求头

           ``headers``：设置的请求头的列表，举例：``["X-My-Header: My-Value",""X-My-Header2: My-Value2""]``
        '''
        return self.set_target_config(target_id=target_id,params={"custom_headers":headers})

    def query_target_scan_id(self,target_id:str):
        '''
            查找扫描目标下创建的所有扫描任务信息，返回扫描任务信息的列表

            可通过如下方式获得扫描任务的id:

            ```python
            scan_list = awvs_api.query_target_scan_id(target_id=target_id)
            scan_id = scan_list[0]['scan_id']
            ```
        '''
        scans= []
        cursor = 0
        while True:
            rsp = self.do_get("scans",req_params={
                "l": 100,
                'c': cursor,
                'q': "target_id:{}".format(target_id)
            })
            if rsp.status_code != 200:
                logger.error("query_target_scan_id failed, server response={}".format(rsp.text))
                return scans
            rsp_scans = rsp.json()["scans"]
            if rsp_scans == None or len(rsp_scans) == 0:
                return scans
            scans.extend(rsp_scans)
            cursor = cursor + len(scans)


    def create_scan_task(self,target_id,profile_name=None,max_scan_time=0):
        '''
            为目标创建扫描任务，并立即开始扫描

            ``profile_name``：如果为None则使用默认的扫描策略，否则使用提供的扫描策略

            ``max_scan_time``：最大扫描持续时间，单位秒，如果为0 ，则不限时间

            创建成功返回扫描任务的scan_id,失败返回""
        '''
        profile_id=""
        if profile_name == None:
            config = self.get_target_config(target_id=target_id)
            if "default_scanning_profile_id" not in config:
                logger.error("create_scan failed, may give a invalid target_id={}".format(target_id))
                return ""
            profile_id = config["default_scanning_profile_id"]
        else:
            profile_id = self.get_profile_id(profile_name)

        if profile_id == "":
            logger.error(
                "create_scan failed, could not get profile_id, target_id={}, profile_name={}".format(
                    target_id,
                    profile_name
                ))
            return ""
            
        rsp = self.do_post("scans", req_header = {"Content-Type": "application/json"}, request_body = {
            "target_id": target_id,
            "profile_id": profile_id,
            "schedule": {
                "disable": True,
                "time_sensitive": True,
                "triggerable": False
            },
            "max_scan_time": max_scan_time,
            "incremental": False
        })
        if rsp.status_code!=201:
            logger.error("create_scan failed, server response={}".format(rsp.text))
            return ""
        scan_id = rsp.headers['Location'].split('/')[4]
        return scan_id

    def status_scan_task(self,scan_id)->dict:
        '''
            查询扫描任务的状态

            返回格式如下：

            ```json
            {
                "criticality": 30,
                "current_session": {
                    "event_level": 1,
                    "progress": 0,
                    "scan_session_id": "381845d3-d6ce-4a1a-a28f-6e5533161123",
                    "severity_counts": {
                        "high": 0,
                        "info": 3,
                        "low": 1,
                        "medium": 2
                    },
                    "start_date": "2022-06-27T06:22:12.723172+08:00",
                    "status": "processing",
                    "threat": 2
                },
                "incremental": false,
                "manual_intervention": false,
                "max_scan_time": 0,
                "next_run": null,
                "profile_id": "11111111-1111-1111-1111-111111111111",
                "profile_name": "Full Scan",
                "report_template_id": null,
                "scan_id": "dee12c87-3677-4006-bd9d-25bd69f09d6f",
                "schedule": {
                    "disable": false,
                    "history_limit": null,
                    "recurrence": null,
                    "start_date": "2022-06-27T08:00:00+08:00",
                    "time_sensitive": false,
                    "triggerable": false
                },
                "target": {
                    "address": "http://example.com",
                    "criticality": 30,
                    "description": "bsdsdsdsd",
                    "type": "default"
                },
                "target_id": "5d6e8c00-c41f-41e1-a4e5-5289125df0c8"
            }
            ```
        '''
        rsp = self.do_get("scans/{}".format(scan_id))
        if rsp.status_code!=200:
            logger.error("status_scan_task with scan_id={} failed, server response={}".format(scan_id,rsp.text))
            return {}
        return rsp.json()

    def pause_scan_task(self, scan_id):
        '''暂停一个正在运行的扫描任务'''
        rsp = self.do_post("scans/{}/pause".format(scan_id))
        if rsp.status_code!=204:
            logger.error("pause_scan_task with scan_id={} failed, server response={}".format(scan_id,rsp.text))
            return False
        return True

    def restart_scan_task(self, scan_id):
        '''重启已经暂停的扫描任务，返回是否重启成功'''
        rsp = self.do_post("scans/{}/resume".format(scan_id))
        if rsp.status_code!=204:
            logger.error("restart_scan_task with scan_id={} failed, server response={}".format(scan_id,rsp.text))
            return False
        return True


    def stop_scan_task(self, scan_id):
        '''停止扫描任务,返回操作是否成功'''
        rsp = self.do_post("scans/{}/abort".format(scan_id))
        if rsp.status_code!=204:
            logger.error("stop_scan_task with scan_id={} failed, server response={}".format(scan_id,rsp.text))
            return False
        return True

    def delete_scan_task(self,scan_id):
        '''删除一个扫描任务'''
        rsp = self.do_delete("scans/{}".format(scan_id))
        if rsp.status_code!=204:
            logger.error("delete_scan_task with scan_id={} failed, server response={}".format(scan_id,rsp.text))
            return False
        return True

    def query_scan_result(self,scan_id,scan_session_id,confidence=None,severity=[0,1,2,3],)->list:
        '''
            获得某次扫描任务按照条件查询得到的漏洞扫描结果

            ``confidence``:置信度，取值为0-100的整数

            ``severity``:威胁等级，取值为 0,1,2,3之多个

            返回列表，列表数据结构如下：
            ```json
            {
                "affects_detail": "",
                "affects_url": "https://192.168.223.1:58080/",
                "app": "wvs",
                "confidence": 95,
                "criticality": 10,
                "last_seen": null,
                "loc_id": 2,
                "severity": 1,
                "status": "open",
                "tags": [
                    "CWE-693",
                    "abuse_of_functionality"
                ],
                "target_id": "277c5ce2-2f80-43d6-a19d-41bb25aaf437",
                "vt_created": "2020-12-23T20:14:46+08:00",
                "vt_id": "b8e2c082-44f1-cf0b-0b8e-0e0bb357e798",
                "vt_name": "\u70b9\u51fb\u52ab\u6301\uff1aX-Frame-Options \u62a5\u5934\u7f3a\u5931",
                "vt_updated": "2021-06-24T00:07:17+08:00",
                "vuln_id": "2869698768494658641"
            }
            ```
        '''
        ret = []
        # 参数校验
        if not (confidence is None or (type(confidence) == int and confidence>=0 and confidence<=100)):
            logger.error("query_scan_last_result found bad param with confidence={}".format(confidence))
            return ret
        if type(severity) != list:
            logger.error("query_scan_last_result found bad param with severity={}".format(severity))
            return ret
        severity_set = set()
        for s in severity:
            if s not in [0,1,2,3]:
                logger.error("query_scan_last_result found bad param with severity={}".format(s))
                return ret
            severity_set.add(s)
        severity = list(severity_set)
        # 整理参数
        req_params = {"l":100}
        query_str = []
        if confidence != None:
            query_str.append("confidence:{}".format(confidence))
        if len(severity) != 0:
            query_str.append("severity:{}".format(",".join(severity)))
        
        if len(query_str)>0:
            req_params['q'] = ";".join(query_str)
        # 发起请求
        cursor = 0
        while True:
            req_params['c'] = cursor
            rsp = self.do_get("scans/{}/results/{}/vulnerabilities".format(scan_id,scan_session_id,),req_params=req_params)
            if rsp.status_code != 200:
                logger.error("query_scan_result failed, server response={}".format(rsp.text))
                return ret
            rsp_result = rsp.json()["vulnerabilities"]
            if rsp_result == None or len(rsp_result) == 0:
                return ret
            ret.extend(rsp_result)
            cursor = cursor + len(ret)

    def get_vulnerabilities_detail(self,scan_id:str,scan_session_id:str,vuln_id:str)->dict:
        '''
            获得某session下扫描session中具体漏洞的描述详情

            返回格式：

            ```json
            {
                "affects_detail": "",
                "affects_url": "https://localhost:58080/",
                "app": "wvs",
                "comment": null,
                "confidence": 100,
                "criticality": 30,
                "cvss2": "AV:N/AC:M/Au:N/C:P/I:P/A:N",
                "cvss3": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N",
                "cvss_score": 5.4,
                "description": "The web s....",                     // 漏洞信息描述
                "details": "The SSL ...",                           // 攻击详情
                "highlights": [],       
                "impact": "An attacker ...",                        // 此漏洞的影响
                "loc_id": 2,
                "long_description": "",
                "recommendation": "It is recommended ...",          // 漏洞修复建议
                "references": [                                     // 此漏洞的参考资料
                    {
                        "href": "https: //tools.ietf.org/html/rfc8996",
                        "rel": "RFC 8996: Deprecating TLS 1.0 and TLS 1.1"
                    },
                    {
                        "href": "https://...",                      // 参考文献的链接
                        "rel": "Are You ..."                        // 参考文献链接的说明
                    },
                    {
                        "href": "https://supp...",
                        "rel": "PCI 3.1 and TLS 1.2 (Cloudflare Support)"
                    }
                ],
                "request": "",                                      // 发现此漏洞时记录到的请求体
                "response_info": false,                             // 请求是否记录了响应体，如果为true，可以使用http_response接口获得
                "severity": 3,                                      // 威胁等级，3是高危
                "source": "/Scripts/PerServer/SSL_Audit.script",    // 发现该问题的漏洞扫描脚本
                "status": "open",                                   // 漏洞状态，目前处于开放状态
                "tags": [                                           // 漏洞所属的标签
                    "CWE-16",
                    "configuration",
                    "confidence.100"
                ],
                "target_id": "34caae35-9d8e-4b90-acbf-372868a46608",
                "vt_created": "2018-01-29T01:31:43+08:00",
                "vt_id": "63fa48a4-bd02-b3eb-1219-3d1f1f8a5143",
                "vt_name": "TLS 1.0 enabled",
                "vt_updated": "2021-08-13T13:38:24+08:00",
                "vuln_id": "2869576821991540112"
            }
            ```
        '''
        rsp = self.do_get("scans/{}/results/{}/vulnerabilities/{}".format(scan_id,scan_session_id,vuln_id))
        if rsp.status_code!=200:
            logger.error("get_vulnerabilities_detail with vuln_id={} failed, server response={}".format(vuln_id,rsp.text))
            return {}
        return rsp.json()

    def get_vulnerabilities_http_response(self,scan_id:str,scan_session_id:str,vuln_id:str)->str:
        '''提供漏扫的ID，查询其请求的响应内容'''
        rsp = self.do_get("scans/{}/results/{}/vulnerabilities/{}/http_response".format(scan_id,scan_session_id,vuln_id))
        if rsp.status_code!=200:
            logger.error("get_vulnerabilities_http_response with vuln_id={} failed, server response={}".format(vuln_id,rsp.text))
            return ""
        return rsp.text
    
    def wait_scan_finished(self,scan_id,time_out:int = 1050):
        '''
            等待某个扫描任务结束,如果超时会手动停止并返回

            返回 scan_session_id
        '''
        scan_session_id = ""
        time_cost = 0
        while True:
            scan_status = self.status_scan_task(scan_id=scan_id)
            status = scan_status.get("current_session",{}).get("status",None)
            scan_session_id = scan_status.get("current_session",{}).get("scan_session_id","")
            if status == None:
                return scan_session_id
            status = status.lower()
            if status == "processing":
                time.sleep(5)
                time_cost = time_cost + 5
                if time_cost >= time_out and time_out > 0:
                    self.stop_scan_task(scan_id=scan_id)
                    return scan_session_id
            if status in ["failed","completed","aborted"]:
                return scan_session_id

    def delete_target_and_etc(self,date_time):
        '''
            删除最后一次扫描时间在``date_time``之前的所有target、扫描session、扫描结果
        '''
        # TODO:获得target: /api/v1/targets?l=20&q=last_scanned:%3C=2022-06-26T16:00:00.000Z
        # 按照target_id搜索所有的扫描，删除它
        # 按照scan_session_id删除所有的扫描结果
        raise Exception("not implement")

    def delete_scan_session_and_etc(self,date_time):
        '''
            删除扫描开始日期在date_time之后的所有扫描任务及其相关的所有扫描结果
        '''
        raise Exception("not implement")
        

class AwvsVulnEnrich():
    '''
        完成将awvs扫描的漏洞结果到S系统二级指标下漏洞问题的描述相关的富化工作
    '''
    def __init__(self,rule_list,awvs_api:AwvsApi):
        '''
            ``rule_list``:支持的指标列表即相关信息

            ``rule_list`` 应具有如下格式
            ```json
            {
                "dict_name": "未设置域名注册保护",
                "dict_id": 4372615375365345281,
                "indicator_dict_name": "未设置域名注册保护",
                "indicator_dict_id": 4372615375365345281,
                "category": "dns",
                "scanner_name": "whoisLookup",
                "scan_method": "clientDeleteProhibited;ServerTransferProhibited",
                "rule_id": "",
                "script": "",
                "plugin_id": "",
                "severity": "低危",
                "hash_field": "indicator_dict_id,task_url,missing_domain_status,current_domain_status"
            }
            ```

            ``awvs_api``:awvs的api对象
        '''
        global cve_info
        self.awvs = awvs_api
        self.rule_dict=dict()
        for rule in rule_list:
            self.rule_dict[rule['dict_id']] = rule
        # AWVS的漏洞等级和S系统的指标id的对应关系
        self.severity_map = {
            1:"4381402116964487169",
            2:"4370134082098565121",
            3:"4370133881434673153",
        }
        self.cve_info = cve_info
    
    def result_enrich(self,scan_id:str,scan_session_id:str)->list:
        '''
            将本次扫描产生的漏洞信息，按照S系统的rs_task表中此扫描插件对应的指标要求的字段进行富化
            
            返回漏洞扫描结果的列表

            富化产生如下字段：
            ```json
            {
                "indicator_dict_id": 4370133881434673153,           // 指标id，必须在rule_list中
                "indicator_dict_name": "高风险漏洞",                 // 指标中文名称
                "create_time": "2022-03-28 14:32:47",               // 扫描出该问题的时间
                "cve": ["cve-xx-xx",],                              // 漏洞的cve信息,仅cve，非cwe
                "cve_description":"xxx",                            // cve的描述信息，必须有,多个cve只取第一个cve的描述
                "title_cn": "XXL-JOB executor 未授权访问漏洞",       // 扫描出的漏洞的中文名字
                "url": "http://192.168.100.11:19530/run",           // 发现漏洞时的url
                "detail":{"request":""，"response":""},             // 原生请求和响应内容,如果有的话
                "publish_time":["2020-06-08",],                     // CVE的漏洞发布时间
                "affected_software":[{},{},],                       // 受影响的软件列表,最多列出10个
            }
            ```
            
        '''
        ret = []
        awvs_vuln_list = self.awvs.query_scan_result(scan_id,scan_session_id,severity=[3,2,1])
        try:
            for awvs_vuln in awvs_vuln_list:
                severity = awvs_vuln['severity']
                indicator_id = self.severity_map[severity]
                rule = self.rule_dict.get(indicator_id,None)
                if rule == None:
                    continue
                # 计算CVE
                cve_list=[]
                for tag in awvs_vuln['tags']:
                    tag_lower = tag.tolower()
                    if tag_lower.startswith("cve"):
                        cve_list.append(tag)
                # 整理CVE的相关信息
                #  1. CVE的受影响软件及版本信息，最多十个
                #  2. 第一个cve的描述信息
                #  3. CVE的发布时间列表
                cve_description = ""
                publish_time = []
                affected_software  = [] 
                p_max_count =10
                for cve in cve_list:
                    cve=cve.upper()
                    if cve not in self.cve_info:
                        publish_time.append("")
                        logger.error("no {} info found, you need to update cve_info".format(cve))
                        continue
                    cve_info = self.cve_info[cve]
                    publish_time.append(cve_info["create_time"])
                    if cve_description == "":
                        cve_description = cve_info["description"]
                    if len(affected_software) < p_max_count:
                        for p in cve_info["product_affects"]:
                            if len(affected_software) < p_max_count:
                                affected_software.append(p)
                            else:
                                break

                # 获得漏洞扫描中的请求和响应(如果有)内容
                awvs_vuln_detail = self.awvs.get_vulnerabilities_detail(scan_id,scan_session_id,awvs_vuln['vuln_id'])
                request = awvs_vuln_detail.get("request","")
                has_response = awvs_vuln_detail.get("response_info",False)
                response = ""
                if has_response:
                    response = self.awvs.get_vulnerabilities_http_response(scan_id,scan_session_id,awvs_vuln['vuln_id'])

                vuln = {
                    "indicator_dict_id":indicator_id,
                    "indicator_dict_name":rule["indicator_dict_name"],
                    "create_time":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "cve":cve_list,
                    "cve_description":cve_description,
                    "title_cn":awvs_vuln['vt_name'],
                    "url":awvs_vuln['affects_url'],
                    "detail":{
                        "request":request,
                        "response":response
                    },
                    "publish_time":publish_time,
                    "affected_software":affected_software,
                }
                ret.append(vuln)
        except Exception as e:
            err = " ".join([s.strip() for s in traceback.format_exc().split('\n') if s])
            logger.error("result_enrich failed:{}".format(err))
        return ret


    

if __name__ == "__main__":
    # 测试代码
    awvs_api = AwvsApi('192.168.223.128:3443', '1986ad8c0a5b3df4d7028d5f3c06e936ce5b239a64337403185a5251ab0866622')
    target_list = awvs_api.get_target_list("bsdsdsdsd")
    target_id = ""
    if len(target_list) == 0:
        target_id = awvs_api.add_target("http://example.com","bsdsdsdsd")
    else:
        target_id = target_list[0]["target_id"]
    if target_id == "":
        raise Exception("no target found")
    config = awvs_api.get_target_config(target_id=target_id)
    logger.info("configuration={}".format(json.dumps(config)))


    new_scan_spped = ["fast","moderate","slow","sequential"][random.randint(0,3)]
    awvs_api.set_target_config_scan_spped(target_id=target_id,scan_speed=new_scan_spped)
    if awvs_api.get_target_config(target_id=target_id)["scan_speed"]!=new_scan_spped:
        raise Exception("set_target_config_scan_spped failed")

    awvs_api.set_target_config_exclusions(target_id=target_id,add=["a/b/c"],remove=["*/*"])
    config = awvs_api.get_target_config(target_id=target_id)
    logger.info("configuration={}".format(json.dumps(config)))

    awvs_api.set_target_config_cookies(target_id=target_id,cookies=[{"url":"https://www.baidu.com","cookie":"c=d;e=f"}])
    config = awvs_api.get_target_config(target_id=target_id)
    logger.info("configuration={}".format(json.dumps(config)))

    awvs_api.set_target_config_profiles(target_id=target_id,profile_name="High Risk")
    config = awvs_api.get_target_config(target_id=target_id)
    logger.info("configuration={}".format(json.dumps(config)))

    awvs_api.set_target_config_request_header(target_id=target_id,headers=["a:v","c:e"])
    config = awvs_api.get_target_config(target_id=target_id)
    logger.info("configuration={}".format(json.dumps(config)))

    scan_list = awvs_api.query_target_scan_id(target_id=target_id)

    # 创建
    scan_id = awvs_api.create_scan_task(target_id=target_id,max_scan_time=720)


    scan_info = awvs_api.status_scan_task(scan_id)
    print(json.dumps(scan_info))

    time.sleep(10)

    # 暂停
    awvs_api.pause_scan_task(scan_id=scan_id)
    scan_info = awvs_api.status_scan_task(scan_id)
    print(json.dumps(scan_info))


    time.sleep(10)
    scan_info = awvs_api.status_scan_task(scan_id)
    print(json.dumps(scan_info))

    time.sleep(10)
    # 重启
    awvs_api.restart_scan_task(scan_id)
    time.sleep(1.5)
    scan_info = awvs_api.status_scan_task(scan_id)
    print(json.dumps(scan_info))
    # 停止
    time.sleep(10)
    awvs_api.stop_scan_task(scan_id=scan_id)
    time.sleep(1.5)
    scan_info = awvs_api.status_scan_task(scan_id)
    print(json.dumps(scan_info))
    # 删除
    time.sleep(10)
    awvs_api.delete_scan_task(scan_id=scan_id)
    time.sleep(1.5)
    scan_info = awvs_api.status_scan_task(scan_id)
    print(json.dumps(scan_info))


    scan_id = "ef90c2ee-f7d6-4e08-a284-8f34e3da2b77"
    scan_session_id = "b74bc7eb-2181-4a8e-971b-f158604f0912"
    ret = awvs_api.query_scan_result(scan_id,scan_session_id)# ,severity=1,confidence=95)
    print(json.dumps(ret))


    ret = awvs_api.get_vulnerabilities_detail(scan_id,scan_session_id,"2869698553461081161")
    print(json.dumps(ret))

    ret = awvs_api.get_vulnerabilities_http_response(scan_id,scan_session_id,"2869698553461081161")
    print("finished")
