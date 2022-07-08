import os,sys,json,requests,re,urllib3,time
import selenium
from bs4 import BeautifulSoup
import logging
from logging.handlers import RotatingFileHandler
# 以下是关于selenium的模块导入
from selenium import webdriver
from selenium.webdriver.common.by import By


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

logger = init_log(os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_get.log"))

def statistic_cve_tags(vuln_types_json_file="./vuln_types.json"):
    '''
        从vuln_types.json文件中统计所有的cve标签,返回cve标签的列表

        注意：vuln_types.json是从awvs的数据库中导出的json格式的vuln_types表的数据
    '''
    ret = set()
    file_data = ""
    vuln_types_json_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),"vuln_types.json")
    with open(vuln_types_json_file,encoding="utf-8") as f:
        file_data = f.read()
    vuln_types=json.loads(file_data)
    for vuln in vuln_types['RECORDS']:
        tags_1 = vuln['tags'].strip("{} \"'")
        tags_list = tags_1.split(",")
        for tag in tags_list:
            tag = tag.lower()
            if tag.startswith("cve"):
                ret.add(tag)
    return list(ret)


cached_cve_info = None
cached_cve_info_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),"cached_cve_info.json") 

def load_cached_cve_info():
    '''加载已经缓存的cve_info数据'''
    global cached_cve_info
    if cached_cve_info != None:
        return
    cached_cve_info = {}
    try:
        with open(cached_cve_info_file,"r",encoding="utf-8") as f:
            for line in f:
                cve_info =json.loads(line)
                cached_cve_info[cve_info['cve_tag']] = cve_info
    except Exception as e:
        return

def get_cve_info_internal(cve_tag):
    '''获得cve_info的内部实现'''
    global edge,options
    try:
        options
        edge
    except:
        
        options = webdriver.EdgeOptions()
        options.add_argument('--headless')
        options.add_experimental_option('excludeSwitches', ['enable-logging'])
        edge = webdriver.Edge(os.path.join(os.path.dirname(os.path.abspath(__file__)),"bin","msedgedriver.exe"),58081,options=options)
        edge.maximize_window()
    edge.get("https://avd.aliyun.com/detail?id={}".format(cve_tag.lower().replace("cve","avd")))
    time.sleep(0.5)

    title = ""
    try:
        ele = edge.find_element(By.CSS_SELECTOR,".header__title__text")
    except Exception as e:
        ret = {
            "title": title,
            "cvss3": "",
            "tags": [],
            "cve_tag": cve_tag,
            "create_time": "",
            "description": "",
            "recommendation": "",
            "reference": [],
            "product_affects": []
        }
        print(json.dumps(ret))
        return ret
    title = ele.text

    cvss3 = ""
    ele = edge.find_element(By.CSS_SELECTOR,".cvss-breakdown__score")
    cvss3 = ele.text

    cve_tag = ""
    create_time = ""
    eles = edge.find_elements(By.CSS_SELECTOR,".metric")
    for ele in eles:
        text = ele.find_element(By.CSS_SELECTOR,"p").text
        if "编号" in text:
            cve_tag = ele.find_element(By.CSS_SELECTOR,'div').text
        if "时间" in text:
            create_time = ele.find_element(By.CSS_SELECTOR,'div').text

    description = ""
    recommendation = ""
    product_affects = []
    eles= edge.find_element(By.CSS_SELECTOR,".py-4").find_elements(By.XPATH,"./*")
    for i in range(1,len(eles)):
        if eles[i-1].text == "漏洞描述":
            description = eles[i].text
        if eles[i-1].text == "解决建议":
            recommendation = eles[i].text
        if eles[i-1].text == "受影响软件情况":
            try:
                btn = eles[i].find_element(By.CSS_SELECTOR,".btn-link.text-muted")
                btn.click()
                time.sleep(1)
            except:
                pass
            product_affect_eles = eles[i].find_elements(By.CSS_SELECTOR,'table > tbody > tr')
            for product_affect_ele in product_affect_eles:
                pa_eles = product_affect_ele.find_elements(By.TAG_NAME,'td')
                if len(pa_eles) <= 4:
                    continue
                production_name = pa_eles[2].text
                if len(pa_eles) == 5:
                    production_version = pa_eles[3].text.strip()
                else:
                    production_range_start = pa_eles[4].text.replace("From","").replace("(excluding)","").replace("(including)","").strip()
                    production_range_end = pa_eles[5].text.replace("Up to","").replace("(excluding)","").replace("(including)","").strip()
                    production_version=production_range_start + " - "+ production_range_end
                if production_name=="":continue
                product_affects.append({
                    "name":production_name,
                    "version":production_version,
                })
    # reference
    reference =[]
    eles = edge.find_elements(By.CSS_SELECTOR,".reference > table > tbody > tr")
    for ele in eles:
        reference.append(ele.find_element(By.TAG_NAME,"a").get_attribute("href"))
    # tags
    tags = []
    eles = edge.find_elements(By.CSS_SELECTOR,".breadcrumbs__list > li")
    for ele in eles:
        tags.append(ele.text)

    # edge.close()

    ret = {
        "title": title,
        "cvss3": cvss3,
        "tags": tags,
        "cve_tag": cve_tag,
        "create_time": create_time,
        "description": description,
        "recommendation": recommendation,
        "reference": reference,
        "product_affects": product_affects
    }
    print(json.dumps(ret))
    return ret


def get_cve_info(cve_tag:str,use_cached=True):
    '''获得cve_info'''
    global cached_cve_info
    cve_tag=cve_tag.upper()
    if use_cached:
        if cached_cve_info == None:
            load_cached_cve_info()
    if cve_tag in cached_cve_info:
        return cached_cve_info[cve_tag]
    cve_info = get_cve_info_internal(cve_tag)
    cached_cve_info[cve_tag] = cve_info
    with open(cached_cve_info_file,'a',encoding="utf-8") as fw:
        fw.write(json.dumps(cve_info))
        fw.write("\n")



if __name__ == "__main__":
    tags = statistic_cve_tags()
    tags.sort()
    ret = {}
    for cve_tag in tags:
        cve_info = get_cve_info(cve_tag)
        ret[cve_tag]=cve_info
    with open("cve_info.json",'w',encoding="utf-8") as f:
        f.write(json.dumps(ret))
