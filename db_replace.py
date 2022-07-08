# -*- coding: utf-8 -*-
import os,sys,json
import psycopg2 # pip install psycopg2==2.8.4


'''
    # 在windows上安装了AWVS后请调用此脚本，完成数据库的数据替换。
    
    ``python3  this_file``

'''



def contains_chinese_word(s):
    for c in s:
        if u'\u4e00' <= c <= u'\u9fa5':
            return True
    return False

password = ""

with open(r"C:\ProgramData\Acunetix\settings.ini","r",encoding="utf-8") as f:
    for line in f:
        if "databases.connections.master.connection.password" in line:
            password = line.split("=")[1].strip()
            break

if password == "":
    raise Exception("password not found")

# 获得连接
conn = psycopg2.connect(database="wvs", user="wvs", password="eba47tfrSHA4BEUKsZIZku5Jlb5c4Na8", host="localhost", port="35432")
# 获得游标对象
cursor = conn.cursor()
# sql语句
sql = "select vt_id from vuln_types;"
# 执行语句
cursor.execute(sql)
# 获取单条数据.
vt_id_list =[]
while True:
    data = cursor.fetchone()
    if data is None:
        break
    vt_id_list.append(data[0])
conn.commit()

sql = '''UPDATE vuln_types 
SET ( NAME, details_template, impact, description, recommendation, long_description ) = ( SELECT NAME, details_template, impact, description, recommendation, long_description FROM vuln_types_localized WHERE vuln_types.vt_id = vuln_types_localized.vt_id ) 
WHERE
	vt_id IN ( SELECT vuln_types_localized.vt_id FROM vuln_types_localized WHERE vuln_types.vt_id = vuln_types_localized.vt_id )

'''
cursor.execute(sql)
conn.commit()

for vt_id in vt_id_list:
    sql = "select name,details_template,impact,description,recommendation,long_description from vuln_types where vt_id='{}';".format(vt_id)
    cursor.execute(sql)
    data_b = cursor.fetchone()
    if not contains_chinese_word(data_b[3]):
        # TODO:如果没有翻译，需要翻译然后写入数据库
        pass
    conn.commit()

# 关闭数据库连接
conn.close()