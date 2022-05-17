from io import StringIO
import pandas as pd
from numpy import *
import warnings
import json

warnings.filterwarnings("ignore")  # 忽略告警

col_name = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment",
            "urgent", "hot", "num_failed_logins",
            "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
            "num_shells", "num_access_files", "num_outbound_cmds", "is_hot_login", "is_guest_login", "count",
            "srv_count",
            "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
            "srv_diff_host_rate",
            "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
            "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
            "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
            "label"]
col_transform = ['protocol_type', 'service', 'flag', 'label']
col_continuous = ['src_bytes', 'dst_bytes', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'num_compromised',
                  'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'count',
                  'srv_count']
pt_map = {'icmp': 0, 'tcp': 1, 'udp': 2}
service_map = {'IRC': 0, 'X11': 1, 'Z39_50': 2, 'aol': 3, 'auth': 4, 'bgp': 5, 'courier': 6, 'csnet_ns': 7, 'ctf': 8,
               'daytime': 9, 'discard': 10, 'domain': 11, 'domain_u': 12,
               'echo': 13, 'eco_i': 14, 'ecr_i': 15, 'efs': 16, 'exec': 17, 'finger': 18, 'ftp': 19, 'ftp_data': 20,
               'gopher': 21, 'harvest': 22, 'hostnames': 23, 'http': 24,
               'http_2784': 25, 'http_443': 26, 'imap4': 27, 'iso_tsap': 28, 'klogin': 29, 'kshell': 30, 'ldap': 31,
               'link': 32, 'login': 33, 'mtp': 34, 'name': 35, 'netbios_dgm': 36,
               'netbios_ns': 37, 'netbios_ssn': 38, 'netstat': 39, 'nnsp': 40, 'nntp': 41, 'other': 42, 'pm_dump': 43,
               'pop_2': 44, 'pop_3': 45, 'printer': 46, 'private': 47, 'remote_job': 48,
               'rje': 49, 'shell': 50, 'smtp': 51, 'sql_net': 52, 'ssh': 53, 'sunrpc': 54, 'supdup': 55, 'systat': 56,
               'telnet': 57, 'tim_i': 58, 'time': 59, 'uucp': 60, 'uucp_path': 61, 'vmnet': 62, 'whois': 63}
flag_map = {'OTH': 0, 'REJ': 1, 'RSTO': 2, 'RSTOS0': 3, 'RSTR': 4, 'S0': 5, 'S1': 6, 'S2': 7, 'S3': 8, 'SF': 9,
            'SH': 10}
label_map = {'back.': 0, 'buffer_overflow.': 1, 'ftp_write.': 2, 'guess_passwd.': 3, 'imap.': 4, 'ipsweep.': 5,
             'land.': 6, 'loadmodule.': 7, 'multihop.': 8, 'neptune.': 9, 'nmap.': 10, 'normal.': 11, 'perl.': 12,
             'phf.': 13,
             'pod.': 14, 'portsweep.': 15, 'rootkit.': 16, 'satan.': 17, 'smurf.': 18, 'spy.': 19, 'teardrop.': 20,
             'warezclient.': 21, 'warezmaster.': 22}
label_dict = {0: 'back.', 1: 'buffer_overflow.', 2: 'ftp_write.', 3: 'guess_passwd.', 4: 'imap.', 5: 'ipsweep.',
              6: 'land.', 7: 'loadmodule.', 8: 'multihop.', 9: 'neptune.',
              10: 'nmap.', 11: 'normal.', 12: 'perl.', 13: 'phf.', 14: 'pod.', 15: 'portsweep.', 16: 'rootkit.',
              17: 'satan.', 18: 'smurf.', 19: 'spy.', 20: 'teardrop.', 21: 'warezclient.', 22: 'warezmaster.'}
maxof_continuous = {'src_bytes': 693375640, 'dst_bytes': 400291060, 'wrong_fragment': 3, 'urgent': 2, 'hot': 28,
                    'num_failed_logins': 5, 'num_compromised': 38, 'num_root': 54, 'num_file_creations': 21,
                    'num_shells': 2, 'num_access_files': 2, 'num_outbound_cmds': 0, 'count': 511, 'srv_count': 511}


def convert(trait):  # 将前端传回的输入转化为df格式
    # strc ="0	tcp	private	SH	0	0	0	0	0	0	0	0	0	0	0	0	0	0	0	0	0	0	1	1	1	1	0	0	1	0	0	255	1	0	1	1	0	1	1	0	0"
    TESTDATA = StringIO(trait)
    df = pd.read_csv(TESTDATA, sep=",", names=col_name[:-1])
    for c_name in col_continuous:
        if maxof_continuous[c_name] != 0:
            df[c_name] = df[c_name] / maxof_continuous[c_name]
    df['protocol_type'] = df['protocol_type'].map(pt_map)
    df['service'] = df['service'].map(service_map)
    df['flag'] = df['flag'].map(flag_map)
    dfnon = df.isnull().any()
    for i in col_name[:-1]:
        if dfnon[i]:
            return "error"
    return df


def getTrandTest():  # 获取训练集测试集label数
    datas = pd.read_csv("./kddcup.data/result_shuffle.csv", names=col_name)
    for c_name in col_continuous:
        datas[c_name] = (datas[c_name] - min(datas[c_name])) / max(datas[c_name])
        datas['protocol_type'] = datas['protocol_type'].map(pt_map)
        datas['service'] = datas['service'].map(service_map)
        datas['flag'] = datas['flag'].map(flag_map)
        datas['label'] = datas['label'].map(label_map)

        class_num = max(datas['label'])

        for i in col_name:
            isnan = datas[i].isnull().any()
            if isnan:
                datas[i] = datas[i].fillna(0)
                # tsdatas[i]=tsdatas[i].fillna(0)

        test_label = []
        for i in range(len(datas['label'])):
            if i % 10 == 0:
                test_label.append(datas['label'][i])
                datas['label'][i] = -1

        train = datas[datas['label'] != -1]
        test = datas[datas['label'] == -1]

        X_train = train.drop('label', 1)
        y_train = train['label']
        X_test = test.drop('label', 1)
        y_test = test_label
        return X_train, y_train, X_test, y_test, class_num


def to_dict(rate):  # 将结果概率转成字典
    dictrate = {}
    for i in range(len(rate[0])):
        dictrate[label_dict[i]] = rate[0][i]
    return dictrate


def to_json(rate):  # 获取全部的攻击类型的概率
    result = []
    for i in range(len(rate[0])):
        thedict = {}
        thedict["value"] = rate[0][i]
        thedict["name"] = label_dict[i]
        result.append(thedict)
    return result


def getTopN(N, rate):  # 获取概率前N的攻击类型的概率
    result = []
    totalRate = to_json(rate)
    for j in range(N):
        themax = -1.0
        t = 0
        for i in range(len(totalRate)):
            if totalRate[i]["value"] > themax:
                t = i
                themax = totalRate[i]["value"]
        thedict = {}
        thedict["value"] = round(float(rate[0][t]), 6)
        print(thedict["value"])
        thedict["name"] = label_dict[t]
        result.append(thedict)
        totalRate[t]["value"] = -1
    return result
