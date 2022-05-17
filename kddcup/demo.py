import pandas as pd

col_name = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment",
            "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted",
            "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_hot_login",
            "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
            "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
            "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
            "dst_host_srv_rerror_rate", "label"]

att_type = ['normal.', 'back.', 'buffer_overflow.', 'ftp_write.', 'guess_passwd.', 'imap.', 'ipsweep.', 'land.',
            'loadmodule.', 'multihop.', 'neptune.', 'nmap.', 'perl.', 'phf.', 'pod.', 'portsweep.', 'rootkit.',
            'satan.', 'smurf.', 'spy.', 'teardrop.', 'warezclient.', 'warezmaster.']

datas = pd.read_csv("kddcup_all.csv", names=col_name)
print(datas.shape)

for i in att_type:
    criteria = datas['label'] == i
    # print(i, datas[criteria].shape ,datas[criteria].shape[0])
    lenth = datas[criteria].shape[0]
    print(i, lenth)
    if lenth < 4000:
        # print(i, lenth,datas[criteria])
        datas[criteria][:lenth].to_csv('result.csv', sep=',', header=False, index=False, mode='a')
    else:
        # print(i, lenth, datas[criteria][:4000 ])
        datas[criteria][:4000].to_csv('result.csv', sep=',', header=False, index=False, mode='a')
